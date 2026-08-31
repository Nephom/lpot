package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Constants. All persistent state lives under LPOT_DIR so behaviour is
// independent of the caller's working directory.
const (
	LPOT_DIR            = "/lpot"
	PERSISTENT_BINARY   = "/lpot/lpot"
	SYS_PCI_DEVICES     = "/sys/bus/pci/devices/"
	TIMESTAMP_FILE      = "/lpot/timestamp"
	REBOOTCOUNT_FILE    = "/lpot/rebootcount"
	TM_TARGET_FILE      = "/lpot/tm_target"
	TM_START_COUNT_FILE = "/lpot/tm_start_count"
	INITIAL_PCI_DEVICES = "/lpot/initial_pci_devices.txt"
	REBOOT_LOG          = "/lpot/reboot.log"
	CLASSIFY_STATE_FILE = "/lpot/pci_devices_classify_state.json"
	COMMAND_USER_LOG    = "/lpot/command_user_custom.log"
	TMP_DIR             = "/lpot/tmp"
	IGNORE_LIST_FILE    = "/lpot/ignore_list.txt"
	CONFIG_CHANGES_LOG  = "/lpot/pci-config-changes.log"
	RESULT_FILE         = "/lpot/result.json"
	CLASSIFY_LOG        = "/lpot/pci_devices_classify.log"
	LPOTSCAN_LOG        = "/lpot/lpotscan.log"
	PCIE_FILTER_FILE    = "/lpot/pcie_filter.txt"
	CONFIG_DUMP_DIR     = "/lpot/config_dump"

	// Per-command timeouts for external tools. Chosen conservatively so a stuck
	// child process cannot hang the overall test loop.
	lspciTimeout         = 30 * time.Second
	systemctlTimeout     = 15 * time.Second
	configScanLogTimeout = 2 * time.Minute
	rebootCmdTimeout     = 30 * time.Second

	// logTimeFormat is the single timestamp layout used across every log file
	// (reboot.log, pci-config-changes.log, lpotscan echo). A unified format
	// lets users correlate events by plain text search and by tools like
	// `sort -k1,2` without translation.
	logTimeFormat = "2006-01-02 15:04:05"
	version       = "2.6.16"
	serviceName   = "lpot.service"
	servicePath   = "/etc/systemd/system/" + serviceName
)

var buildTime = "development"

// Global variables
var (
	debugMode bool
	debugHash string
	stopFlag  atomic.Bool // set when SIGINT/SIGTERM is received or rootCtx is cancelled

	// rootCtx is cancelled on SIGINT/SIGTERM and is used to bound every external
	// command so the test loop cannot be left waiting on a stuck child process.
	rootCtx    context.Context
	rootCancel context.CancelFunc

	// currentCycle holds the reboot cycle number for the current run. It is
	// written once by main() after updateRebootCount() succeeds and then read
	// by log helpers to tag every event with [Cycle N].
	currentCycle atomic.Int64

	// changedCycles records cycles where any topology / lspci / config-space
	// change was detected, along with a short reason string. It is summarised
	// at the end of the run so users can see exactly which cycles were noisy
	// without grepping the entire reboot.log.
	changedCyclesMu sync.Mutex
	changedCycles   []cycleChange

	// endpointFilterSet, when non-nil, restricts every PCI-touching path
	// (savePCIConfig, compareDeviceConfigs, processPCIDevices) to the set of
	// short BDFs it contains. nil means "no filter" so unit tests and the
	// legacy code path keep working unchanged.
	endpointFilterSet       map[string]bool
	classifiedDevicesGlobal []deviceClassification

	// Statistics tracking
	cyclesWithConfigChanges int
	deviceChangeStats       map[string]int
	mostAffectedDevice      string
	mostChangedField        string
)

func main() {
	// Parse flags before requiring root or resolving Linux-only tools. This keeps
	// `./lpot` and `./lpot -h` useful from a development machine and makes the
	// explicit -t gate visible before any host mutation can begin.
	var (
		waitHours   = flag.Int("t", 12, "Setup runtime in hours")
		standbyTime = flag.Int("d", 300, "Setup delay time for driver ready in seconds")
		waitSeconds = flag.Int("s", 300, "Setup delay time for reboot in seconds")
		testCycles  = flag.Int("tm", 0, "Run a fixed number of reboots instead of hours")
		stopService = flag.Bool("p", false, "Set stop flag when error occurred")
		debug       = flag.String("g", "", "")
		showKey     = flag.Bool("k", false, "Show encrypted root password value")
		reset       = flag.Bool("r", false, "Reset /lpot directory")
		scanOnly    = flag.Bool("scan", false, "Only scan and generate ignore bits file, then exit")
		classify    = flag.Bool("classify", false, "Print PCI link-capability report and exit")
		ui          = flag.Bool("ui", false, "Open the local read-only result dashboard")
		help        = flag.Bool("h", false, "Show help menu")
	)
	parsedArgs, customArgs, err := splitCustomCommandArgs(os.Args)
	if err != nil {
		fatalOperation("Startup failed: invalid command-line arguments", err,
			"put LPOT options before -c and give -c a command to run")
	}
	os.Args = parsedArgs
	customCommandArgs = customArgs
	applyDefaultDurationForBareT()
	flag.Parse()
	debugHash = *debug
	debugRequested := flagWasProvided("g")
	tRequested := flagWasProvided("t")
	tmRequested := flagWasProvided("tm")

	if *help || (!tRequested && !tmRequested && !debugRequested && !*showKey && !*reset && !*scanOnly && !*classify && !*ui) {
		showHelp(os.Args[0])
		return
	}
	if *ui {
		if err := startDashboard(); err != nil {
			fatalOperation("Dashboard failed", err, "verify that localhost is available and try -ui again")
		}
		return
	}

	// Root privileges are required for every operation other than help. Bail
	// out early rather than failing half-initialised after touching the host.
	ensureRoot()

	// rootCtx is the single cancellation primitive for external commands and
	// internal sleep loops. signal handlers cancel it on first Ctrl-C.
	rootCtx, rootCancel = context.WithCancel(context.Background())
	defer rootCancel()

	// Signal handlers must be installed before any long-running operation.
	setupSignalHandlers()

	if *showKey {
		hash, err := rootPasswordHash()
		if err != nil {
			fatalOperation("Startup failed: cannot compute the root password hash", err,
				"run this as root so /etc/shadow is readable")
		}
		fmt.Println(hash)
		return
	}

	// Resolve external tool paths against a sanitised PATH to prevent a
	// writable PATH entry from shadowing standard system binaries. Reset only
	// needs systemd tools; normal runs additionally need PCI tools.
	{
		requireRebootTools := *reset || tRequested || tmRequested || (*classify && !debugRequested) || (debugRequested && !*scanOnly && !*classify)
		if err := resolveBinaries(!*reset, requireRebootTools); err != nil {
			fatalOperation("Startup failed: unable to resolve required Linux tools", err,
				"install pciutils and systemd tools, then run this binary on the target Linux host")
		}
	}

	if debugRequested {
		if err := authenticateDebug(debugHash); err != nil {
			fatalOperation("Authentication failed", err, "check the -g hash value and retry")
		}
		debugMode = true
		runDryRunAudit(os.Args, *waitHours, *standbyTime, *waitSeconds, *stopService, *scanOnly, *classify)
		return
	}

	// Ensure /lpot is a real root-owned directory with tight permissions. All
	// persistent state files are addressed via absolute constants thereafter,
	// so we no longer need to Chdir into it.
	if err := secureLpotDir(); err != nil {
		fatalOperation("Startup failed: cannot prepare /lpot", err,
			"ensure /lpot is a root-owned directory and rerun as root")
	}

	if *reset {
		if err := resetLpotDirectory(); err != nil {
			fatalOperation("Reset failed", err,
				"confirm that /lpot is root-owned and that no process is using its runtime files")
		}
		return
	}
	if *testCycles < 0 {
		fmt.Fprintln(os.Stderr, "-tm must be greater than zero when provided")
		os.Exit(1)
	}
	if *testCycles > 0 {
		reached, err := prepareTestCycleLimit(*testCycles)
		if err != nil {
			fatalOperation("Startup failed: cannot prepare -tm cycle limit", err,
				"check /lpot/rebootcount and /lpot permissions")
		}
		if reached {
			fmt.Printf("-tm reboot limit reached; no further reboot will start\n")
			generateFinalSummary()
			disableFixedCycleService()
			return
		}
	}

	if *scanOnly && !tRequested {
		if err := scanAndGenerateIgnoreBits(); err != nil {
			fatalOperation("Scan failed", err,
				"verify that /sys/bus/pci/devices is readable and that the process is running as root")
		}
		return
	}

	// -classify prints how every PCI BDF would be treated by the link-capability filter
	// and appends the same report to /lpot. It does not change host policies.
	if *classify && !tRequested {
		bdfs, err := fetchPCIBDFs()
		if err != nil {
			fatalOperation("Classification failed: unable to read PCI devices", err,
				"run on Linux with PCI sysfs mounted and execute as root")
		}
		ov, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
		if err != nil {
			fatalOperation(fmt.Sprintf("Classification failed: unable to load %s", PCIE_FILTER_FILE), err,
				"fix the filter file permissions or remove it to use automatic classification")
		}
		decisions := classifyDevices(bdfs, ov)
		printClassificationReport(os.Stdout, decisions)

		if err := persistClassificationReport(decisions); err != nil {
			fatalOperation("Classification failed: cannot write the report", err,
				"check the filesystem and /lpot permissions")
		}
		if err := persistClassificationConfigDumps(decisions); err != nil {
			fatalOperation("Classification failed: cannot write config dumps", err,
				"check /lpot/config_dump permissions and PCI sysfs access")
		}
		if report := buildClassificationReport(decisions); report.Unverified > 0 {
			fatalOperation("Classification failed", fmt.Errorf("%d PCI devices could not be verified", report.Unverified),
				"run -classify to review the report and check /lpot/pcie_filter.txt")
		}
		return
	}

	// Validate input parameters
	if !validateInputParameters(*waitHours, *waitSeconds, *standbyTime) {
		os.Exit(1)
	}

	debugf("Parameters - wait_hours: %d, reboot_wait_seconds: %d, driver_ready_time: %d, stopService: %t",
		*waitHours, *waitSeconds, *standbyTime, *stopService)

	// The test host is dedicated lab hardware. Disable host firewall and
	// mandatory access-control services before installing the reboot service so
	// the PCI test is not blocked by distro-specific policy.
	if err := prepareHostPolicies(); err != nil {
		fatalOperation("Startup failed: cannot prepare host policies", err,
			"run only on the reserved test host and verify the listed service can be stopped or disabled")
	}

	// Create reboot script if not exists
	if err := createRebootScript(persistentRebootArgs(os.Args), customCommandArgs); err != nil {
		fatalOperation("Startup failed: cannot install the persistent reboot executable/script", err,
			"keep the downloaded binary readable and executable, and verify that /lpot is root-owned")
	}

	// Hour-based runs use the timestamp; -tm runs stop only at their cycle limit.
	if *testCycles == 0 {
		// Check timestamp
		if !fileExists(TIMESTAMP_FILE) {
			if err := resetClassificationBaseline(); err != nil {
				fatalOperation("Startup failed: cannot reset classification baseline", err,
					"check /lpot permissions before starting a new test run")
			}
			if err := writeTimestamp(*waitHours); err != nil {
				fatalOperation("Startup failed: cannot write the test expiration timestamp", err,
					"check /lpot permissions and available disk space")
			}
		} else {
			currentTime := time.Now()
			timestamp, err := readTimestamp()
			if err != nil {
				fatalOperation("Startup failed: cannot read the existing test expiration timestamp", err,
					"remove the corrupt /lpot/timestamp only after confirming the previous test is no longer running")
			}

			if currentTime.After(timestamp) {
				timestampStr := getCurrentTimestamp()
				errorMsg := fmt.Sprintf("%s Execution halted: timestamp expired.\n", timestampStr)

				if logFp, err := openSecureAppend(REBOOT_LOG, 0644); err == nil {
					logFp.WriteString(errorMsg)
					logFp.Close()
				}

				// Clean up temporary files
				os.RemoveAll(TMP_DIR)

				// Execute configscan_log.sh if it was located at a trusted absolute
				// path during startup. Skip silently otherwise; this helper is
				// optional and its absence must not be mistaken for a PATH lookup.
				if configScanLogPath != "" {
					if _, err := runExternal(configScanLogTimeout, configScanLogPath); err != nil {
						fmt.Fprintf(os.Stderr, "configscan_log.sh failed: %v\n", err)
					}
				}

				// Generate final summary before exit
				generateFinalSummary()

				os.Exit(1)
			}
		}
	}

	// Setup systemd service
	if err := setupSystemdService(); err != nil {
		fatalOperation("Startup failed: cannot install or enable lpot.service", err,
			"verify that systemd is running and /etc/systemd/system is writable by root")
	}

	// Initialize statistics tracking
	initializeStatistics()

	// Update reboot count and publish it so log helpers can tag events with
	// [Cycle N] for every subsequent write.
	rebootCount, err := updateRebootCount()
	if err != nil {
		fatalOperation("Startup failed: cannot update the reboot counter", err,
			"check /lpot/rebootcount ownership, permissions, and filesystem health")
	}
	currentCycle.Store(int64(rebootCount))

	// Open log file
	logFp, err := openSecureAppend(REBOOT_LOG, 0644)
	if err != nil {
		fatalOperation("Startup failed: cannot open /lpot/reboot.log", err,
			"check /lpot permissions and available disk space")
	}
	defer logFp.Close()

	timestampStr := getCurrentTimestamp()
	logInitialInfo(logFp, rebootCount)

	// Get PCI device list
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fatalOperation("Cycle failed: cannot enumerate PCI devices", err,
			"verify that /sys/bus/pci/devices is mounted and readable on Linux")
	}

	if debugMode {
		debugf("Found %d PCI devices (full raw-config set)", len(bdfs))
		for i, bdf := range bdfs {
			if i < 10 { // Only show first 10 devices
				debugf("PCI device %d: %s", i+1, bdf)
			}
		}
		if len(bdfs) > 10 {
			debugf("... and %d more devices", len(bdfs)-10)
		}
	}

	// Wait for driver ready
	fmt.Fprintf(logFp, "%s Wait %d seconds for devices driver ready.\n", timestampStr, *standbyTime)
	logFp.Sync()
	fmt.Printf("%s Wait %d seconds for devices driver ready.\n", timestampStr, *standbyTime)

	// Sleep in segments to respond to signals
	for i := 0; i < *standbyTime && !stopFlag.Load(); i++ {
		time.Sleep(1 * time.Second)
	}

	if stopFlag.Load() {
		fmt.Fprintf(logFp, "%s Received stop signal, exiting gracefully.\n", getCurrentTimestamp())
		if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
			warnIncompleteReport(err)
		}
		return
	}

	// Classify only after the driver-ready wait so raw and lspci link evidence
	// reflects the settled post-boot device state.
	overrides, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
	if err != nil {
		fatalOperation("Startup failed: cannot read the optional PCI link filter", err,
			"fix the permissions on /lpot/pcie_filter.txt or remove it to use automatic classification")
	}
	decisions := classifyDevices(bdfs, overrides)
	_, skipped := filterClassifiedEndpoints(bdfs, decisions)
	classifiedDevicesGlobal = decisions
	endpointFilterSet = make(map[string]bool, len(bdfs))
	for _, bdf := range bdfs {
		endpointFilterSet[normalizeBDF(bdf)] = true
	}
	if err := persistClassificationReport(decisions); err != nil {
		fatalOperation("Startup failed: cannot write the PCI link-capability report", err,
			"check /lpot permissions and available disk space")
	}
	if err := persistClassificationConfigDumps(decisions); err != nil {
		fatalOperation("Startup failed: cannot write config dumps", err,
			"check /lpot/config_dump permissions and PCI sysfs access")
	}
	if err := writeClassificationReportToLog(logFp, decisions); err != nil {
		fatalOperation("Startup failed: cannot publish PCI link classification", err,
			"fix PCI config-space access and verify the classification baseline file")
	}
	logFp.Sync()
	if report := buildClassificationReport(decisions); report.Unverified > 0 {
		fatalOperation("Startup failed: PCI link classification is unverified",
			fmt.Errorf("%d device(s) could not be read", report.Unverified),
			"fix PCI config-space access and rerun -classify")
	}
	fmt.Fprintf(logFp, "%s Link classification: %d / %d link-capable; raw config coverage: %d / %d devices (%d classification skips)\n",
		getCurrentTimestamp(), len(bdfs)-len(skipped), len(bdfs), len(bdfs), len(bdfs), len(skipped))
	logFp.Sync()

	// Scan the complete raw-config set. A normal -t run always refreshes the
	// generated ignore list; -scan remains available as a standalone debugging
	// mode above.
	{
		timestampStr = getCurrentTimestamp()
		fmt.Fprintf(logFp, "%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)
		logFp.Sync()
		fmt.Printf("%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)

		if err := scanAndGenerateIgnoreBits(); err != nil {
			fatalOperation("Cycle failed: automatic volatile-byte scan failed", err,
				"run -scan separately, verify PCI config-space access, then retry the -t run")
		} else {
			fmt.Printf("%s Auto-scan completed successfully\n", timestampStr)
			fmt.Fprintf(logFp, "%s Auto-scan completed successfully\n", timestampStr)
		}
		logFp.Sync()
	}

	if len(bdfs) == 0 {
		fatalOperation("Cycle failed: no PCIe link-capable devices were found", errors.New("empty link-capable set"),
			"run -classify to review Link Capabilities and check /lpot/pcie_filter.txt")
	}

	// Create initial PCI device files if not exist
	if !fileExists(INITIAL_PCI_DEVICES) {
		debugf("Executing initial lspci -vv > %s", INITIAL_PCI_DEVICES)

		output, err := runExternal(lspciTimeout, lspciPath, "-vv")
		if err != nil {
			logWarn("initial lspci command failed: %v", err)
		} else {
			if werr := writeFileNoFollow(INITIAL_PCI_DEVICES, output, 0644); werr != nil {
				logWarn("could not write %s: %v", INITIAL_PCI_DEVICES, werr)
			}
		}

		for _, bdf := range bdfs {
			if stopFlag.Load() {
				break
			}
			if err := executeLspci(bdf, "_init.txt"); err != nil {
				fatalOperation("Startup failed: cannot capture the initial lspci snapshot", err,
					"verify that pciutils is installed and that the device is still present")
			}
		}
	}

	// Analysis phase
	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s Analyzing\n", timestampStr)
	logFp.Sync()
	fmt.Fprintf(logFp, "%s Scan PCI Config space...\n", timestampStr)
	logFp.Sync()

	// Execute config scan logic
	if err := runConfigScan(); err != nil {
		fatalOperation("Cycle failed: PCI configuration scan failed", err,
			"verify PCI sysfs access and regenerate /lpot/ignore_list.txt with -scan")
	}

	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s PCI Config space Scan Done\n", timestampStr)
	logFp.Sync()

	// Process PCI devices
	if err := processPCIDevices(bdfs, logFp, *stopService); err != nil {
		timestampStr = getCurrentTimestamp()
		fmt.Fprintf(logFp, "%s PCI devices check failed\n", timestampStr)
		fatalOperation("Cycle failed: PCI device comparison failed", err,
			"review /lpot/reboot.log and verify that pciutils can query every link-capable device")
	}
	if *stopService {
		noteworthy, configNoise := cycleChangeKind()
		if noteworthy || configNoise {
			fmt.Fprintf(logFp, "%s %s-p detected a comparison difference; stopping and disabling future reboot cycles.\n",
				getCurrentTimestamp(), cycleTag())
			logFp.Sync()
			if err := stopAndDisableService(serviceName); err != nil {
				fatalOperation("Cycle failed: unable to stop test service after -p comparison failure", err,
					"manually run systemctl stop and systemctl disable lpot.service")
			}
			if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
				warnIncompleteReport(err)
			}
			generateFinalSummary()
			return
		}
	}

	// Clean up tmp directory files
	cleanupBDFFiles()

	// Emit the cycle-end banner before the reboot wait so even a kernel panic
	// during shutdown still leaves a per-cycle terminator in reboot.log.
	// Topology / lspci changes are noteworthy ("changes detected"); benign
	// config-space register noise alone leaves the cycle effectively clean so
	// `grep '===== Cycle.*END (changes detected)'` only surfaces real issues.
	noteworthy, configNoise := cycleChangeKind()
	cycleStatus := "clean"
	switch {
	case noteworthy:
		cycleStatus = "changes detected"
	case configNoise:
		cycleStatus = "clean (config noise)"
	}
	logCycleEnd(logFp, rebootCount, cycleStatus)
	if err := writeResultReport(true); err != nil {
		fatalOperation("Cycle failed: cannot write the result checkpoint before reboot wait", err,
			"check /lpot permissions and available disk space; reboot was not started")
	}
	if *testCycles > 0 {
		reached, err := fixedCycleLimitReached(rebootCount)
		if err != nil {
			logWarn("could not evaluate the -tm cycle limit: %v", err)
		} else if reached {
			fmt.Fprintf(logFp, "%s -tm reboot limit reached; reboot not started.\n", getCurrentTimestamp())
			logFp.Sync()
			generateFinalSummary()
			disableFixedCycleService()
			return
		}
	}

	// Prepare for reboot. The wait is interruptible so SIGINT/SIGTERM does not
	// force the operator to sit through the full waitSeconds (up to 3600).
	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s Wait %d seconds for reboot SUT.\n", timestampStr, *waitSeconds)
	logFp.Sync()
	if !sleepInterruptible(rootCtx, time.Duration(*waitSeconds)*time.Second) {
		if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
			warnIncompleteReport(err)
		}
		return
	}

	// If a stop was requested during the wait (Ctrl-C, SIGTERM, or context
	// cancellation from anywhere else), skip the reboot entirely: rebooting a
	// host the operator has just asked us to leave alone would be surprising
	// and could disrupt other workloads running on the machine.
	if stopFlag.Load() {
		fmt.Fprintf(logFp, "%s Stop requested before reboot; skipping reboot.\n", getCurrentTimestamp())
		logFp.Sync()
		if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
			warnIncompleteReport(err)
		}
		return
	}

	// Remove lpotscan log
	os.Remove(LPOTSCAN_LOG)

	// Execute reboot (skip in debug mode)
	if debugMode {
		debugf("Reboot command disabled in debug mode")
		fmt.Fprintf(logFp, "%s DEBUG: Reboot command disabled in debug mode\n", timestampStr)
		logFp.Sync()
	} else {
		// reboot(8) itself typically returns before the kernel actually brings
		// the system down, so we only surface an error if the command fails or
		// times out. We log to both stdout and reboot.log so a stuck system is
		// at least diagnosable post-mortem.
		if _, err := runExternal(rebootCmdTimeout, rebootPath); err != nil {
			fmt.Fprintf(os.Stderr, "reboot command failed: %v\n", err)
			if logFp, lerr := openSecureAppend(REBOOT_LOG, 0600); lerr == nil {
				fmt.Fprintf(logFp, "%s reboot command failed: %v\n", getCurrentTimestamp(), err)
				logFp.Close()
			}
			if reportErr := writeResultReportWithStatus(false, "INCOMPLETE"); reportErr != nil {
				warnIncompleteReport(reportErr)
			}
		}
	}
}
