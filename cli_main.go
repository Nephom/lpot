//go:build !simulate

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
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
	tRequested := flagWasProvided("t")
	tmRequested := flagWasProvided("tm")

	if *help || (!tRequested && !tmRequested && !*reset && !*scanOnly && !*classify && !*ui) {
		showHelp(os.Args[0])
		return
	}
	// -t and -tm select two mutually exclusive run modes (hour-based duration
	// vs. a fixed reboot count). Accepting both silently would make it
	// ambiguous which stop condition governs the run, and the current code
	// would silently prefer -tm (testCycles > 0) while still writing a
	// -t-shaped timestamp file that never gets consulted. Reject the
	// combination outright instead of guessing the operator's intent.
	if tRequested && tmRequested {
		fmt.Fprintln(os.Stderr, "-t and -tm cannot be used together; choose one run mode.")
		fmt.Fprintln(os.Stderr, "Suggestion: use `-t 24` for an hour-based run, or `-tm 10` for a fixed reboot count.")
		os.Exit(1)
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

	// Resolve external tool paths against a sanitised PATH to prevent a
	// writable PATH entry from shadowing standard system binaries. Reset only
	// needs systemd tools; normal runs additionally need PCI tools.
	{
		requireRebootTools := *reset || tRequested || tmRequested || *classify
		if err := resolveBinaries(!*reset, requireRebootTools); err != nil {
			fatalOperation("Startup failed: unable to resolve required Linux tools", err,
				"install pciutils and systemd tools, then run this binary on the target Linux host")
		}
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
	// -tm is a cycle-count mode and must be >= 1 whenever the operator
	// explicitly supplies it. testCycles == 0 is ambiguous on its own: it is
	// both flag.Int's zero value (meaning "-tm was not provided") and the
	// one value a user could type by hand as "-tm 0". tmRequested
	// (flagWasProvided, evaluated before flag.Parse mutates nothing else)
	// disambiguates the two, so an explicit -tm 0 is rejected outright
	// instead of silently falling through to the -t timestamp/hour-based
	// path below (Issue #19).
	if tmRequested && *testCycles < 1 {
		fmt.Fprintln(os.Stderr, "-tm must be at least 1 when provided.")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-tm 10`, or omit -tm entirely for the -t hour-based mode.")
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
			generateFinalSummary("")
			disableFixedCycleService()
			return
		}
	}

	if *scanOnly && !tRequested {
		if err := scanAndGenerateIgnoreBits(nil); err != nil {
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
				generateFinalSummary("")

				os.Exit(1)
			}
		}
	}

	// Setup systemd service
	if err := setupSystemdService(); err != nil {
		fatalOperation("Startup failed: cannot install or enable lpot.service", err,
			"verify that systemd is running and /etc/systemd/system is writable by root")
	}

	// Update reboot count and publish it so log helpers can tag events with
	// [Cycle N] for every subsequent write.
	rebootCount, err := updateRebootCount()
	if err != nil {
		fatalOperation("Startup failed: cannot update the reboot counter", err,
			"check /lpot/rebootcount ownership, permissions, and filesystem health")
	}
	currentCycle.Store(int64(rebootCount))

	// lpotscan.log accumulates every changed Dev/Lnk field for the ENTIRE
	// run, exactly like pci-config-changes.log accumulates every raw
	// config-space change for the entire run — it is NOT truncated at the
	// start or end of each cycle. Every line is already tagged with
	// "[Cycle N]" (cycleTag()), so per-cycle attribution is preserved
	// without truncation. This must not be cleared here: generateFinalSummary()
	// (via buildResultReport()'s parseLspciResultChanges and this file's
	// own "Most changed field" tally) reads lpotscan.log ONCE at the very
	// end of a multi-cycle run and needs every earlier cycle's lspci
	// difference to still be present, not just the last cycle's. A
	// previous version of this code truncated lpotscan.log at the start of
	// every cycle specifically to avoid stale cross-cycle leakage on an
	// early-return path (stop signal, -p, -tm limit, cancelled reboot
	// wait) — but the correct fix for that leakage is per-line [Cycle N]
	// tagging (already in place), not truncation, since truncation
	// silently discarded every cycle's lspci differences except the most
	// recent one from the final result.json and summary.

	// Open log file
	logFp, err := openSecureAppend(REBOOT_LOG, 0644)
	if err != nil {
		fatalOperation("Startup failed: cannot open /lpot/reboot.log", err,
			"check /lpot permissions and available disk space")
	}
	defer logFp.Close()

	timestampStr := getCurrentTimestamp()
	logInitialInfo(logFp, rebootCount)

	// Wait for driver ready before taking the PCI snapshot. PCI enumeration can
	// complete asynchronously after the service starts, so a snapshot taken
	// before this wait could permanently miss devices for this cycle.
	fmt.Fprintf(logFp, "%s Wait %d seconds for devices driver ready.\n", timestampStr, *standbyTime)
	logFp.Sync()
	fmt.Printf("%s Wait %d seconds for devices driver ready.\n", timestampStr, *standbyTime)

	// Sleep in segments to respond to signals
	for i := 0; i < *standbyTime && !stopFlag.Load(); i++ {
		time.Sleep(1 * time.Second)
	}

	if stopFlag.Load() {
		fmt.Fprintf(logFp, "%s Received stop signal, exiting gracefully.\n", getCurrentTimestamp())
		logFp.Sync()
		finalizeIncompleteRun()
		return
	}

	// Classify only after the driver-ready wait so raw and lspci link evidence
	// reflects the settled post-boot device state. If PCI enumeration is still
	// in progress, rediscover the sysfs entries rather than retrying a stale
	// BDF slice.
	overrides, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
	if err != nil {
		fatalOperation("Startup failed: cannot read the optional PCI link filter", err,
			"fix the permissions on /lpot/pcie_filter.txt or remove it to use automatic classification")
	}
	discovery, err := discoverPCIEndpointsWithRetry(
		fetchPCIBDFs,
		func(allBDFs []string) ([]string, []deviceClassification) {
			decisions := classifyDevices(allBDFs, overrides)
			kept, _ := filterClassifiedEndpoints(allBDFs, decisions)
			return kept, decisions
		},
		pciDiscoveryRetryAttempts,
		pciDiscoveryRetryInterval,
		func() bool { return stopFlag.Load() },
	)
	if err != nil {
		fatalOperation("Cycle failed: cannot enumerate PCI devices", err,
			"verify that /sys/bus/pci/devices is mounted and readable on Linux")
	}
	if discovery.attempts > 1 {
		fmt.Fprintf(logFp, "%s PCI discovery succeeded after %d attempts.\n", getCurrentTimestamp(), discovery.attempts)
	}
	bdfs := discovery.kept
	decisions := discovery.decisions
	totalDiscoveredBDFs := discovery.totalDiscovered
	skipped := discovery.skipped
	classifiedDevicesGlobal = decisions
	endpointFilterSet = make(map[string]bool, len(bdfs))
	for _, bdf := range bdfs {
		endpointFilterSet[normalizeBDF(bdf)] = true
	}
	// Every PCI-touching path from this point on (raw config-space scanning,
	// lspci Dev/Lnk comparison, topology tracking) must operate on only the
	// KEEP set. The discovery result is already filtered so manual "-" excludes
	// take effect for every later call that receives bdfs as an argument.
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
	// Measure actual raw config-space readability instead of asserting a
	// hardcoded 100%: a device whose /sys/.../config read returns fewer than
	// the 64-byte minimum PCI header is not truly "covered" even though it is
	// present in bdfs. This is the same readability test savePCIConfig() and
	// parsePCIConfig() apply, so this line and the later per-device warnings
	// (see savePCIConfig) describe the same underlying measurement. Coverage is
	// measured only over the KEEP set (bdfs, already filtered above), since
	// SKIP devices are intentionally excluded from every later comparison.
	readableConfigCount := 0
	var unreadableConfigBDFs []string
	for _, bdf := range bdfs {
		if len(readSysfsConfig(bdf, 256)) >= 64 {
			readableConfigCount++
		} else {
			unreadableConfigBDFs = append(unreadableConfigBDFs, bdf)
		}
	}
	fmt.Fprintf(logFp, "%s Link classification: %d / %d link-capable; raw config coverage: %d / %d KEEP devices (%d classification skips)\n",
		getCurrentTimestamp(), len(bdfs), totalDiscoveredBDFs, readableConfigCount, len(bdfs), len(skipped))
	if len(unreadableConfigBDFs) > 0 {
		fmt.Fprintf(logFp, "%s Warning: raw config space could not be fully read (< 64 bytes) for: %s. These devices cannot be compared for config-space changes this cycle.\n",
			getCurrentTimestamp(), strings.Join(unreadableConfigBDFs, ", "))
	}
	logFp.Sync()

	// Scan the complete raw-config set. A normal -t run always refreshes the
	// generated ignore list; -scan remains available as a standalone debugging
	// mode above.
	{
		timestampStr = getCurrentTimestamp()
		fmt.Fprintf(logFp, "%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)
		logFp.Sync()
		fmt.Printf("%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)

		if err := scanAndGenerateIgnoreBits(logFp); err != nil {
			fatalOperation("Cycle failed: automatic volatile-byte scan failed", err,
				"run -scan separately, verify PCI config-space access, then retry the -t run")
		} else {
			fmt.Printf("%s Auto-scan completed successfully\n", timestampStr)
			fmt.Fprintf(logFp, "%s Auto-scan completed successfully\n", timestampStr)
		}
		logFp.Sync()
	}

	if len(bdfs) == 0 {
		fatalOperation("Cycle failed: no PCIe link-capable devices were found", errors.New("empty link-capable set after bounded discovery retries"),
			"run -classify to review Link Capabilities and check /lpot/pcie_filter.txt")
	}

	// Create initial PCI device files if not exist
	if !fileExists(INITIAL_PCI_DEVICES) {
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
	if err := runConfigScan(logFp); err != nil {
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
		fail, notice, noise := cycleChangeKind()
		if cycleRequiresStop(fail, notice, noise) {
			fmt.Fprintf(logFp, "%s %s-p detected a comparison difference; stopping and disabling future reboot cycles.\n",
				getCurrentTimestamp(), cycleTag())
			logFp.Sync()
			if err := stopAndDisableService(serviceName); err != nil {
				fatalOperation("Cycle failed: unable to stop test service after -p comparison failure", err,
					"manually run systemctl stop and systemctl disable lpot.service")
			}
			finalizeIncompleteRun()
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
	// cycleEndStatus is the same classifier cycleRequiresStop (above) consults,
	// so a cycle can never be labelled "clean (config noise)" here while also
	// having triggered -p above.
	fail, notice, noise := cycleChangeKind()
	cycleStatus := cycleEndStatus(fail, notice, noise)
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
			generateFinalSummary("")
			disableFixedCycleService()
			return
		}
	}

	// Time-mode (-t) only: re-check the expiration timestamp now that this
	// cycle's scan/comparison work is actually done, instead of only at
	// process startup. The startup check (above, before setupSystemdService)
	// can pass while the timestamp is still in the future, but PCI scanning
	// and comparison for this cycle can take long enough that the deadline
	// passes before we reach the reboot-wait step below. Rebooting anyway at
	// that point would start a cycle nothing will ever inspect, so this cycle
	// is finalized as complete instead of triggering one more reboot
	// (Issue #20). -tm (cycle-count) mode has no timestamp and is unaffected
	// (guarded by *testCycles == 0, matching the startup check's own guard).
	if *testCycles == 0 && fileExists(TIMESTAMP_FILE) {
		if timestamp, err := readTimestamp(); err != nil {
			logWarn("could not re-check the test expiration timestamp before reboot: %v", err)
		} else if !time.Now().Before(timestamp) {
			fmt.Fprintf(logFp, "%s Timestamp expired after this cycle's work completed; finishing without another reboot.\n", getCurrentTimestamp())
			logFp.Sync()
			generateFinalSummary("")
			return
		}
	}

	// Prepare for reboot. The wait is interruptible so SIGINT/SIGTERM does not
	// force the operator to sit through the full waitSeconds (up to 3600).
	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s Wait %d seconds for reboot SUT.\n", timestampStr, *waitSeconds)
	logFp.Sync()
	if !sleepInterruptible(rootCtx, time.Duration(*waitSeconds)*time.Second) {
		finalizeIncompleteRun()
		return
	}

	// If a stop was requested during the wait (Ctrl-C, SIGTERM, or context
	// cancellation from anywhere else), skip the reboot entirely: rebooting a
	// host the operator has just asked us to leave alone would be surprising
	// and could disrupt other workloads running on the machine.
	if stopFlag.Load() {
		fmt.Fprintf(logFp, "%s Stop requested before reboot; skipping reboot.\n", getCurrentTimestamp())
		logFp.Sync()
		finalizeIncompleteRun()
		return
	}

	// lpotscan.log accumulates for the whole run (see the comment at
	// currentCycle.Store above); it is intentionally NOT cleared here
	// before reboot.

	// Execute reboot.
	{
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
			finalizeIncompleteRun()
		}
	}
}

// finalizeIncompleteRun writes both the human-readable final summary and the
// machine-readable INCOMPLETE result for every interrupted run path.
func finalizeIncompleteRun() {
	generateFinalSummary("INCOMPLETE")
}

// pciDiscoveryResult contains the latest complete discovery attempt. The
// caller must use the returned KEEP list and classifications together: using
// an older BDF list after a retry would reintroduce the startup race.
type pciDiscoveryResult struct {
	kept            []string
	decisions       []deviceClassification
	totalDiscovered int
	skipped         []deviceClassification
	attempts        int
}

// discoverPCIEndpointsWithRetry waits for PCI enumeration to become visible by
// re-reading sysfs on every attempt. It retries only a bounded number of times;
// an empty KEEP set is a valid final result and is not converted into fake
// success. fetch and classify are injected so the retry state machine can be
// tested without requiring Linux PCI hardware.
func discoverPCIEndpointsWithRetry(
	fetch func() ([]string, error),
	classify func([]string) ([]string, []deviceClassification),
	maxAttempts int,
	interval time.Duration,
	shouldStop func() bool,
) (pciDiscoveryResult, error) {
	if maxAttempts < 1 {
		return pciDiscoveryResult{}, errors.New("PCI discovery retry limit must be at least one")
	}
	if shouldStop == nil {
		shouldStop = func() bool { return false }
	}

	var result pciDiscoveryResult
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if shouldStop() {
			return pciDiscoveryResult{}, errors.New("PCI discovery cancelled")
		}

		allBDFs, err := fetch()
		if err != nil {
			lastErr = err
		} else {
			kept, decisions := classify(allBDFs)
			_, skipped := filterClassifiedEndpoints(allBDFs, decisions)
			result = pciDiscoveryResult{
				kept:            kept,
				decisions:       decisions,
				totalDiscovered: len(allBDFs),
				skipped:         skipped,
				attempts:        attempt,
			}
			if len(kept) > 0 || attempt == maxAttempts {
				return result, nil
			}
		}

		if attempt < maxAttempts {
			if interval > 0 {
				time.Sleep(interval)
			}
			if shouldStop() {
				return pciDiscoveryResult{}, errors.New("PCI discovery cancelled")
			}
		}
	}

	if lastErr != nil {
		return pciDiscoveryResult{}, lastErr
	}
	return result, nil
}
