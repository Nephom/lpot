package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Constants. All persistent state lives under LPOT_DIR so behaviour is
// independent of the caller's working directory.
const (
	LPOT_DIR            = "/lpot"
	SYS_PCI_DEVICES     = "/sys/bus/pci/devices/"
	TIMESTAMP_FILE      = "/lpot/timestamp"
	REBOOTCOUNT_FILE    = "/lpot/rebootcount"
	INITIAL_PCI_DEVICES = "/lpot/initial_pci_devices.txt"
	REBOOT_LOG          = "/lpot/reboot.log"
	TMP_DIR             = "/lpot/tmp"
	IGNORE_LIST_FILE    = "/lpot/ignore_list.txt"
	CONFIG_CHANGES_LOG  = "/lpot/pci-config-changes.log"
	CLASSIFY_LOG        = "/lpot/pci_devices_classify.log"
	LPOTSCAN_LOG        = "/lpot/lpotscan.log"
	PCIE_FILTER_FILE    = "/lpot/pcie_filter.txt"

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
	version       = "2.2.0"
)

// bdfRegex matches a canonical PCI BDF, optionally with a 4-digit domain:
//
//	[domain:]bus:device.function
//	       ^^^ 4 hex   ^^ 2 hex  ^^ 2 hex  ^ 1 hex (0-7)
//
// The sysfs layout under /sys/bus/pci/devices/ always uses this form.
var bdfRegex = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

// shortBDFRegex matches the domain-less short form "bus:device.function" that
// lspci -s emits in its text output. parseDeviceFile() reads device files in
// this form, so map keys and ignore-list entries must agree to avoid silent
// lookup misses.
var shortBDFRegex = regexp.MustCompile(`^[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

// normalizeBDF returns the short form ("bus:device.function") of a BDF when
// the long form has domain 0000, and the input unchanged otherwise. This
// unifies map keys across the sysfs world (always long) and the lspci-text
// world (always short) on single-domain systems while preserving correctness
// on the very rare multi-domain host.
func normalizeBDF(bdf string) string {
	bdf = strings.TrimSpace(bdf)
	if bdfRegex.MatchString(bdf) && strings.HasPrefix(bdf, "0000:") {
		return bdf[5:]
	}
	return bdf
}

// Global variables
var (
	debugMode bool
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
	// legacy code path keep working unchanged. skippedDevicesGlobal records
	// the BDFs that were filtered out, with their classification reason, so
	// the final summary can list them in a dedicated section.
	endpointFilterSet    map[string]bool
	skippedDevicesGlobal []deviceClassification

	// Statistics tracking
	testStartTime                   time.Time
	totalRebootCycles               int
	cyclesWithChanges               int
	cyclesWithDeviceTopologyChanges int
	cyclesWithLspciChanges          int
	cyclesWithConfigChanges         int
	deviceChangeStats               map[string]int
	configChangeStats               map[string]map[string]int
	mostAffectedDevice              string
	mostChangedField                string
)

// cycleChange is a single line-item emitted at the end of a test summarising
// what went wrong in a given cycle. Multiple entries per cycle are allowed.
//
// Noteworthy distinguishes genuinely concerning changes (device topology and
// lspci capability changes) from benign config-space byte noise (vendor
// registers a controller re-initialises to the same value on every boot).
// Only noteworthy changes flip the cycle-end banner to "changes detected";
// pure config-space noise leaves the cycle labelled "clean (config noise)".
type cycleChange struct {
	Cycle      int64
	Time       time.Time
	Reason     string
	Noteworthy bool
}

// recordCycleChange appends a noteworthy change record (topology / lspci) for
// the final summary. It is safe to call concurrently from any
// reboot-processing goroutine.
func recordCycleChange(reason string) {
	appendCycleChange(reason, true)
}

// recordCycleNoise appends a non-noteworthy change record (config-space byte
// noise). It is still listed in the final summary for completeness but does
// not flip the cycle-end banner to "changes detected".
func recordCycleNoise(reason string) {
	appendCycleChange(reason, false)
}

func appendCycleChange(reason string, noteworthy bool) {
	changedCyclesMu.Lock()
	defer changedCyclesMu.Unlock()
	changedCycles = append(changedCycles, cycleChange{
		Cycle:      currentCycle.Load(),
		Time:       time.Now(),
		Reason:     reason,
		Noteworthy: noteworthy,
	})
}

// cycleChangeKind reports what kind of change records exist for the
// currently-running cycle, used to label the cycle-end banner:
//   - noteworthy: a topology / lspci change was recorded (genuinely concerning)
//   - configNoise: only config-space byte changes were recorded (benign)
func cycleChangeKind() (noteworthy, configNoise bool) {
	changedCyclesMu.Lock()
	defer changedCyclesMu.Unlock()
	cycle := currentCycle.Load()
	for _, c := range changedCycles {
		if c.Cycle != cycle {
			continue
		}
		if c.Noteworthy {
			noteworthy = true
		} else {
			configNoise = true
		}
	}
	return noteworthy, configNoise
}

// logTimestamp returns the current time formatted for log output.
func logTimestamp() string {
	return time.Now().Format(logTimeFormat)
}

// cycleTag returns a "[Cycle N] " prefix when a cycle number is set, and an
// empty string otherwise. Callers prepend it to log lines so events can be
// attributed to a specific reboot iteration.
func cycleTag() string {
	if n := currentCycle.Load(); n > 0 {
		return fmt.Sprintf("[Cycle %d] ", n)
	}
	return ""
}

// describePCIBDF returns a short human-readable description of the device at
// the given BDF ("21:00.4 (1022:1557 Serial bus controller)"), reading
// vendor/device/class from the device's PCI configuration space via sysfs. It
// accepts both short and long BDF forms so log lines emitted from either path
// (lspci-text comparison or config-space binary comparison) get the same
// enrichment. Best-effort: on any I/O error we return the BDF alone so log
// writes are never blocked by a transient read failure.
func describePCIBDF(bdf string) string {
	info, ok := readPCIDeviceInfo(bdf)
	if !ok {
		return bdf
	}
	className, ok := pciClassNames[info.BaseClass]
	if !ok {
		className = fmt.Sprintf("class 0x%02x", info.BaseClass)
	}
	return fmt.Sprintf("%s (%04x:%04x %s)", bdf, info.Vendor, info.Device, className)
}

// pciClassNames maps PCI Base Class codes to human-readable names per the PCI
// Code and ID Assignment Specification. Only the base class is shown in logs;
// the subclass detail (e.g., "NVMe") would require a table several hundred
// entries long and is already visible in initial_pci_devices.txt.
var pciClassNames = map[byte]string{
	0x00: "Unclassified device",
	0x01: "Mass storage controller",
	0x02: "Network controller",
	0x03: "Display controller",
	0x04: "Multimedia controller",
	0x05: "Memory controller",
	0x06: "Bridge",
	0x07: "Communication controller",
	0x08: "Generic system peripheral",
	0x09: "Input device controller",
	0x0a: "Docking station",
	0x0b: "Processor",
	0x0c: "Serial bus controller",
	0x0d: "Wireless controller",
	0x0e: "Intelligent controller",
	0x0f: "Satellite communications controller",
	0x10: "Encryption controller",
	0x11: "Signal processing controller",
	0x12: "Processing accelerator",
	0x13: "Non-Essential Instrumentation",
}

// pciDeviceInfo carries the header fields needed for endpoint classification
// and for log enrichment. It is intentionally a small subset of the full
// PCIDeviceInfo struct so callers that only need the class/header data are not
// forced to parse the entire 256-byte config space.
type pciDeviceInfo struct {
	BDF        string
	Vendor     uint16 // config offset 0x00-0x01
	Device     uint16 // config offset 0x02-0x03
	SubClass   byte   // config offset 0x0a
	BaseClass  byte   // config offset 0x0b
	HeaderType byte   // config offset 0x0e, masked with 0x7f (top bit = MFD)
	HasPCIeCap bool   // PCI Express Capability (Cap ID 0x10) present in cap list
}

// readSysfsConfig reads up to n bytes from a device's PCI configuration space
// via /sys/bus/pci/devices/<bdf>/config. It tries both BDF forms so callers
// that hold either a long or short BDF get the same answer.
func readSysfsConfig(bdf string, n int) []byte {
	candidates := []string{bdf}
	if shortBDFRegex.MatchString(bdf) {
		candidates = append(candidates, "0000:"+bdf)
	}
	for _, b := range candidates {
		f, err := os.Open(filepath.Join(SYS_PCI_DEVICES, b, "config"))
		if err != nil {
			continue
		}
		buf := make([]byte, n)
		m, _ := f.Read(buf)
		f.Close()
		if m > 0 {
			return buf[:m]
		}
	}
	return nil
}

// readPCIDeviceInfo extracts the header / class / capability data needed for
// endpoint classification. Returns ok=false on any read failure so callers can
// treat the BDF as "unknown" rather than block the test.
func readPCIDeviceInfo(bdf string) (pciDeviceInfo, bool) {
	cfg := readSysfsConfig(bdf, 256)
	if len(cfg) < 0x40 {
		return pciDeviceInfo{BDF: bdf}, false
	}
	return pciDeviceInfo{
		BDF:        bdf,
		Vendor:     binary.LittleEndian.Uint16(cfg[0x00:0x02]),
		Device:     binary.LittleEndian.Uint16(cfg[0x02:0x04]),
		SubClass:   cfg[0x0a],
		BaseClass:  cfg[0x0b],
		HeaderType: cfg[0x0e] & 0x7f,
		HasPCIeCap: hasPCIeCapability(cfg),
	}, true
}

// hasPCIeCapability walks the PCI capability list starting at offset 0x34 and
// returns true when Cap ID 0x10 (PCI Express) is present. It walks at most 48
// links to avoid pointer loops on a malformed list, and short-circuits if the
// Status register's Capabilities List bit (bit 4 of offset 0x06) is clear.
func hasPCIeCapability(cfg []byte) bool {
	if len(cfg) < 0x35 {
		return false
	}
	status := binary.LittleEndian.Uint16(cfg[0x06:0x08])
	if status&0x10 == 0 {
		return false
	}
	next := int(cfg[0x34] & 0xfc)
	for i := 0; i < 48 && next != 0 && next+1 < len(cfg); i++ {
		if cfg[next] == 0x10 { // PCI Express
			return true
		}
		next = int(cfg[next+1] & 0xfc)
	}
	return false
}

// isPCIeEndpoint applies the three-layer endpoint rule:
//  1. PCI Header Type == 0x00 (Type 0 layout — only endpoints have this)
//  2. Base Class != 0x06 (excludes every Bridge Device subclass)
//  3. PCI Express Capability present (excludes legacy non-PCIe devices)
//
// Returns (true, "") for endpoints and (false, reason) otherwise, where
// reason is a short human-readable string suitable for inclusion in the
// classification report and the final summary.
func isPCIeEndpoint(info pciDeviceInfo) (bool, string) {
	if info.HeaderType != 0x00 {
		return false, fmt.Sprintf("Header Type %d (bridge layout)", info.HeaderType)
	}
	if info.BaseClass == 0x06 {
		return false, "Base Class 0x06 (Bridge Device)"
	}
	if !info.HasPCIeCap {
		return false, "no PCI Express capability (legacy PCI)"
	}
	return true, ""
}

// pcieFilterOverrides holds user-supplied include/exclude directives parsed
// from PCIE_FILTER_FILE. A BDF in Include is treated as an endpoint even if
// auto-classification would skip it; a BDF in Exclude is skipped even if
// auto-classification would keep it. Keys are stored in short form.
type pcieFilterOverrides struct {
	Include map[string]bool
	Exclude map[string]bool
}

// loadPCIeFilterOverrides parses PCIE_FILTER_FILE. Lines starting with '+' are
// force-include directives, lines starting with '-' are force-exclude. Empty
// lines and '#' comments are skipped. The file is optional; its absence is not
// an error so the test loop can start on a fresh system without any override.
func loadPCIeFilterOverrides(path string) (pcieFilterOverrides, error) {
	ov := pcieFilterOverrides{
		Include: make(map[string]bool),
		Exclude: make(map[string]bool),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ov, nil
		}
		return ov, err
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var sign byte
		switch line[0] {
		case '+', '-':
			sign = line[0]
			line = strings.TrimSpace(line[1:])
		default:
			// Bare BDF (no sign) is treated as include for convenience.
			sign = '+'
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		bdf := normalizeBDF(fields[0])
		if !shortBDFRegex.MatchString(bdf) && !bdfRegex.MatchString(bdf) {
			continue
		}
		if sign == '+' {
			ov.Include[bdf] = true
		} else {
			ov.Exclude[bdf] = true
		}
	}
	return ov, nil
}

// deviceClassification captures the per-BDF decision for both the runtime
// filter and the -classify dry-run report. KeptReason is set only for kept
// devices to record which override (if any) saved them; SkipReason is set for
// skipped devices.
type deviceClassification struct {
	BDF        string
	Info       pciDeviceInfo
	InfoOK     bool
	Kept       bool
	KeptReason string // "endpoint", "forced by pcie_filter.txt", ""
	SkipReason string // populated when Kept == false
}

// classifyDevices runs the three-layer endpoint check on each BDF, then
// applies pcie_filter.txt overrides (Exclude beats Include). The output is
// stable-ordered by BDF so the dry-run report and the summary section render
// deterministically across runs.
func classifyDevices(bdfs []string, ov pcieFilterOverrides) []deviceClassification {
	out := make([]deviceClassification, 0, len(bdfs))
	for _, bdf := range bdfs {
		short := normalizeBDF(bdf)
		dc := deviceClassification{BDF: short}
		info, ok := readPCIDeviceInfo(bdf)
		dc.Info = info
		dc.InfoOK = ok
		switch {
		case ov.Exclude[short]:
			dc.Kept = false
			dc.SkipReason = "forced by pcie_filter.txt (-)"
		case ov.Include[short]:
			dc.Kept = true
			dc.KeptReason = "forced by pcie_filter.txt (+)"
		case !ok:
			dc.Kept = false
			dc.SkipReason = "unreadable config space"
		default:
			endpoint, reason := isPCIeEndpoint(info)
			dc.Kept = endpoint
			if endpoint {
				dc.KeptReason = "endpoint"
			} else {
				dc.SkipReason = reason
			}
		}
		out = append(out, dc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BDF < out[j].BDF })
	return out
}

// filterEndpoints applies classifyDevices() to bdfs and returns only the BDFs
// that pass, preserving the original (sysfs / caller) BDF form so downstream
// file paths under TMP_DIR remain unchanged. The skipped slice carries the
// classification records for skipped devices so callers can surface them in
// the final summary.
func filterEndpoints(bdfs []string, ov pcieFilterOverrides) (kept []string, skipped []deviceClassification) {
	decisions := classifyDevices(bdfs, ov)
	keptShort := make(map[string]bool, len(decisions))
	for _, d := range decisions {
		if d.Kept {
			keptShort[d.BDF] = true
		} else {
			skipped = append(skipped, d)
		}
	}
	for _, bdf := range bdfs {
		if keptShort[normalizeBDF(bdf)] {
			kept = append(kept, bdf)
		}
	}
	return kept, skipped
}

// printClassificationReport renders a deterministic, human-readable summary of
// every BDF and the keep/skip decision. It is used both by the -classify
// dry-run flag and by the post-test summary so users see exactly the same
// view.
func printClassificationReport(w *os.File, decisions []deviceClassification) {
	fmt.Fprintf(w, "%-12s %-9s %-9s %-7s %-8s %s\n",
		"BDF", "Vendor", "Device", "Class", "HdrType", "Decision")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 78))
	for _, d := range decisions {
		var ven, dev, cls, hdr string
		if d.InfoOK {
			ven = fmt.Sprintf("%04x", d.Info.Vendor)
			dev = fmt.Sprintf("%04x", d.Info.Device)
			cls = fmt.Sprintf("0x%02x", d.Info.BaseClass)
			hdr = fmt.Sprintf("Type %d", d.Info.HeaderType)
		} else {
			ven, dev, cls, hdr = "-", "-", "-", "-"
		}
		decision := "KEEP " + d.KeptReason
		if !d.Kept {
			decision = "SKIP " + d.SkipReason
		}
		fmt.Fprintf(w, "%-12s %-9s %-9s %-7s %-8s %s\n",
			d.BDF, ven, dev, cls, hdr, decision)
	}
}

// endpointFilterAllows reports whether bdf is kept by the active endpoint
// filter. It is permissive (returns true) when endpointFilterSet is nil so
// unit tests and any code path that bypasses the main() setup are unaffected.
// Callers pass either short or long BDFs; both are normalised before lookup.
func endpointFilterAllows(bdf string) bool {
	if endpointFilterSet == nil {
		return true
	}
	return endpointFilterSet[normalizeBDF(bdf)]
}

// runExternal runs an external command with an upper-bound timeout derived
// from rootCtx, so both Ctrl-C and a stuck child will release the caller.
// argv[0] must be an absolute path or be resolvable via exec.LookPath; callers
// are responsible for passing a trusted command name.
func runExternal(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(rootCtx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

// Absolute paths of trusted system binaries, resolved at startup via
// resolveBinaries() against a sanitised PATH. Using absolute paths for every
// subprocess prevents a writable PATH entry from shadowing standard tools.
var (
	lspciPath         string
	systemctlPath     string
	rebootPath        string
	configScanLogPath string
	setenforcePath    string
	ufwPath           string
)

// trustedBinDirs is the allow-list of system directories in which the standard
// tools may live. A resolved path outside these directories is treated as
// evidence of PATH tampering.
var trustedBinDirs = []string{"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"}

// resolveBinaries locks down PATH and resolves the external tools the test
// harness will invoke. It must run before setupSystemdService() or any loop
// that shells out.
func resolveBinaries() error {
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")

	for _, t := range []struct {
		name string
		dst  *string
	}{
		{"lspci", &lspciPath},
		{"systemctl", &systemctlPath},
		{"reboot", &rebootPath},
	} {
		p, err := exec.LookPath(t.name)
		if err != nil {
			return fmt.Errorf("required tool %q not found in PATH: %w", t.name, err)
		}
		trusted := false
		for _, d := range trustedBinDirs {
			if strings.HasPrefix(p, d) {
				trusted = true
				break
			}
		}
		if !trusted {
			return fmt.Errorf("tool %q resolved to untrusted path %q", t.name, p)
		}
		*t.dst = p
	}

	// configscan_log.sh is a custom helper shipped alongside the binary. Only
	// accept it from known absolute locations to avoid PATH-based hijacking.
	for _, p := range []string{
		filepath.Join(LPOT_DIR, "configscan_log.sh"),
		"/usr/local/bin/configscan_log.sh",
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			configScanLogPath = p
			break
		}
	}
	// These commands are optional and are handled as best-effort controls for
	// distributions where the corresponding security facility is installed.
	setenforcePath, _ = exec.LookPath("setenforce")
	ufwPath, _ = exec.LookPath("ufw")
	return nil
}

// ensureRoot aborts startup if the process is not running with effective uid 0.
// Every meaningful operation (reading PCI config space, writing to /etc, and
// rebooting the host) requires root, so refusing early is clearer than failing
// later with a partially-initialised state.
func ensureRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "lpot must be run as root (effective uid 0).")
		os.Exit(1)
	}
}

// secureLpotDir ensures LPOT_DIR exists as a real directory owned by root and
// not reachable through a symlink. Permissions are tightened to 0700 so that
// only root can read the accumulated logs and ignore_list.txt.
func secureLpotDir() error {
	info, err := os.Lstat(LPOT_DIR)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", LPOT_DIR, err)
		}
		if err := os.MkdirAll(LPOT_DIR, 0700); err != nil {
			return fmt.Errorf("create %s: %w", LPOT_DIR, err)
		}
		info, err = os.Lstat(LPOT_DIR)
		if err != nil {
			return fmt.Errorf("stat %s after create: %w", LPOT_DIR, err)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to run", LPOT_DIR)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", LPOT_DIR)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("%s must be owned by root (uid 0), found uid %d", LPOT_DIR, st.Uid)
	}
	if info.Mode().Perm() != 0700 {
		if err := os.Chmod(LPOT_DIR, 0700); err != nil {
			return fmt.Errorf("chmod %s to 0700: %w", LPOT_DIR, err)
		}
	}
	tmpInfo, err := os.Lstat(TMP_DIR)
	if err == nil {
		if tmpInfo.Mode()&os.ModeSymlink != 0 || !tmpInfo.IsDir() {
			return fmt.Errorf("%s must be a real directory", TMP_DIR)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(TMP_DIR, 0700); err != nil {
			return fmt.Errorf("create %s: %w", TMP_DIR, err)
		}
	} else {
		return fmt.Errorf("stat %s: %w", TMP_DIR, err)
	}
	if err := os.Chmod(TMP_DIR, 0700); err != nil {
		return fmt.Errorf("chmod %s: %w", TMP_DIR, err)
	}
	return nil
}

// openSecureAppend opens path for append-only writing with O_NOFOLLOW, so an
// attacker who can drop a symlink at path cannot redirect log writes to a
// target file elsewhere (e.g. /etc/shadow).
func openSecureAppend(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, perm)
}

// openSecureCreateExcl creates path with O_EXCL|O_NOFOLLOW, returning
// os.ErrExist if the file already exists. This closes the standard Stat+Create
// TOCTOU window used by reboot-script / systemd-unit setup.
func openSecureCreateExcl(path string, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
}

// writeFileNoFollow writes data to path, creating or truncating the file
// without following symlinks. If path is an existing symlink the OpenFile
// syscall fails with ELOOP, which prevents a symlink planted at path from
// redirecting the write to an attacker-chosen target. This is the drop-in
// replacement for os.WriteFile / os.Create in every place that writes to a
// path under /lpot, /tmp or /etc.
func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		f.Close()
		return werr
	}
	return f.Close()
}

// shellQuote returns a single-quoted POSIX shell word. Reboot script arguments
// originate from os.Args, so each argument must be quoted independently rather
// than joined into an unescaped command line.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// sleepInterruptible blocks until d elapses or ctx is cancelled. It returns
// true if the full duration elapsed and false if the context was cancelled
// first. Callers that must not proceed after cancellation should consult the
// return value (or stopFlag) before taking their next action.
func sleepInterruptible(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// PCIConfigHeader represents the PCI configuration space header (first 64 bytes)
type PCIConfigHeader struct {
	VendorID          uint16
	DeviceID          uint16
	Command           uint16
	Status            uint16
	RevisionID        uint8
	ClassCode         [3]byte
	CacheLineSize     uint8
	LatencyTimer      uint8
	HeaderType        uint8
	BIST              uint8
	BaseAddresses     [6]uint32
	CardbusCIS        uint32
	SubsystemVendorID uint16
	SubsystemID       uint16
	ExpansionROM      uint32
	CapPointer        uint8
	Reserved          [7]byte
	InterruptLine     uint8
	InterruptPin      uint8
	MinGnt            uint8
	MaxLat            uint8
}

// PCICapability represents a PCI capability structure
type PCICapability struct {
	ID     uint8
	Next   uint8
	Length uint8
	Data   []byte
}

// PCIDeviceInfo stores key information about a PCI device
type PCIDeviceInfo struct {
	BusID             string
	VendorID          uint16
	DeviceID          uint16
	Class             [3]byte
	SubsystemVendorID uint16
	SubsystemID       uint16
	Command           uint16
	Status            uint16
	Capabilities      map[uint8]PCICapability
	InterruptLine     uint8
	InterruptPin      uint8
	ConfigData        []byte // Store raw config data for comparison
}

// DeviceIgnoreBits structure for storing bytes to ignore
type DeviceIgnoreBits struct {
	BusID           string
	IgnoreBytes     map[int]bool
	IsUSBController bool
	IgnoreDevice    bool
}

// StableConfig holds PCI config data together with per-byte stability info.
// Bytes whose values disagree across rapid samples are flagged as timer noise
// and excluded from comparison, so only genuine capability changes are logged.
type StableConfig struct {
	Data          []byte
	UnstableBytes map[int]bool
}

// Device struct for lspci comparison
type Device struct {
	DeviceID     string
	BDF          string
	Capabilities struct {
		DevLnkFields map[string]string
	}
}

// ComparisonResult for device comparison
type ComparisonResult struct {
	HasDifferences   bool
	Error            error
	LogEntries       []string
	ScannedDeviceIDs []string
}

// Define which registers are timer-related
var timerRelatedOffsets = map[int]bool{
	0x0D: true, // LatencyTimer
	0x3E: true, // MinGnt
	0x3F: true, // MaxLat
	0xc8: true, // PTR
	0xc9: true, // PTR
	0xe4: true,
	0xe5: true,
}

// Define volatile status bits
var volatileStatusBits = uint16(0x00F8) // Bits 3-7 of Status register (offset 0x06)

// setupSignalHandlers installs SIGINT/SIGTERM handling. The first signal
// triggers graceful shutdown: rootCtx is cancelled (aborting in-flight exec
// commands via exec.CommandContext) and stopFlag is latched so in-process
// sleep loops can exit promptly. A second signal falls through to the Go
// runtime's default handler so an unresponsive run can still be forcibly
// killed with a second Ctrl-C.
func setupSignalHandlers() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt signal. Cleaning up...")
		stopFlag.Store(true)
		rootCancel()
		<-c
		fmt.Println("Second interrupt: forcing exit.")
		signal.Stop(c)
		os.Exit(130)
	}()
}

// File existence check
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// Get current timestamp string
func getCurrentTimestamp() string {
	return time.Now().Format(logTimeFormat)
}

// Validate input parameters
func validateInputParameters(waitHours, waitSeconds, standbyTime int) bool {
	if waitHours < 1 || waitHours > 8760 {
		fmt.Fprintf(os.Stderr, "Error: wait_hours must be between 1 and 8760\n")
		return false
	}
	if waitSeconds < 10 || waitSeconds > 3600 {
		fmt.Fprintf(os.Stderr, "Error: wait_seconds must be between 10 and 3600\n")
		return false
	}
	if standbyTime < 10 || standbyTime > 3600 {
		fmt.Fprintf(os.Stderr, "Error: standby_time must be between 10 and 3600\n")
		return false
	}
	return true
}

// Write timestamp
func writeTimestamp(hours int) error {
	now := time.Now().Add(time.Duration(hours) * time.Hour)
	data := []byte(fmt.Sprintf("%d\n", now.Unix()))
	if err := writeFileNoFollow(TIMESTAMP_FILE, data, 0644); err != nil {
		return fmt.Errorf("failed to write timestamp file: %v", err)
	}
	return nil
}

// Read timestamp
func readTimestamp() (time.Time, error) {
	data, err := os.ReadFile(TIMESTAMP_FILE)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read timestamp file: %v", err)
	}

	timestamp, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %v", err)
	}

	return time.Unix(timestamp, 0), nil
}

// updateRebootCount atomically reads, increments and writes the persisted
// reboot counter under an exclusive advisory lock. The lock protects against a
// stuck-but-respawned systemd unit racing against the next invocation, which
// would otherwise corrupt the counter and silently break the test schedule.
func updateRebootCount() (int, error) {
	fp, err := os.OpenFile(REBOOTCOUNT_FILE, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, fmt.Errorf("failed to open reboot count file: %v", err)
	}
	defer fp.Close()

	if err := syscall.Flock(int(fp.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("failed to lock reboot count file: %v", err)
	}
	defer syscall.Flock(int(fp.Fd()), syscall.LOCK_UN)

	var buf [64]byte
	n, _ := fp.ReadAt(buf[:], 0)
	count := 1
	if n > 0 {
		if c, err := strconv.Atoi(strings.TrimSpace(string(buf[:n]))); err == nil {
			count = c + 1
		}
	}

	if _, err := fp.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("failed to seek reboot count file: %v", err)
	}
	if err := fp.Truncate(0); err != nil {
		return 0, fmt.Errorf("failed to truncate reboot count file: %v", err)
	}
	if _, err := fmt.Fprintf(fp, "%d\n", count); err != nil {
		return 0, fmt.Errorf("failed to write reboot count: %v", err)
	}
	return count, nil
}

// Log initial test information. Emits a clearly delimited cycle-start banner
// so `grep '===== Cycle'` pulls out every cycle boundary, and every event
// between two banners is known to belong to the enclosing cycle.
func logInitialInfo(logFp *os.File, rebootCount int) {
	timeStr := getCurrentTimestamp()
	fmt.Fprintf(logFp, "\n\n%s ===== Cycle %d START =====\n", timeStr, rebootCount)
	fmt.Fprintf(logFp, "%s #########Start to test#########\n", timeStr)
	fmt.Fprintf(logFp, "\t\t\tReboot Count: %d\n", rebootCount)
	logFp.Sync()
}

// logCycleEnd emits the matching cycle-end banner. status is one of "clean",
// "clean (config noise)", or "changes detected" so `grep '===== Cycle.*END'`
// gives a per-cycle verdict without having to parse the intervening event
// stream. Only "changes detected" marks a genuinely concerning cycle.
func logCycleEnd(logFp *os.File, rebootCount int, status string) {
	timeStr := getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s ===== Cycle %d END (%s) =====\n", timeStr, rebootCount, status)
	logFp.Sync()
}

// Fetch PCI BDFs from /sys/bus/pci/devices/
func fetchPCIBDFs() ([]string, error) {
	entries, err := os.ReadDir(SYS_PCI_DEVICES)
	if err != nil {
		return nil, fmt.Errorf("failed to open PCI devices directory: %v", err)
	}

	var bdfs []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			bdfs = append(bdfs, entry.Name())
		}
	}

	return bdfs, nil
}

// Execute lspci command safely
func executeLspci(bdf, suffix string) error {
	var filename string
	if strings.Contains(suffix, "_init.txt") || strings.Contains(suffix, ".txt") {
		filename = filepath.Join(TMP_DIR, bdf+suffix)
	} else {
		filename = bdf + suffix
	}

	// Validate BDF format
	if bdf == "" || strings.ContainsAny(bdf, ";&|`$") {
		return fmt.Errorf("invalid BDF format: %s", bdf)
	}

	if debugMode {
		fmt.Printf("DEBUG: Executing lspci -s %s -vv > %s\n", bdf, filename)
	}

	// Validate BDF before passing to lspci. The value is sourced from sysfs
	// directory listings so it should always match bdfRegex, but refusing a
	// malformed value here removes an argv-injection vector outright.
	if !bdfRegex.MatchString(bdf) {
		return fmt.Errorf("refusing to invoke lspci with malformed BDF %q", bdf)
	}
	output, err := runExternal(lspciTimeout, lspciPath, "-s", bdf, "-vv")
	if err != nil {
		if debugMode {
			fmt.Printf("DEBUG: lspci command failed for BDF %s: %v\n", bdf, err)
		}
		return err
	}

	return writeFileNoFollow(filename, output, 0644)
}

// Create reboot script
func createRebootScript(args []string) error {
	scriptPath := filepath.Join(LPOT_DIR, "reboot.sh")

	// Use O_CREATE|O_EXCL|O_NOFOLLOW to close the TOCTOU window between the
	// existence check and the create: if an attacker drops a symlink at
	// scriptPath between Stat and Create the write would otherwise land in the
	// symlink target. O_EXCL makes the syscall fail with EEXIST if the file
	// already exists, which we treat as "already generated, nothing to do".
	file, err := os.OpenFile(scriptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0700)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			info, statErr := os.Lstat(scriptPath)
			if statErr != nil {
				return fmt.Errorf("failed to verify existing reboot script: %v", statErr)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to use %s: path is a symlink", scriptPath)
			}
			return nil
		}
		return fmt.Errorf("failed to create script file: %v", err)
	}
	defer file.Close()

	// Get the absolute path of the current executable
	executablePath, err := os.Executable()
	if err != nil {
		// Fallback to args[0] if os.Executable() fails
		executablePath = args[0]
		if !filepath.IsAbs(executablePath) {
			// Try to resolve relative path to absolute path
			if absPath, err := filepath.Abs(executablePath); err == nil {
				executablePath = absPath
			}
		}
	}

	fmt.Fprintln(file, "#!/bin/sh")
	fmt.Fprint(file, "exec ", shellQuote(executablePath))
	for _, arg := range args[1:] {
		fmt.Fprint(file, " ", shellQuote(arg))
	}
	fmt.Fprintln(file)

	return nil
}

// Setup systemd service
func setupSystemdService() error {
	servicePath := "/etc/systemd/system/lpot_reboot.service"
	scriptPath := filepath.Join(LPOT_DIR, "reboot.sh")

	serviceContent := systemdServiceContent(scriptPath)

	// O_CREATE|O_EXCL|O_NOFOLLOW: either we create the unit file freshly or we
	// treat its pre-existence as success. This avoids both the Stat/Create race
	// and the possibility of following a malicious symlink into another file
	// under /etc/systemd/system/.
	f, err := os.OpenFile(servicePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			info, statErr := os.Lstat(servicePath)
			if statErr != nil {
				return fmt.Errorf("failed to verify existing systemd service file: %v", statErr)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to use %s: path is a symlink", servicePath)
			}
			// The unit may exist but still need daemon-reload/enable. Continue
			// through the common systemd activation path below.
		} else {
			return fmt.Errorf("failed to create systemd service file: %v", err)
		}
	} else {
		if _, err := f.WriteString(serviceContent); err != nil {
			f.Close()
			return fmt.Errorf("failed to write systemd service file: %v", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close systemd service file: %v", err)
		}
	}

	// Reload systemd daemon
	if _, err := runExternal(systemctlTimeout, systemctlPath, "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v", err)
	}

	// Enable service
	if _, err := runExternal(systemctlTimeout, systemctlPath, "enable", "lpot_reboot.service"); err != nil {
		return fmt.Errorf("failed to enable lpot_reboot service: %v", err)
	}

	return nil
}

func systemdServiceContent(scriptPath string) string {
	return fmt.Sprintf(`[Unit]
Description=LPOT PCIe reboot stability test
After=local-fs.target

[Service]
ExecStart=%s
Restart=no
User=root
Group=root
WorkingDirectory=/lpot

[Install]
WantedBy=multi-user.target
`, scriptPath)
}

// selinuxConfigPath is kept as a variable so the Linux SELinux configuration
// path is explicit and easy to inspect in diagnostics.
var (
	selinuxConfigPath = "/etc/selinux/config"
)

// disableSELinux best-effort puts SELinux into permissive mode immediately and
// disabled mode across the next reboot. It is safe on distributions without
// SELinux: a missing config file is treated as "not installed". The config
// rewrite handles enforcing, permissive, and whitespace variants.
func disableSELinux() error {
	info, err := os.Lstat(selinuxConfigPath)
	if err != nil {
		// Missing config is normal on Ubuntu installations without SELinux and
		// on systems where SELinux was not installed.
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to modify %s: path is a symlink", selinuxConfigPath)
	}

	// Temporarily switch the running kernel into permissive mode. The command
	// is absent on non-SELinux systems, so there is nothing to do in that case.
	if setenforcePath != "" {
		if _, err := runExternal(systemctlTimeout, setenforcePath, "0"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: setenforce 0 failed: %v\n", err)
		}
	}

	data, err := os.ReadFile(selinuxConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", selinuxConfigPath, err)
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") {
			lines[i] = "SELINUX=disabled"
			found = true
		}
	}
	if !found {
		lines = append(lines, "SELINUX=disabled")
	}
	content := strings.Join(lines, "\n")
	if err := writeFileNoFollow(selinuxConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to update %s: %w", selinuxConfigPath, err)
	}
	return nil
}

// systemdUnitExists distinguishes a missing optional unit from a unit that is
// installed but currently inactive. The latter must still be disabled for the
// next reboot.
func systemdUnitExists(unit string) bool {
	out, err := runExternal(systemctlTimeout, systemctlPath, "cat", unit)
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

// stopAndDisableUnit stops an installed unit and disables it when it is enabled.
// Missing units are normal across RHEL, SLES, and Ubuntu and return nil.
func stopAndDisableUnit(unit string) error {
	if !systemdUnitExists(unit) {
		return nil
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "stop", unit); err != nil {
		return fmt.Errorf("failed to stop %s: %w", unit, err)
	}
	if state, err := runExternal(systemctlTimeout, systemctlPath, "is-enabled", unit); err == nil && strings.TrimSpace(string(state)) == "enabled" {
		if _, err := runExternal(systemctlTimeout, systemctlPath, "disable", unit); err != nil {
			return fmt.Errorf("failed to disable %s: %w", unit, err)
		}
	}
	return nil
}

// disableFirewall stops and disables firewall services used by RHEL, SLES,
// and Ubuntu families. Missing services are expected and never abort the test.
// The explicit service list also covers older SLES installations that still
// expose SuSEfirewall2 rather than firewalld/nftables.
func disableFirewall() error {
	services := []string{
		"firewalld",
		"ufw",
		"nftables",
		"iptables",
		"ip6tables",
		"SuSEfirewall2",
	}
	for _, service := range services {
		if err := stopAndDisableUnit(service); err != nil {
			return err
		}
	}
	if ufwPath != "" {
		if _, err := runExternal(systemctlTimeout, ufwPath, "disable"); err != nil {
			return fmt.Errorf("failed to disable ufw: %w", err)
		}
	}
	return nil
}

// disableAppArmor stops and disables Ubuntu's AppArmor service. RHEL and SLES
// normally do not install it, so a missing unit is intentionally harmless.
func disableAppArmor() error {
	return stopAndDisableUnit("apparmor")
}

func prepareHostPolicies() error {
	if err := disableFirewall(); err != nil {
		return fmt.Errorf("disable firewall: %w", err)
	}
	if err := disableAppArmor(); err != nil {
		return fmt.Errorf("disable AppArmor: %w", err)
	}
	if err := disableSELinux(); err != nil {
		return fmt.Errorf("configure SELinux: %w", err)
	}
	return nil
}

// Reset lpot directory
func resetLpotDirectory() {
	fmt.Println("Resetting /lpot directory...")

	// Refuse to operate on LPOT_DIR if it is a symlink or not owned by root,
	// to avoid inadvertently deleting files outside of /lpot.
	info, err := os.Lstat(LPOT_DIR)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Printf("Refusing to reset: %s is a symlink\n", LPOT_DIR)
			return
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			fmt.Printf("Refusing to reset: %s must be owned by root (uid 0), found uid %d\n", LPOT_DIR, st.Uid)
			return
		}
	}

	if err := os.MkdirAll(LPOT_DIR, 0700); err != nil {
		fmt.Printf("Failed to create %s directory: %v\n", LPOT_DIR, err)
		return
	}

	// Clean all files directly under /lpot. WalkDir does not descend into
	// symlinks by default; os.Remove removes the symlink entry itself rather
	// than following it, so both layers are safe against a symlink-redirected
	// delete.
	filepath.WalkDir(LPOT_DIR, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && path != LPOT_DIR {
			os.Remove(path)
		}
		return nil
	})

	fmt.Println("Reset completed. You can now run lpot with normal parameters.")
}

// printDryRunFile reports a complete text payload without opening the target
// for writing. It intentionally reads an existing regular file only to make
// the audit output explain whether the normal O_EXCL/write path would create,
// skip, or replace it.
func printDryRunFile(path, action string, mode os.FileMode, content string) {
	state := "WOULD CREATE"
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			state = "WOULD REFUSE (symlink exists)"
		} else {
			state = "WOULD USE EXISTING"
			if action == "replace" {
				state = "WOULD REPLACE"
			}
		}
	} else if !os.IsNotExist(err) {
		state = fmt.Sprintf("WOULD INSPECT (stat failed: %v)", err)
	}

	fmt.Printf("[DRY-RUN] %s %s mode=%#o\n", state, path, mode.Perm())
	fmt.Printf("[DRY-RUN] CONTENT BEGIN %s\n%s[DRY-RUN] CONTENT END %s\n", path, content, path)
}

func printDryRunCommand(name string, args ...string) {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	fmt.Printf("[DRY-RUN] WOULD EXEC %s\n", strings.Join(parts, " "))
}

func printDryRunReadCommand(timeout time.Duration, name string, args ...string) []byte {
	printDryRunCommand(name, args...)
	out, err := runExternal(timeout, name, args...)
	if err != nil {
		fmt.Printf("[DRY-RUN] READ COMMAND FAILED: %v\n", err)
		return nil
	}
	fmt.Printf("[DRY-RUN] COMMAND OUTPUT BEGIN %s\n%s[DRY-RUN] COMMAND OUTPUT END %s\n",
		name, string(out), name)
	return out
}

// runDryRunAudit performs the read-only portion of startup and prints every
// planned mutation. It is deliberately separate from the normal execution
// path: a dry run must remain safe even when a future write is added to the
// reboot loop and its author forgets to add another guard.
func runDryRunAudit(args []string, waitHours, standbyTime, waitSeconds int, stopService bool) {
	fmt.Println("[DRY-RUN] audit mode enabled; no filesystem or host-state mutation will occur")
	fmt.Printf("[DRY-RUN] parameters: duration=%dh driver-delay=%ds reboot-delay=%ds stop-on-error=%t\n",
		waitHours, standbyTime, waitSeconds, stopService)

	if info, err := os.Lstat(LPOT_DIR); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0700\n", LPOT_DIR)
		} else {
			fmt.Printf("[DRY-RUN] READ %s failed: %v\n", LPOT_DIR, err)
		}
	} else {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			LPOT_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}
	if info, err := os.Lstat(TMP_DIR); err != nil && os.IsNotExist(err) {
		fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0700\n", TMP_DIR)
	} else if err == nil {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			TMP_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}

	services := []string{"firewalld", "ufw", "nftables", "iptables", "ip6tables", "SuSEfirewall2", "apparmor"}
	for _, service := range services {
		if systemdUnitExists(service) {
			printDryRunCommand(systemctlPath, "stop", service)
			printDryRunCommand(systemctlPath, "is-enabled", service)
			printDryRunCommand(systemctlPath, "disable", service)
		} else {
			fmt.Printf("[DRY-RUN] READ systemd unit %s: absent (skip)\n", service)
		}
	}
	if ufwPath != "" {
		printDryRunCommand(ufwPath, "disable")
	}

	if info, err := os.Lstat(selinuxConfigPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
		if setenforcePath != "" {
			printDryRunCommand(setenforcePath, "0")
		}
		if data, readErr := os.ReadFile(selinuxConfigPath); readErr == nil {
			lines := strings.Split(string(data), "\n")
			found := false
			for i, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") {
					lines[i] = "SELINUX=disabled"
					found = true
				}
			}
			if !found {
				lines = append(lines, "SELINUX=disabled")
			}
			printDryRunFile(selinuxConfigPath, "replace", 0644, strings.Join(lines, "\n"))
		} else {
			fmt.Printf("[DRY-RUN] READ %s failed: %v\n", selinuxConfigPath, readErr)
		}
	} else {
		fmt.Printf("[DRY-RUN] READ %s: absent or symlink (no SELinux config write)\n", selinuxConfigPath)
	}

	executablePath, err := os.Executable()
	if err != nil {
		executablePath = args[0]
		if !filepath.IsAbs(executablePath) {
			executablePath, _ = filepath.Abs(executablePath)
		}
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\nexec ")
	script.WriteString(shellQuote(executablePath))
	for _, arg := range args[1:] {
		script.WriteString(" ")
		script.WriteString(shellQuote(arg))
	}
	script.WriteByte('\n')
	printDryRunFile(filepath.Join(LPOT_DIR, "reboot.sh"), "create", 0700, script.String())

	servicePath := "/etc/systemd/system/lpot_reboot.service"
	printDryRunFile(servicePath, "create", 0644, systemdServiceContent(filepath.Join(LPOT_DIR, "reboot.sh")))
	printDryRunCommand(systemctlPath, "daemon-reload")
	printDryRunCommand(systemctlPath, "enable", "lpot_reboot.service")

	nextCount := 1
	if data, err := os.ReadFile(REBOOTCOUNT_FILE); err == nil {
		if count, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil {
			nextCount = count + 1
		}
	}
	printDryRunFile(REBOOTCOUNT_FILE, "replace", 0600, fmt.Sprintf("%d\n", nextCount))
	printDryRunFile(TIMESTAMP_FILE, "replace", 0644,
		fmt.Sprintf("%d\n", time.Now().Add(time.Duration(waitHours)*time.Hour).Unix()))

	fmt.Printf("[DRY-RUN] WOULD READ %s and discover PCI devices\n", SYS_PCI_DEVICES)
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fmt.Printf("[DRY-RUN] READ PCI devices failed: %v\n", err)
	} else {
		overrides, filterErr := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
		if filterErr != nil {
			overrides = pcieFilterOverrides{Include: map[string]bool{}, Exclude: map[string]bool{}}
			fmt.Printf("[DRY-RUN] READ %s: absent/unreadable, using automatic classification\n", PCIE_FILTER_FILE)
		}
		kept, skipped := filterEndpoints(bdfs, overrides)
		fmt.Printf("[DRY-RUN] PCI classification: kept=%d skipped=%d\n", len(kept), len(skipped))
		initialOutput := printDryRunReadCommand(lspciTimeout, lspciPath, "-vv")
		if len(initialOutput) > 0 {
			printDryRunFile(INITIAL_PCI_DEVICES, "replace", 0644, string(initialOutput))
		}
		for _, bdf := range kept {
			output := printDryRunReadCommand(lspciTimeout, lspciPath, "-s", bdf, "-vv")
			if len(output) > 0 {
				printDryRunFile(filepath.Join(TMP_DIR, bdf+"_init.txt"), "replace", 0644, string(output))
				printDryRunFile(filepath.Join(TMP_DIR, bdf+".txt"), "replace", 0644, string(output))
			} else {
				fmt.Printf("[DRY-RUN] WOULD WRITE %s (content unavailable because read command failed)\n", filepath.Join(TMP_DIR, bdf+"_init.txt"))
				fmt.Printf("[DRY-RUN] WOULD WRITE %s (content unavailable because read command failed)\n", filepath.Join(TMP_DIR, bdf+".txt"))
			}
		}
	}

	for _, path := range []string{
		INITIAL_PCI_DEVICES, IGNORE_LIST_FILE, "/lpot/initial.bin", "/lpot/current.bin",
		CONFIG_CHANGES_LOG, CLASSIFY_LOG, LPOTSCAN_LOG, REBOOT_LOG,
	} {
		fmt.Printf("[DRY-RUN] WOULD WRITE/UPDATE %s (content generated from read-only PCI scan and comparison)\n", path)
	}
	fmt.Printf("[DRY-RUN] WOULD REMOVE generated temporary snapshots under %s\n", TMP_DIR)
	fmt.Printf("[DRY-RUN] WOULD WAIT %ds before reboot\n", waitSeconds)
	printDryRunCommand(rebootPath)
	fmt.Println("[DRY-RUN] audit complete; reboot command was not executed")
}

// Show help
func showHelp(programName string) {
	fmt.Printf("Usage: %s [OPTIONS]\n", programName)
	fmt.Printf("Version: %s (Integrated)\n", version)
	fmt.Printf("Author: Nephom,Chiang (Integrated by AI)\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -t <hours>   Setup runtime, default is 12 hours.\n")
	fmt.Printf("  -d <secs>    Setup delay time for driver ready, default is 300 seconds.\n")
	fmt.Printf("  -s <secs>    Setup delay time for reboot, default is 300 seconds.\n")
	fmt.Printf("  -p           Set stop flag when Error occurred!\n")
	fmt.Printf("  -g           Dry-run audit mode; show commands and file contents without changing the host.\n")
	fmt.Printf("  -r           Reset /lpot directory and clean all files.\n")
	fmt.Printf("  -scan        Scan USB/bridge/volatile devices and write /lpot/ignore_list.txt, then exit.\n")
	fmt.Printf("  -classify    Print PCI endpoint classification report and exit (dry-run).\n")
	fmt.Printf("  -h, --help   Show Help menu\n")
	fmt.Printf("\nNOTE: PCI device scanning is automatically performed after driver ready time if ignore_list.txt doesn't exist.\n")
	fmt.Printf("NOTE: Bridges and legacy PCI devices are filtered automatically. Override via %s.\n", PCIE_FILTER_FILE)
	fmt.Printf("\nExample:\n")
	fmt.Printf("  %s -t 24 -s 600    Run reboot during 24 hours and each reboot wait for 600 seconds\n", programName)
	fmt.Printf("  %s -g -t 2         Print a read-only audit for a 2-hour run\n", programName)
	fmt.Printf("  %s -r              Reset /lpot directory to clean state\n", programName)
	fmt.Printf("  %s -scan           Only scan PCI devices and generate ignore bits file\n", programName)
	fmt.Printf("  %s -classify       Preview which BDFs the endpoint filter will keep/skip\n", programName)
}

func main() {
	// Root privileges are required to read /sys/bus/pci/*/config, write under
	// /etc/systemd/system, and call reboot(). Bail out early rather than failing
	// half-initialised.
	ensureRoot()

	// rootCtx is the single cancellation primitive for external commands and
	// internal sleep loops. signal handlers cancel it on first Ctrl-C.
	rootCtx, rootCancel = context.WithCancel(context.Background())
	defer rootCancel()

	// Signal handlers must be installed before any long-running operation.
	setupSignalHandlers()

	// Resolve external tool paths against a sanitised PATH to prevent a
	// writable PATH entry from shadowing standard system binaries.
	if err := resolveBinaries(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve required binaries: %v\n", err)
		os.Exit(1)
	}

	// Parse flags before touching /lpot so dry-run mode can guarantee that
	// startup itself does not create or chmod any runtime directory.
	var (
		waitHours   = flag.Int("t", 12, "Setup runtime in hours")
		standbyTime = flag.Int("d", 300, "Setup delay time for driver ready in seconds")
		waitSeconds = flag.Int("s", 300, "Setup delay time for reboot in seconds")
		stopService = flag.Bool("p", false, "Set stop flag when error occurred")
		debug       = flag.Bool("g", false, "Dry-run audit mode")
		reset       = flag.Bool("r", false, "Reset /lpot directory")
		scanOnly    = flag.Bool("scan", false, "Only scan and generate ignore bits file, then exit")
		classify    = flag.Bool("classify", false, "Print PCI endpoint classification report and exit")
		help        = flag.Bool("h", false, "Show help menu")
	)
	flag.Parse()
	debugMode = *debug

	if *help {
		showHelp(os.Args[0])
		return
	}
	if debugMode {
		runDryRunAudit(os.Args, *waitHours, *standbyTime, *waitSeconds, *stopService)
		return
	}

	// Ensure /lpot is a real root-owned directory with tight permissions. All
	// persistent state files are addressed via absolute constants thereafter,
	// so we no longer need to Chdir into it.
	if err := secureLpotDir(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to secure %s: %v\n", LPOT_DIR, err)
		os.Exit(1)
	}

	if *reset {
		resetLpotDirectory()
		return
	}

	if *scanOnly {
		if err := prepareHostPolicies(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to prepare host: %v\n", err)
			os.Exit(1)
		}
		if err := scanAndGenerateIgnoreBits(); err != nil {
			fmt.Printf("Error during scan: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// -classify is a dry-run that prints how every PCI BDF would be treated by
	// the endpoint filter (after pcie_filter.txt overrides), then exits. It
	// touches no persistent state so users can run it before committing to a
	// reboot test.
	if *classify {
		if err := prepareHostPolicies(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to prepare host: %v\n", err)
			os.Exit(1)
		}
		bdfs, err := fetchPCIBDFs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to fetch PCI BDFs: %v\n", err)
			os.Exit(1)
		}
		ov, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", PCIE_FILTER_FILE, err)
			os.Exit(1)
		}
		decisions := classifyDevices(bdfs, ov)
		printClassificationReport(os.Stdout, decisions)

		// Persist the same report to /lpot/pci_devices_classify.log (alongside
		// reboot.log / pci-config-changes.log) so the keep/skip decisions can be
		// reviewed later. Appended with a timestamped banner so repeated runs
		// build a history instead of silently overwriting the prior report. A
		// write failure is non-fatal: the report already printed to stdout.
		if fp, err := openSecureAppend(CLASSIFY_LOG, 0644); err == nil {
			fmt.Fprintf(fp, "\n===== %s classify run (%d devices) =====\n",
				getCurrentTimestamp(), len(decisions))
			printClassificationReport(fp, decisions)
			fp.Close()
		} else {
			fmt.Fprintf(os.Stderr, "Warning: failed to write %s: %v\n", CLASSIFY_LOG, err)
		}
		return
	}

	// Validate input parameters
	if !validateInputParameters(*waitHours, *waitSeconds, *standbyTime) {
		os.Exit(1)
	}

	if debugMode {
		fmt.Printf("DEBUG: Parameters - wait_hours: %d, reboot_wait_seconds: %d, driver_ready_time: %d, stopService: %t\n",
			*waitHours, *waitSeconds, *standbyTime, *stopService)
	}

	// The test host is dedicated lab hardware. Disable host firewall and
	// mandatory access-control services before installing the reboot service so
	// the PCI test is not blocked by distro-specific policy.
	if err := prepareHostPolicies(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to prepare host: %v\n", err)
		os.Exit(1)
	}

	// Create reboot script if not exists
	if err := createRebootScript(os.Args); err != nil {
		fmt.Printf("Failed to create reboot script: %v\n", err)
	}

	// Check timestamp
	if !fileExists(TIMESTAMP_FILE) {
		if err := writeTimestamp(*waitHours); err != nil {
			fmt.Printf("Failed to write timestamp: %v\n", err)
			os.Exit(1)
		}
	} else {
		currentTime := time.Now()
		timestamp, err := readTimestamp()
		if err != nil {
			fmt.Printf("Failed to read timestamp: %v\n", err)
			os.Exit(1)
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

	// Setup systemd service
	if err := setupSystemdService(); err != nil {
		fmt.Printf("Failed to setup systemd service: %v\n", err)
		os.Exit(1)
	}

	// Initialize statistics tracking
	initializeStatistics()

	// Update reboot count and publish it so log helpers can tag events with
	// [Cycle N] for every subsequent write.
	rebootCount, err := updateRebootCount()
	if err != nil {
		fmt.Printf("Failed to update reboot count: %v\n", err)
		os.Exit(1)
	}
	currentCycle.Store(int64(rebootCount))

	totalRebootCycles = rebootCount

	// Open log file
	logFp, err := openSecureAppend(REBOOT_LOG, 0644)
	if err != nil {
		fmt.Printf("Failed to open reboot.log: %v\n", err)
		os.Exit(1)
	}
	defer logFp.Close()

	timestampStr := getCurrentTimestamp()
	logInitialInfo(logFp, rebootCount)

	// Get PCI device list
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fmt.Printf("Failed to fetch PCI BDFs: %v\n", err)
		os.Exit(1)
	}

	// Apply endpoint classification (three-layer rule) plus the optional
	// pcie_filter.txt overrides so bridges and legacy non-PCIe devices are
	// excluded from every per-cycle comparison and from the config-space
	// snapshots. The skipped set is remembered for the final summary so
	// users see exactly which BDFs were dropped and why.
	overrides, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
	if err != nil {
		fmt.Printf("Warning: Failed to load %s: %v\n", PCIE_FILTER_FILE, err)
		overrides = pcieFilterOverrides{Include: map[string]bool{}, Exclude: map[string]bool{}}
	}
	kept, skipped := filterEndpoints(bdfs, overrides)
	skippedDevicesGlobal = skipped
	endpointFilterSet = make(map[string]bool, len(kept))
	for _, bdf := range kept {
		endpointFilterSet[normalizeBDF(bdf)] = true
	}
	fmt.Fprintf(logFp, "%s Endpoint filter: kept %d / %d devices (%d skipped)\n",
		getCurrentTimestamp(), len(kept), len(bdfs), len(skipped))
	logFp.Sync()
	bdfs = kept

	if debugMode {
		fmt.Printf("DEBUG: Found %d PCI devices (after endpoint filter)\n", len(bdfs))
		for i, bdf := range bdfs {
			if i < 10 { // Only show first 10 devices
				fmt.Printf("DEBUG: PCI device %d: %s\n", i+1, bdf)
			}
		}
		if len(bdfs) > 10 {
			fmt.Printf("DEBUG: ... and %d more devices\n", len(bdfs)-10)
		}
	}

	// Wait for driver ready
	fmt.Fprintf(logFp, "%s Wait %d seconds for devices driver ready. \n", timestampStr, *standbyTime)
	logFp.Sync()
	fmt.Printf("%s Wait %d seconds for devices driver ready. \n", timestampStr, *standbyTime)

	// Sleep in segments to respond to signals
	for i := 0; i < *standbyTime && !stopFlag.Load(); i++ {
		time.Sleep(1 * time.Second)
	}

	if stopFlag.Load() {
		fmt.Fprintf(logFp, "Received stop signal, exiting gracefully.\n")
		return
	}

	// Auto-scan after driver ready time (if ignore_list.txt doesn't exist)
	if !fileExists(IGNORE_LIST_FILE) {
		timestampStr = getCurrentTimestamp()
		fmt.Fprintf(logFp, "%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)
		logFp.Sync()
		fmt.Printf("%s Auto-scanning PCI devices to generate ignore bits...\n", timestampStr)

		if err := scanAndGenerateIgnoreBits(); err != nil {
			fmt.Printf("Warning: Auto-scan failed: %v\n", err)
			fmt.Fprintf(logFp, "%s Warning: Auto-scan failed: %v\n", timestampStr, err)
		} else {
			fmt.Printf("%s Auto-scan completed successfully\n", timestampStr)
			fmt.Fprintf(logFp, "%s Auto-scan completed successfully\n", timestampStr)
		}
		logFp.Sync()
	}

	if len(bdfs) == 0 {
		fmt.Printf("Error: No PCI devices found\n")
		os.Exit(1)
	}

	// Create initial PCI device files if not exist
	if !fileExists(INITIAL_PCI_DEVICES) {
		if debugMode {
			fmt.Printf("DEBUG: Executing initial lspci -vv > %s\n", INITIAL_PCI_DEVICES)
		}

		output, err := runExternal(lspciTimeout, lspciPath, "-vv")
		if err != nil {
			fmt.Printf("Warning: Initial lspci command failed: %v\n", err)
		} else {
			if werr := writeFileNoFollow(INITIAL_PCI_DEVICES, output, 0644); werr != nil {
				fmt.Printf("Warning: Failed to write %s: %v\n", INITIAL_PCI_DEVICES, werr)
			}
		}

		for _, bdf := range bdfs {
			if stopFlag.Load() {
				break
			}
			executeLspci(bdf, "_init.txt")
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
		fmt.Printf("Warning: Config scan failed: %v\n", err)
	}

	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s PCI Config space Scan Done\n", timestampStr)
	logFp.Sync()

	// Process PCI devices
	if err := processPCIDevices(bdfs, logFp, *stopService); err != nil {
		timestampStr = getCurrentTimestamp()
		fmt.Fprintf(logFp, "%s PCI devices check failed\n", timestampStr)
		os.Exit(1)
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

	// Prepare for reboot. The wait is interruptible so SIGINT/SIGTERM does not
	// force the operator to sit through the full waitSeconds (up to 3600).
	timestampStr = getCurrentTimestamp()
	fmt.Fprintf(logFp, "%s Wait %d seconds for reboot SUT. \n", timestampStr, *waitSeconds)
	logFp.Sync()
	sleepInterruptible(rootCtx, time.Duration(*waitSeconds)*time.Second)

	// If a stop was requested during the wait (Ctrl-C, SIGTERM, or context
	// cancellation from anywhere else), skip the reboot entirely: rebooting a
	// host the operator has just asked us to leave alone would be surprising
	// and could disrupt other workloads running on the machine.
	if stopFlag.Load() {
		fmt.Fprintf(logFp, "%s Stop requested before reboot; skipping reboot.\n", getCurrentTimestamp())
		logFp.Sync()
		return
	}

	// Remove lpotscan log
	os.Remove(LPOTSCAN_LOG)

	// Execute reboot (skip in debug mode)
	if debugMode {
		fmt.Printf("DEBUG: Reboot command disabled in debug mode\n")
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
		}
	}
}

// scanAndGenerateIgnoreBits scans PCI devices and generates ignore bits file
func scanAndGenerateIgnoreBits() error {
	timestamp := logTimestamp()
	fmt.Printf("%s Starting volatile byte detection (this will take about 5 seconds)...\n", timestamp)

	ignoreBits, _, err := detectVolatileBytesWithSamples()
	if err != nil {
		return fmt.Errorf("failed to detect volatile bytes: %v", err)
	}

	err = saveIgnoreBits(IGNORE_LIST_FILE, ignoreBits)
	if err != nil {
		return fmt.Errorf("failed to save ignore bits: %v", err)
	}

	fmt.Printf("%s Successfully saved ignore bits for %d devices\n", timestamp, len(ignoreBits))
	return nil
}

// runConfigScan executes the config scan logic
func runConfigScan() error {
	initialFile := "/lpot/initial.bin"

	// Check if ignore_list.txt exists, if not run scan first
	if !fileExists(IGNORE_LIST_FILE) {
		if err := scanAndGenerateIgnoreBits(); err != nil {
			fmt.Printf("Warning: Failed to generate ignore bits: %v\n", err)
		}
	}

	// Check if initial.bin exists
	if !fileExists(initialFile) {
		timestamp := logTimestamp()
		fmt.Printf("%s Initial PCI config not found, creating %s\n", timestamp, initialFile)

		if err := savePCIConfig(initialFile); err != nil {
			return fmt.Errorf("error saving initial PCI config: %v", err)
		}
		fmt.Printf("%s Initial PCI config saved.\n", timestamp)
		return nil
	}

	// Compare initial snapshot against freshly-sampled stable config
	timestamp := logTimestamp()
	fmt.Printf("%s Comparing PCI configs...\n", timestamp)
	return compareDeviceConfigs(initialFile, CONFIG_CHANGES_LOG)
}

// processPCIDevices processes all PCI devices and checks for changes
func processPCIDevices(bdfs []string, logFp *os.File, stopService bool) error {
	newDevices := []string{}
	removedDevices := []string{}

	// Read existing init files
	initFiles, err := filepath.Glob(filepath.Join(TMP_DIR, "*_init.txt"))
	if err != nil {
		return fmt.Errorf("error finding init files: %v", err)
	}

	// Generate current device files
	for _, bdf := range bdfs {
		executeLspci(bdf, ".txt")
	}

	// Check for removed devices. Removed devices cannot be queried via sysfs
	// (they're gone), so we only emit the BDF; lspci dump for this BDF is
	// already in *_init.txt and is appended to the log by filterLpotscanErrors.
	for _, initFile := range initFiles {
		filename := filepath.Base(initFile)
		bdf := strings.TrimSuffix(filename, "_init.txt")
		currentFile := filepath.Join(TMP_DIR, bdf+".txt")

		if !fileExists(currentFile) {
			removedDevices = append(removedDevices, bdf)
			fmt.Fprintf(logFp, "%s %sREMOVED Device: %s\n", getCurrentTimestamp(), cycleTag(), bdf)
			recordCycleChange(fmt.Sprintf("device removed: %s", bdf))
		}
	}

	// Check for new devices. New devices are present in sysfs, so enrich the
	// log line with vendor/device/class to help identify which hardware
	// appeared without requiring a separate lspci.
	for _, bdf := range bdfs {
		initFile := filepath.Join(TMP_DIR, bdf+"_init.txt")
		if !fileExists(initFile) {
			newDevices = append(newDevices, bdf)
			fmt.Fprintf(logFp, "%s %sNEW Device: %s\n", getCurrentTimestamp(), cycleTag(), describePCIBDF(bdf))
			recordCycleChange(fmt.Sprintf("device added: %s", bdf))
		}
	}

	allUnchanged := (len(newDevices) == 0 && len(removedDevices) == 0)
	overallSuccess := true

	// Track device topology changes. A topology change always interrupts any
	// active "clean streak" summary that may have been aggregating.
	if !allUnchanged {
		cyclesWithDeviceTopologyChanges++
		flushCleanStreak(logFp)
	}

	if allUnchanged {
		// Load ignore list for lpotscan
		ignoreSet, err := loadIgnoreList(IGNORE_LIST_FILE)
		if err != nil {
			fmt.Printf("Warning: Failed to load ignore list: %v\n", err)
			ignoreSet = make(map[string]bool)
		}

		// Compare each device using lpotscan logic
		for _, bdf := range bdfs {
			initFile := filepath.Join(TMP_DIR, bdf+"_init.txt")
			currentFile := filepath.Join(TMP_DIR, bdf+".txt")

			if !fileExists(initFile) || !fileExists(currentFile) {
				continue
			}

			result := compareDeviceFiles(initFile, currentFile, ignoreSet, stopService)
			if result.HasDifferences {
				overallSuccess = false
			}
			if result.Error != nil && stopService {
				return result.Error
			}
		}

		timeStr := getCurrentTimestamp()
		logFile, err := openSecureAppend(REBOOT_LOG, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		defer logFile.Close()

		if !overallSuccess {
			flushCleanStreak(logFile)
			fmt.Fprintf(logFile, "%s %sHad devices changed\n", timeStr, cycleTag())
			logFile.Sync()
			cyclesWithChanges++
			cyclesWithLspciChanges++
			recordCycleChange("lspci differences detected")
			if debugMode {
				fmt.Printf("DEBUG: Device changes detected\n")
			}
			filterLpotscanErrors(LPOTSCAN_LOG, logFile)
			logFile.Sync()
			if stopService {
				fmt.Fprintf(logFile, "%s %sYou setting -p parameter, I will stop reboot test.\n", timeStr, cycleTag())
				logFile.Sync()
				if debugMode {
					fmt.Printf("DEBUG: Stop service flag is set, exiting due to device changes\n")
				}
				os.Exit(1)
			}
		} else {
			// "No devices changed" is repeated every cycle; collapse
			// consecutive clean cycles into a single line with a running
			// counter so the log stays readable across 48 h runs.
			noteCleanCycle(logFile, timeStr)
			if debugMode {
				fmt.Printf("DEBUG: No device changes detected\n")
			}
		}
	} else {
		// Topology change implies at least one new/removed device was already
		// logged above. Ensure the cycle is flagged even when lpotscan is
		// skipped by `allUnchanged == false`.
		cyclesWithChanges++
	}

	return nil
}

// cleanCycleStreak tracks how many consecutive cycles reported "No devices
// changed". A single summary line is emitted for long clean runs so reboot.log
// doesn't grow a page per idle cycle.
var (
	cleanCycleMu     sync.Mutex
	cleanCycleStart  int64
	cleanCycleLast   int64
	cleanCycleCount  int
	cleanCycleHeader bool
)

// noteCleanCycle emits a single line when a clean streak starts, then updates
// a trailing "... N cycles clean (Cycle X-Y)" status line in-memory state.
// The final flush happens either when a non-clean cycle interrupts the streak
// (handled via flushCleanStreak) or at test end via generateFinalSummary.
func noteCleanCycle(logFile *os.File, timeStr string) {
	cleanCycleMu.Lock()
	defer cleanCycleMu.Unlock()
	cycle := currentCycle.Load()
	if !cleanCycleHeader {
		fmt.Fprintf(logFile, "%s [Cycle %d] No devices changed (clean streak started)\n", timeStr, cycle)
		cleanCycleHeader = true
		cleanCycleStart = cycle
		cleanCycleCount = 1
	} else {
		cleanCycleCount++
	}
	cleanCycleLast = cycle
	// Every 25 clean cycles, emit a heartbeat so long quiet periods still
	// show progress without spamming the log every cycle.
	if cleanCycleCount%25 == 0 {
		fmt.Fprintf(logFile, "%s [Cycle %d] %d consecutive clean cycles (Cycle %d..%d)\n",
			timeStr, cycle, cleanCycleCount, cleanCycleStart, cleanCycleLast)
	}
	logFile.Sync()
}

// flushCleanStreak terminates a clean streak and writes a one-line summary
// to logFile. Called from any path that records a non-clean event, and from
// generateFinalSummary at shutdown.
func flushCleanStreak(logFile *os.File) {
	cleanCycleMu.Lock()
	defer cleanCycleMu.Unlock()
	if !cleanCycleHeader {
		return
	}
	fmt.Fprintf(logFile, "%s [Cycle %d] Clean streak ended: %d cycles clean (Cycle %d..%d)\n",
		getCurrentTimestamp(), currentCycle.Load(), cleanCycleCount, cleanCycleStart, cleanCycleLast)
	logFile.Sync()
	cleanCycleHeader = false
	cleanCycleCount = 0
}

// cleanupBDFFiles removes current .txt files but keeps _init.txt files
func cleanupBDFFiles() {
	entries, err := os.ReadDir(TMP_DIR)
	if err != nil {
		fmt.Printf("Warning: Failed to read tmp directory: %v\n", err)
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".txt") && !strings.HasSuffix(name, "_init.txt") && name != "initial_pci_devices.txt" {
			filepath := filepath.Join(TMP_DIR, name)
			if err := os.Remove(filepath); err != nil {
				fmt.Printf("Warning: Failed to delete file %s: %v\n", filepath, err)
			}
		}
	}
}

// detectVolatileBytesWithSamples detects frequently changing bytes and returns sample data
func detectVolatileBytesWithSamples() (map[string]DeviceIgnoreBits, []map[string][]byte, error) {
	ignoreBits := make(map[string]DeviceIgnoreBits)

	// Create a fresh 0700 private directory under /tmp (name randomised by the
	// kernel) and keep all sample files inside it. This avoids the symlink /
	// predictable-filename race that a predictable /tmp/pci_config_tmp*.bin
	// layout would expose to other local users.
	sampleDir, err := os.MkdirTemp("", "lpot-ignore-bits-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sample directory: %v", err)
	}
	defer os.RemoveAll(sampleDir)

	const sampleCount = 5
	tmpFiles := make([]string, sampleCount)
	for i := range tmpFiles {
		tmpFiles[i] = filepath.Join(sampleDir, fmt.Sprintf("sample-%d.bin", i+1))
	}

	fmt.Println("Collecting PCI config samples for volatile byte detection...")

	// Collect 5 samples, 1 second apart
	for i, tmpFile := range tmpFiles {
		fmt.Printf("Collecting sample %d/%d...\n", i+1, len(tmpFiles))
		if err := savePCIConfig(tmpFile); err != nil {
			return nil, nil, fmt.Errorf("failed to create sample %d: %v", i+1, err)
		}

		if i < len(tmpFiles)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	// Read sample data
	var samples []map[string][]byte
	for _, tmpFile := range tmpFiles {
		data, err := os.ReadFile(tmpFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %v", tmpFile, err)
		}

		devices := splitDevices(data)
		samples = append(samples, devices)
	}

	// Find devices common to all samples
	deviceIDs := make(map[string]bool)
	for _, sample := range samples {
		for busID := range sample {
			deviceIDs[busID] = true
		}
	}

	// Analyze each device
	for busID := range deviceIDs {
		var deviceData [][]byte

		// Check if device exists in all samples
		validDevice := true
		for _, sample := range samples {
			if data, exists := sample[busID]; exists {
				deviceData = append(deviceData, data)
			} else {
				validDevice = false
				break
			}
		}

		if !validDevice || len(deviceData) < 3 {
			continue
		}

		// USB controllers, bridges, and legacy/non-endpoint devices are not part
		// of the external PCIe test set. Record them as whole-device ignores so
		// -scan produces the reusable ignore_list.txt requested by the operator.
		if info, ok := readPCIDeviceInfo(busID); ok {
			if endpoint, reason := isPCIeEndpoint(info); !endpoint {
				ignoreBits[busID] = DeviceIgnoreBits{
					BusID:        busID,
					IgnoreBytes:  make(map[int]bool),
					IgnoreDevice: true,
				}
				fmt.Printf("Device %s: %s, ignoring entire device\n", busID, reason)
				continue
			}
		}

		// Check if it's a USB Controller. Keep this explicit classification in
		// the record for readable diagnostics even though IgnoreDevice is the
		// field consumed by saveIgnoreBits.
		if len(deviceData[0]) >= 11 {
			classCode := deviceData[0][11] // Base Class
			subClass := deviceData[0][10]  // Sub Class
			if classCode == 0x0c && subClass == 0x03 {
				// USB Controller - ignore entire device
				ignoreBits[busID] = DeviceIgnoreBits{
					BusID:           busID,
					IgnoreBytes:     make(map[int]bool),
					IsUSBController: true,
					IgnoreDevice:    true,
				}
				fmt.Printf("Device %s: USB Controller detected, ignoring entire device\n", busID)
				continue
			}
		}

		ignoreBytes := make(map[int]bool)

		// Copy basic timer-related offsets
		for offset := range timerRelatedOffsets {
			ignoreBytes[offset] = true
		}

		// Improved volatile byte detection algorithm
		statusOffset := 6
		for i := 0; i < len(deviceData[0]) && i < 256; i++ {
			// Special handling for status register (offsets 0x06-0x07)
			if i == statusOffset || i == statusOffset+1 {
				continue
			}

			// Count changes and different values for this byte
			changeCount := 0
			valueSet := make(map[byte]bool)

			// Collect all values
			for j := 0; j < len(deviceData); j++ {
				if len(deviceData[j]) > i {
					valueSet[deviceData[j][i]] = true
				}
			}

			// Count changes between adjacent samples
			for j := 1; j < len(deviceData); j++ {
				if len(deviceData[j]) <= i || len(deviceData[j-1]) <= i {
					continue
				}

				if deviceData[j][i] != deviceData[j-1][i] {
					changeCount++
				}
			}

			// Use bit pattern analysis for more accurate timer detection
			isTimer, pattern := analyzeBitPatterns(deviceData, i)

			// If multiple different values or changes exceed threshold, or timer pattern detected
			if len(valueSet) > 2 || changeCount >= 2 || isTimer {
				ignoreBytes[i] = true
				reason := fmt.Sprintf("values: %d, changes: %d", len(valueSet), changeCount)
				if isTimer {
					reason += fmt.Sprintf(", timer_pattern: %s", pattern)
				}
				fmt.Printf("Device %s: Detected volatile byte at offset 0x%02x (%s)\n",
					busID, i, reason)
			}
		}

		if len(ignoreBytes) > 0 {
			ignoreBits[busID] = DeviceIgnoreBits{
				BusID:           busID,
				IgnoreBytes:     ignoreBytes,
				IsUSBController: false,
				IgnoreDevice:    false,
			}
		}
	}

	// Delete temporary files
	for _, tmpFile := range tmpFiles {
		os.Remove(tmpFile)
	}

	return ignoreBits, samples, nil
}

// initializeStatistics initializes the statistics tracking variables
func initializeStatistics() {
	if testStartTime.IsZero() {
		testStartTime = time.Now()
	}
	if deviceChangeStats == nil {
		deviceChangeStats = make(map[string]int)
	}
	if configChangeStats == nil {
		configChangeStats = make(map[string]map[string]int)
	}
}

// analyzeBitPatterns analyzes bit-level change patterns to detect timer bits
func analyzeBitPatterns(samples [][]byte, offset int) (bool, string) {
	if len(samples) < 3 {
		return false, ""
	}

	var values []byte
	for _, sample := range samples {
		if len(sample) > offset {
			values = append(values, sample[offset])
		}
	}

	if len(values) < 3 {
		return false, ""
	}

	// Check for increasing pattern (typical timer behavior)
	increasing := true
	decreasing := true
	for i := 1; i < len(values); i++ {
		if values[i] <= values[i-1] {
			increasing = false
		}
		if values[i] >= values[i-1] {
			decreasing = false
		}
	}

	if increasing {
		return true, "monotonic_increasing"
	}
	if decreasing {
		return true, "monotonic_decreasing"
	}

	// Check bit flip patterns (some timers have bit flipping)
	bitFlips := make([]int, 8)
	for i := 1; i < len(values); i++ {
		xor := values[i] ^ values[i-1]
		for bit := 0; bit < 8; bit++ {
			if (xor>>bit)&1 == 1 {
				bitFlips[bit]++
			}
		}
	}

	// If a bit flips frequently, it might be a timer bit
	for bit, flips := range bitFlips {
		if flips >= len(values)/2 {
			return true, fmt.Sprintf("bit_%d_flipping", bit)
		}
	}

	// Check for periodic changes
	uniqueValues := make(map[byte]bool)
	for _, v := range values {
		uniqueValues[v] = true
	}

	// If multiple different values and frequent changes, might be timer
	if len(uniqueValues) >= 3 {
		return true, "multiple_values"
	}

	return false, ""
}

// savePCIConfig saves PCI configuration space to file
func savePCIConfig(outputFile string) error {
	pciPath := "/sys/bus/pci/devices/"
	files, err := os.ReadDir(pciPath)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer
	for _, file := range files {
		busID := file.Name()
		// Skip bridges / legacy PCI when an endpoint filter is active so the
		// initial snapshot (and every cycle's stable snapshot) contains only
		// the BDFs the rest of the pipeline cares about. When the filter is
		// nil this is a no-op.
		if !endpointFilterAllows(busID) {
			continue
		}
		configPath := filepath.Join(pciPath, busID, "config")
		configData, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", configPath, err)
			continue
		}

		// Only read first 256 bytes
		if len(configData) > 256 {
			configData = configData[:256]
		}

		// XXD-like output format. The BDF header is written in short form so
		// downstream consumers (splitDevices, the comparison maps, the ignore
		// list) all share the same key form regardless of which path produced
		// the BDF.
		buffer.WriteString(fmt.Sprintf("# %s\n", normalizeBDF(busID)))
		for i := 0; i < len(configData); i += 16 {
			// Write offset
			buffer.WriteString(fmt.Sprintf("%04x: ", i))
			// Write hex representation
			for j := 0; j < 16; j++ {
				if i+j < len(configData) {
					buffer.WriteString(fmt.Sprintf("%02x ", configData[i+j]))
				} else {
					buffer.WriteString("   ")
				}
				// Add a space between 8-byte groups
				if j == 7 {
					buffer.WriteString(" ")
				}
			}
			// Write ASCII representation
			buffer.WriteString(" |")
			for j := 0; j < 16; j++ {
				if i+j < len(configData) {
					c := configData[i+j]
					if c >= 32 && c <= 126 {
						buffer.WriteString(string(c))
					} else {
						buffer.WriteString(".")
					}
				}
			}
			buffer.WriteString("|\n")
		}
		buffer.WriteString("\n")
	}
	return writeFileNoFollow(outputFile, buffer.Bytes(), 0644)
}

// splitDevices splits device data from XXD-like format
func splitDevices(data []byte) map[string][]byte {
	devices := make(map[string][]byte)
	deviceSections := bytes.Split(data, []byte("\n# "))
	for i, section := range deviceSections {
		if i == 0 && !bytes.Contains(section, []byte(": ")) {
			continue // Skip potential header
		}
		lines := strings.Split(string(section), "\n")
		if len(lines) < 2 {
			continue
		}
		busID := strings.TrimSpace(lines[0])
		if busID == "" {
			continue
		}
		// Reconstruct hex data
		var hexBuilder strings.Builder
		for _, line := range lines[1:] {
			line = strings.TrimSpace(line)
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			// Split line and remove anything after '|'
			lineParts := strings.Split(line, "|")
			hexPart := lineParts[0]
			// Remove offset
			parts := strings.SplitN(hexPart, ": ", 2)
			if len(parts) < 2 {
				continue
			}
			hexPart = strings.TrimSpace(parts[1])
			// Remove spaces and convert to hex string
			hexPart = strings.ReplaceAll(hexPart, " ", "")
			hexBuilder.WriteString(hexPart)
		}
		configData, err := hex.DecodeString(hexBuilder.String())
		if err == nil {
			// Normalize so downstream lookups against the lspci-text path's
			// short BDFs hit consistently. Older initial.bin files written
			// before the format unification used long BDFs; normalizing on
			// read keeps them compatible without a migration step.
			devices[normalizeBDF(busID)] = configData
		}
	}
	return devices
}

// saveIgnoreBits saves ignore bits to file
func saveIgnoreBits(filePath string, ignoreBits map[string]DeviceIgnoreBits) error {
	var buffer bytes.Buffer

	buffer.WriteString("# Auto-generated list of volatile PCI configuration bytes to ignore\n")
	buffer.WriteString("# Generated at: " + logTimestamp() + "\n")
	buffer.WriteString("# Format: BusID [0xXX 0xYY ...] (offsets are volatile, no offsets means whole-device ignore)\n")
	buffer.WriteString("# BusID is written in short form (bus:device.function) to match\n")
	buffer.WriteString("# parseDeviceFile()'s lspci-text view; long form is still accepted on read.\n")
	buffer.WriteString("# These bytes are identified as timer-related or frequently changing\n")

	// Convert map to sorted list by BusID, normalised to short form so the
	// file is identical whether entries originated from sysfs (long form) or
	// from a prior round of normalisation.
	normalised := make(map[string]DeviceIgnoreBits, len(ignoreBits))
	for busID, dev := range ignoreBits {
		normalised[normalizeBDF(busID)] = dev
	}
	var busIDs []string
	for busID := range normalised {
		busIDs = append(busIDs, busID)
	}
	sort.Strings(busIDs)

	for _, busID := range busIDs {
		device := normalised[busID]

		// Whole-device ignores include USB controllers, bridges, and other
		// non-endpoint devices.
		if device.IgnoreDevice || device.IsUSBController {
			buffer.WriteString(busID + "\n")
		} else if len(device.IgnoreBytes) > 0 {
			// Has timer offsets - only ignore specific offsets
			buffer.WriteString(busID)

			// Convert ignore bytes to sorted list
			var offsets []int
			for offset := range device.IgnoreBytes {
				offsets = append(offsets, offset)
			}
			sort.Ints(offsets)

			for _, offset := range offsets {
				buffer.WriteString(fmt.Sprintf(" 0x%02x", offset))
			}
			buffer.WriteString("\n")
		}
	}

	return writeFileNoFollow(filePath, buffer.Bytes(), 0644)
}

// compareDeviceConfigs compares the initial PCI config snapshot against the
// current state. Multiple live samples are collected via collectStableConfig
// to filter out timer noise, so only genuine capability changes are logged.
func compareDeviceConfigs(initialFile, reportFile string) error {
	initialData, err := os.ReadFile(initialFile)
	if err != nil {
		return err
	}

	// Read ignore devices and offsets
	ignoreDevices, ignoreOffsets, err := readIgnoreDevicesAndOffsets(IGNORE_LIST_FILE)
	if err != nil {
		return fmt.Errorf("failed to read ignore devices: %v", err)
	}

	// Collect stable-value snapshot (3 samples, 200ms apart) instead of a single
	// shot. Bytes that keep changing during the sampling window are marked as
	// timer noise and skipped during comparison.
	stableConfigs, err := collectStableConfig(3, 200)
	if err != nil {
		return fmt.Errorf("failed to collect stable config: %v", err)
	}

	logFile, err := openSecureAppend(reportFile, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	initialDevices := splitDevices(initialData)

	timestamp := logTimestamp()
	fmt.Printf("%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))
	fmt.Fprintf(logFile, "%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))

	// Track if any config changes are found in this cycle
	configChangesFoundInThisCycle := false

	// Check for disappeared devices
	for busID, configData := range initialDevices {
		if _, exists := stableConfigs[busID]; !exists {
			if ignoreDevices[busID] {
				continue
			}
			initialInfo := parsePCIConfig(configData)
			initialInfo.BusID = busID
			logDeviceChange(logFile, &initialInfo, nil, "DEVICE DISAPPEARED")
		}
	}

	// Check for new devices
	for busID, stableCfg := range stableConfigs {
		if _, exists := initialDevices[busID]; !exists {
			if ignoreDevices[busID] {
				continue
			}
			currentInfo := parsePCIConfig(stableCfg.Data)
			currentInfo.BusID = busID
			logDeviceChange(logFile, nil, &currentInfo, "NEW DEVICE")
		}
	}

	// Compare configuration changes
	for busID, initialConfigData := range initialDevices {
		stableCfg, exists := stableConfigs[busID]
		if !exists {
			continue
		}
		if ignoreDevices[busID] {
			continue
		}

		initialInfo := parsePCIConfig(initialConfigData)
		initialInfo.BusID = busID
		currentInfo := parsePCIConfig(stableCfg.Data)
		currentInfo.BusID = busID

		// Merge static offset ignore list from ignore_list.txt
		combinedIgnore := map[int]bool{}
		if offsets, ok := ignoreOffsets[busID]; ok {
			for offset := range offsets {
				combinedIgnore[offset] = true
			}
		}

		// Pass stableCfg.UnstableBytes for live timer filtering
		hasChanges := compareAndLogDeviceChanges(logFile, initialInfo, currentInfo, combinedIgnore, stableCfg.UnstableBytes)
		if hasChanges {
			configChangesFoundInThisCycle = true
		}
	}

	// Increment cycle counter only once per cycle if any config changes were
	// found. These are recorded as noise (not noteworthy): the vast majority
	// are vendor registers a controller resets to the same value on every
	// boot. The final summary partitions them into reboot-fixed vs. truly
	// volatile; only the latter warrants attention.
	if configChangesFoundInThisCycle {
		cyclesWithConfigChanges++
		recordCycleNoise("PCI config-space byte changes detected")
	}

	return nil
}

// parsePCIConfig parses binary configuration data into structured PCI device information
func parsePCIConfig(rawConfig []byte) PCIDeviceInfo {
	info := PCIDeviceInfo{
		ConfigData:   rawConfig,
		Capabilities: make(map[uint8]PCICapability),
	}
	if len(rawConfig) < 64 {
		return info // Return empty info as data is insufficient
	}
	// Parse header
	info.VendorID = binary.LittleEndian.Uint16(rawConfig[0:2])
	info.DeviceID = binary.LittleEndian.Uint16(rawConfig[2:4])
	info.Command = binary.LittleEndian.Uint16(rawConfig[4:6])
	info.Status = binary.LittleEndian.Uint16(rawConfig[6:8])
	info.Class[0] = rawConfig[9]  // Programming Interface
	info.Class[1] = rawConfig[10] // Sub Class
	info.Class[2] = rawConfig[11] // Base Class

	headerType := rawConfig[14] & 0x7F
	// Read Subsystem IDs (only applicable for Type 0 header)
	if headerType == 0 && len(rawConfig) >= 48 {
		info.SubsystemVendorID = binary.LittleEndian.Uint16(rawConfig[44:46])
		info.SubsystemID = binary.LittleEndian.Uint16(rawConfig[46:48])
	}
	if len(rawConfig) >= 61 {
		info.InterruptLine = rawConfig[60]
		info.InterruptPin = rawConfig[61]
	}

	return info
}

// formatDeviceInfo formats device information into human-readable string
func formatDeviceInfo(info PCIDeviceInfo) string {
	var sb strings.Builder
	// Format basic information
	sb.WriteString(fmt.Sprintf(" %s (%04x:%04x", info.BusID, info.VendorID, info.DeviceID))
	if info.SubsystemVendorID != 0 || info.SubsystemID != 0 {
		sb.WriteString(fmt.Sprintf(" Subsystem %04x:%04x)", info.SubsystemVendorID, info.SubsystemID))
	} else {
		sb.WriteString(")")
	}
	return sb.String()
}

// compareAndLogDeviceChanges compares two devices' PCI config data and logs differences.
//
// Filter priority (highest to lowest):
//  1. unstableBytes: bytes flagged as timer noise by live stability analysis (collectStableConfig)
//  2. timerPatterns: static offset ignore list from ignore_list.txt
//  3. timerRelatedOffsets: hardcoded known timer registers
//  4. volatileStatusBits: volatile status bits masked in the Status register
//
// Returns true if non-timer changes were found, false otherwise.
func compareAndLogDeviceChanges(logFile *os.File, initialInfo, currentInfo PCIDeviceInfo,
	timerPatterns map[int]bool, unstableBytes map[int]bool) bool {
	var changes []string

	for i := 0; i < len(initialInfo.ConfigData) && i < len(currentInfo.ConfigData); i++ {
		// 1. Live stability filter: byte was unstable during sampling → timer noise
		if unstableBytes[i] {
			continue
		}

		// 2. Static ignore list and known timer registers
		if timerPatterns[i] || timerRelatedOffsets[i] {
			continue
		}

		// 3. Special handling for status register (offsets 0x06-0x07)
		if i == 6 || i == 7 {
			statusOffset := 6
			initialStatus := binary.LittleEndian.Uint16(initialInfo.ConfigData[statusOffset : statusOffset+2])
			currentStatus := binary.LittleEndian.Uint16(currentInfo.ConfigData[statusOffset : statusOffset+2])

			// Mask volatile status bits
			initialStatus &= ^volatileStatusBits
			currentStatus &= ^volatileStatusBits

			if (i == 6 && (initialStatus&0xFF) == (currentStatus&0xFF)) ||
				(i == 7 && ((initialStatus>>8)&0xFF) == ((currentStatus>>8)&0xFF)) {
				continue
			}
		}

		// Compare non-timer related bytes
		if initialInfo.ConfigData[i] != currentInfo.ConfigData[i] {
			changes = append(changes, fmt.Sprintf("Value at offset 0x%02x changed from 0x%02x to 0x%02x",
				i, initialInfo.ConfigData[i], currentInfo.ConfigData[i]))
		}
	}

	if len(changes) > 0 {
		timestamp := logTimestamp()
		fmt.Fprintf(logFile, "%s %sDevice: %s (config space change detected)\n",
			timestamp, cycleTag(), formatDeviceInfo(currentInfo))

		// Track config space changes for statistics (per device, not per cycle)
		if configChangeStats[currentInfo.BusID] == nil {
			configChangeStats[currentInfo.BusID] = make(map[string]int)
		}

		for _, change := range changes {
			fmt.Fprintln(logFile, change)
			// Extract offset from change string for statistics
			if strings.Contains(change, "offset 0x") {
				parts := strings.Split(change, " ")
				for i, part := range parts {
					if part == "offset" && i+1 < len(parts) {
						offset := parts[i+1]
						configChangeStats[currentInfo.BusID][offset]++
						break
					}
				}
			}
		}
		fmt.Fprintln(logFile, "---")
		return true
	}
	return false
}

// logDeviceChange logs device appearance/disappearance
func logDeviceChange(logFile *os.File, initialInfo, currentInfo *PCIDeviceInfo, changeType string) {
	var info PCIDeviceInfo
	if initialInfo != nil {
		info = *initialInfo
	} else if currentInfo != nil {
		info = *currentInfo
	}

	timestamp := logTimestamp()
	fmt.Fprintf(logFile, "%s %sDevice: %s (%s)\n", timestamp, cycleTag(), formatDeviceInfo(info), changeType)
	fmt.Fprintln(logFile, "---")
}

// readIgnoreDevicesAndOffsets reads ignore devices and offsets list
func readIgnoreDevicesAndOffsets(filePath string) (map[string]bool, map[string]map[int]bool, error) {
	ignoreDevices := make(map[string]bool)
	ignoreOffsets := make(map[string]map[int]bool)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ignoreDevices, ignoreOffsets, nil
		}
		return nil, nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		// Validate BDF format and normalise to short form so map lookups
		// against splitDevices() output (also normalised) succeed regardless of
		// whether the file on disk uses 0000:bb:dd.f or bb:dd.f.
		bdf := normalizeBDF(parts[0])
		if !shortBDFRegex.MatchString(bdf) && !bdfRegex.MatchString(bdf) {
			continue
		}

		if len(parts) == 1 {
			// Only BDF, ignore entire device (USB Controller)
			ignoreDevices[bdf] = true
		} else {
			// Has offsets, only ignore specific offsets (timers)
			if ignoreOffsets[bdf] == nil {
				ignoreOffsets[bdf] = make(map[int]bool)
			}
			for i := 1; i < len(parts); i++ {
				offsetStr := strings.TrimPrefix(parts[i], "0x")
				offset, err := strconv.ParseInt(offsetStr, 16, 64)
				if err == nil {
					ignoreOffsets[bdf][int(offset)] = true
				}
			}
		}
	}

	return ignoreDevices, ignoreOffsets, nil
}

// collectStableConfig samples every PCI device's config space sampleCount times
// with intervalMs between samples, then per-byte majority-votes to produce a
// stable snapshot. Bytes that fail to reach the stability threshold are flagged
// as timer noise in UnstableBytes so that compareAndLogDeviceChanges can skip
// them, ensuring only genuine capability changes are logged.
func collectStableConfig(sampleCount int, intervalMs int) (map[string]StableConfig, error) {
	if sampleCount < 2 {
		sampleCount = 2
	}

	// Randomised private directory under /tmp so the predictable filenames
	// inside cannot be pre-seeded by a local attacker.
	sampleDir, err := os.MkdirTemp("", "lpot-stable-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sample directory: %v", err)
	}
	defer os.RemoveAll(sampleDir)

	tmpFiles := make([]string, sampleCount)
	for i := range tmpFiles {
		tmpFiles[i] = filepath.Join(sampleDir, fmt.Sprintf("sample-%d.bin", i))
	}

	fmt.Printf("Collecting %d stability samples (%dms apart)...\n", sampleCount, intervalMs)
	for i, f := range tmpFiles {
		if err := savePCIConfig(f); err != nil {
			return nil, fmt.Errorf("failed to collect sample %d: %v", i+1, err)
		}
		if i < sampleCount-1 {
			time.Sleep(time.Duration(intervalMs) * time.Millisecond)
		}
	}

	samples := make([]map[string][]byte, sampleCount)
	for i, f := range tmpFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to read sample %d: %v", i+1, err)
		}
		samples[i] = splitDevices(data)
	}

	return analyzeStableConfig(samples), nil
}

// analyzeStableConfig is the pure (I/O-free) core of collectStableConfig.
// Given per-sample device maps, it uses majority-voting to derive a stable
// snapshot for every device that appears in at least two samples, and flags
// bytes that fail the stability threshold as timer noise.
func analyzeStableConfig(samples []map[string][]byte) map[string]StableConfig {
	result := make(map[string]StableConfig)
	if len(samples) < 2 {
		return result
	}

	deviceIDs := make(map[string]bool)
	for _, s := range samples {
		for id := range s {
			deviceIDs[id] = true
		}
	}

	// Stability threshold: at least ceil(2/3 * sampleCount) samples must agree
	stableThreshold := (len(samples)*2 + 2) / 3

	for busID := range deviceIDs {
		var deviceSamples [][]byte
		for _, s := range samples {
			if d, ok := s[busID]; ok {
				deviceSamples = append(deviceSamples, d)
			}
		}
		if len(deviceSamples) < 2 {
			continue
		}

		maxLen := 0
		for _, d := range deviceSamples {
			if len(d) > maxLen {
				maxLen = len(d)
			}
		}

		stableData := make([]byte, maxLen)
		unstable := make(map[int]bool)

		for i := 0; i < maxLen; i++ {
			valueCounts := make(map[byte]int)
			for _, d := range deviceSamples {
				if len(d) > i {
					valueCounts[d[i]]++
				}
			}

			var majorityVal byte
			majorityCount := 0
			for val, count := range valueCounts {
				if count > majorityCount {
					majorityCount = count
					majorityVal = val
				}
			}

			if majorityCount >= stableThreshold {
				stableData[i] = majorityVal
			} else {
				// Unstable: timer noise. Keep an available sample as a placeholder;
				// device config files can legitimately have different lengths.
				unstable[i] = true
				for _, sample := range deviceSamples {
					if len(sample) > i {
						stableData[i] = sample[i]
						break
					}
				}
			}
		}

		result[busID] = StableConfig{
			Data:          stableData,
			UnstableBytes: unstable,
		}
	}

	return result
}

// loadIgnoreList reads the ignore list file and returns a set of BusIDs to ignore
func loadIgnoreList(filePath string) (map[string]bool, error) {
	ignoreSet := make(map[string]bool)

	file, err := os.Open(filePath)
	if err != nil {
		// If file doesn't exist, return empty set (no devices to ignore)
		if os.IsNotExist(err) {
			return ignoreSet, nil
		}
		return nil, fmt.Errorf("failed to open ignore list file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		// Skip empty lines and comments
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract BusID (first field before any space) and normalise to short
		// form so the lookup in parseDeviceFile() (which uses lspci-text's
		// short BDF) succeeds even when the file on disk uses long form.
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ignoreSet[normalizeBDF(fields[0])] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ignore list file %s: %w", filePath, err)
	}

	return ignoreSet, nil
}

// compareDeviceFiles compares two device files using lspci logic
func compareDeviceFiles(filePath1, filePath2 string, ignoreSet map[string]bool, stopServiceEnabled bool) ComparisonResult {
	device1, err := parseDeviceFile(filePath1, ignoreSet)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	device2, err := parseDeviceFile(filePath2, ignoreSet)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	if device1.DeviceID != device2.DeviceID {
		return ComparisonResult{
			Error: fmt.Errorf("device IDs do not match: %s vs %s", device1.DeviceID, device2.DeviceID),
		}
	}

	return compareDevices(device1, device2, stopServiceEnabled)
}

// parseDeviceFile reads and parses a device file containing lspci output
func parseDeviceFile(filePath string, ignoreSet map[string]bool) (Device, error) {
	var currentDevice Device
	currentDevice.Capabilities.DevLnkFields = make(map[string]string)

	file, err := os.Open(filePath)
	if err != nil {
		return currentDevice, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inCapabilities := false
	var currentFieldName string
	var currentFieldValue strings.Builder
	isDevLnk := false

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		// Extract device ID from the first line
		if currentDevice.DeviceID == "" && len(line) >= 7 {
			// Extract full BusID (format: 0000:xx:yy.z)
			fields := strings.Fields(line)
			if len(fields) > 0 {
				currentDevice.DeviceID = fields[0]
			} else {
				currentDevice.DeviceID = line[:7]
			}
			remainingDesc := ""
			if len(fields) > 0 {
				remainingDesc = strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
			}

			// Check if this device should be ignored
			if ignoreSet[normalizeBDF(currentDevice.DeviceID)] {
				return currentDevice, fmt.Errorf("device %s is in ignore list", currentDevice.DeviceID)
			}

			// Skip virtual USB devices
			if strings.Contains(strings.ToLower(remainingDesc), "virtual usb") {
				break
			}
			continue
		}

		// Enter capabilities section
		if strings.HasPrefix(line, "Capabilities") && !inCapabilities && currentDevice.DeviceID != "" {
			inCapabilities = true
			continue
		}

		if inCapabilities {
			// Process Dev/Lnk fields
			if (strings.HasPrefix(line, "Dev") || strings.HasPrefix(line, "Lnk")) && !strings.HasPrefix(line, "Device") {
				isDevLnk = true

				// Save previous field if exists
				if currentFieldName != "" && currentFieldValue.Len() > 0 {
					currentDevice.Capabilities.DevLnkFields[currentFieldName] = strings.TrimSpace(currentFieldValue.String())
					currentFieldValue.Reset()
				}

				// Parse new field
				if colonIndex := strings.Index(line, ":"); colonIndex != -1 {
					currentFieldName = strings.TrimSpace(line[:colonIndex])
					currentFieldValue.WriteString(strings.TrimSpace(line[colonIndex+1:]))
				}
				continue
			}

			// Handle continuation lines (indented with tab)
			if strings.HasPrefix(rawLine, "\t") && currentFieldName != "" {
				currentFieldValue.WriteString(" " + strings.TrimSpace(rawLine))
				continue
			}

			// Handle empty lines - finalize current field
			if len(line) == 0 && currentFieldName != "" {
				if currentFieldValue.Len() > 0 {
					currentDevice.Capabilities.DevLnkFields[currentFieldName] = strings.TrimSpace(currentFieldValue.String())
					currentFieldValue.Reset()
				}
				currentFieldName = ""
				continue
			}

			// Break if another Capabilities section is found after Dev/Lnk fields
			if strings.HasPrefix(line, "Capabilities") && isDevLnk {
				break
			}

			// Append to current field value if we have an active field
			if currentFieldName != "" {
				currentFieldValue.WriteString(" " + line)
			}
		}
	}

	// Save the last field if exists
	if currentFieldName != "" && currentFieldValue.Len() > 0 {
		currentDevice.Capabilities.DevLnkFields[currentFieldName] = strings.TrimSpace(currentFieldValue.String())
	}

	if err := scanner.Err(); err != nil {
		return currentDevice, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return currentDevice, nil
}

// compareDevices compares two devices and returns the comparison result
func compareDevices(device1, device2 Device, stopServiceEnabled bool) ComparisonResult {
	result := ComparisonResult{HasDifferences: false}

	// Record the scanned device ID
	result.ScannedDeviceIDs = append(result.ScannedDeviceIDs, device1.DeviceID)

	// Open log file
	logFile, err := openSecureAppend(LPOTSCAN_LOG, 0644)
	if err != nil {
		result.Error = fmt.Errorf("failed to open log file: %w", err)
		return result
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)

	// Compare device capabilities
	for key, value1 := range device1.Capabilities.DevLnkFields {
		value2, exists := device2.Capabilities.DevLnkFields[key]
		if !exists || value1 == value2 {
			continue
		}

		result.HasDifferences = true
		logEntry := fmt.Sprintf("%s %s| %s | %s\nBefore: %s\nAfter: %s\n",
			logTimestamp(), cycleTag(), device1.DeviceID, key, value1, value2)

		// Add detailed differences
		if differences := findDifferences(value1, value2); differences != "" {
			logEntry += fmt.Sprintf("\tDifferences: %s\n", differences)
		}

		// Track statistics
		deviceChangeStats[device1.DeviceID]++

		// Store log entry
		result.LogEntries = append(result.LogEntries, logEntry)
		logger.Println(logEntry)
		fmt.Print(logEntry)

		// Stop service if enabled and no previous error
		if stopServiceEnabled && result.Error == nil {
			if err := stopService("lpot_reboot"); err != nil {
				result.Error = fmt.Errorf("failed to stop service: %w", err)
				logger.Printf("Service stop error: %v\n", result.Error)
			}
		}
	}

	return result
}

// findDifferences finds differences between two strings with context
func findDifferences(value1, value2 string) string {
	var diff []string

	// Split both values into words for comparison
	words1 := strings.Fields(value1)
	words2 := strings.Fields(value2)

	// Compare words and find differences with context
	for i := 0; i < len(words1) || i < len(words2); i++ {
		if i < len(words1) && i < len(words2) {
			if words1[i] != words2[i] {
				// Try to find the field name by looking at previous words
				fieldName := ""
				if i > 0 {
					// Look for common PCI field patterns
					prevWord := words1[i-1]
					if strings.Contains(prevWord, "MaxPayload") || strings.Contains(prevWord, "MaxReadReq") ||
						strings.Contains(prevWord, "Speed") || strings.Contains(prevWord, "Width") {
						fieldName = prevWord
					} else if i > 1 {
						// Check two words back for compound field names
						prevPrevWord := words1[i-2]
						if prevPrevWord == "MaxPayload" || prevPrevWord == "MaxReadReq" {
							fieldName = prevPrevWord
						}
					}
				}

				if fieldName != "" {
					diff = append(diff, fmt.Sprintf("%s | '%s' to '%s'", fieldName, words1[i], words2[i]))
				} else {
					diff = append(diff, fmt.Sprintf("'%s' to '%s'", words1[i], words2[i]))
				}
			}
		} else if i < len(words1) {
			diff = append(diff, fmt.Sprintf("'%s' (only in before)", words1[i]))
		} else if i < len(words2) {
			diff = append(diff, fmt.Sprintf("'%s' (only in after)", words2[i]))
		}
	}

	return strings.Join(diff, ", ")
}

// stopService stops a systemd service
func stopService(serviceName string) error {
	output, err := runExternal(systemctlTimeout, systemctlPath, "stop", serviceName)
	if err != nil {
		return fmt.Errorf("failed to stop service %s: %w, output: %s", serviceName, err, string(output))
	}
	fmt.Printf("Service %s stopped successfully\n", serviceName)
	return nil
}

// filterLpotscanErrors filters lpotscan errors and writes to log.
// bufio.Scanner.Text() strips the terminating newline, so we must re-append it
// with Fprintln; writing "%s" would collapse every filtered line into a single
// unreadable run.
func filterLpotscanErrors(errorLogPath string, logFp *os.File) {
	errorLog, err := os.Open(errorLogPath)
	if err != nil {
		fmt.Printf("Failed to open error log: %v\n", err)
		return
	}
	defer errorLog.Close()

	scanner := bufio.NewScanner(errorLog)
	writeLine := false

	for scanner.Scan() {
		line := scanner.Text()

		// Avoid "No devices changed" meaningless messages
		if strings.Contains(line, "No devices changed on lspci lists.") {
			continue
		}

		// Lines with '|' symbol represent device change information
		if strings.Contains(line, "|") {
			fmt.Fprintln(logFp, line)
			writeLine = true
		} else if writeLine {
			// If we previously output a BDF info line, allow continuing to output change content
			if strings.Contains(line, "Before") || strings.Contains(line, "After") || strings.Contains(line, "Differences") {
				fmt.Fprintln(logFp, line)
			}
		}
	}
}

// writeAffectedCyclesSection emits a deduplicated per-cycle breakdown of every
// recorded change, sorted by cycle number. If no changes were recorded the
// section is reduced to a single line noting perfect stability, so summaries
// remain compact for clean runs.
func writeAffectedCyclesSection(logFile *os.File) {
	changedCyclesMu.Lock()
	snapshot := make([]cycleChange, len(changedCycles))
	copy(snapshot, changedCycles)
	changedCyclesMu.Unlock()

	fmt.Fprintf(logFile, "\nAffected Cycles:\n")
	if len(snapshot) == 0 {
		fmt.Fprintf(logFile, "  (none — every cycle was clean)\n")
		return
	}

	// Bucket reasons per cycle, deduplicating identical reason strings while
	// preserving first-seen order so the narrative reflects what happened.
	perCycle := make(map[int64][]string)
	cycleTime := make(map[int64]time.Time)
	order := []int64{}
	for _, c := range snapshot {
		if _, seen := perCycle[c.Cycle]; !seen {
			order = append(order, c.Cycle)
			cycleTime[c.Cycle] = c.Time
		}
		dup := false
		for _, r := range perCycle[c.Cycle] {
			if r == c.Reason {
				dup = true
				break
			}
		}
		if !dup {
			perCycle[c.Cycle] = append(perCycle[c.Cycle], c.Reason)
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	for _, cycle := range order {
		fmt.Fprintf(logFile, "  Cycle %d (%s): %s\n",
			cycle,
			cycleTime[cycle].Format(logTimeFormat),
			strings.Join(perCycle[cycle], "; "))
	}
	fmt.Fprintf(logFile, "  Total affected cycles: %d\n", len(order))
}

// writeFilteredDevicesSection prints the BDFs that the endpoint filter excluded
// from the run, with vendor/device IDs and the reason. It is intentionally
// terse (one device per line) so even a 200-device system fits on one screen.
// When the filter was inactive (e.g. legacy callers) or every device was kept,
// the section is suppressed entirely so it doesn't add noise to clean runs.
func writeFilteredDevicesSection(logFile *os.File) {
	if len(skippedDevicesGlobal) == 0 {
		return
	}
	fmt.Fprintf(logFile, "\nFiltered Devices (excluded by endpoint classifier / pcie_filter.txt):\n")
	// classifyDevices already sorts by BDF, but copy + re-sort defensively
	// so the section is deterministic even if a caller mutated the slice.
	snap := make([]deviceClassification, len(skippedDevicesGlobal))
	copy(snap, skippedDevicesGlobal)
	sort.Slice(snap, func(i, j int) bool { return snap[i].BDF < snap[j].BDF })
	for _, d := range snap {
		ven, dev := "----", "----"
		if d.InfoOK {
			ven = fmt.Sprintf("%04x", d.Info.Vendor)
			dev = fmt.Sprintf("%04x", d.Info.Device)
		}
		fmt.Fprintf(logFile, "  %-12s %s:%s  %s\n", d.BDF, ven, dev, d.SkipReason)
	}
	fmt.Fprintf(logFile, "  Total filtered: %d device(s)\n", len(snap))
}

// generateFinalSummary generates the final test summary and appends to reboot.log
func generateFinalSummary() {
	logFile, err := openSecureAppend(REBOOT_LOG, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file for summary: %v\n", err)
		return
	}
	defer logFile.Close()

	// Close any open clean-streak aggregate so the summary sits under a
	// properly-terminated cycle narrative.
	flushCleanStreak(logFile)

	// Parse the reboot.log to get accurate statistics
	actualStartTime, actualTotalCycles, actualCyclesWithChanges, actualTopologyChanges, actualLspciChanges := parseRebootLogForStats()

	endTime := time.Now()
	duration := endTime.Sub(actualStartTime)

	// Calculate most affected device and most changed field
	maxDeviceChanges := 0
	maxFieldChanges := 0
	fieldChangeCount := make(map[string]int)

	for device, count := range deviceChangeStats {
		if count > maxDeviceChanges {
			maxDeviceChanges = count
			mostAffectedDevice = device
		}
	}

	// Count field changes from lpotscan log
	if data, err := os.ReadFile(LPOTSCAN_LOG); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.Contains(line, " | ") {
				parts := strings.Split(line, " | ")
				if len(parts) >= 3 {
					field := strings.TrimSpace(parts[2])
					fieldChangeCount[field]++
					if fieldChangeCount[field] > maxFieldChanges {
						maxFieldChanges = fieldChangeCount[field]
						mostChangedField = field
					}
				}
			}
		}
	}

	// Write test session summary
	fmt.Fprintf(logFile, "\n========== Test Session Summary ==========\n")
	fmt.Fprintf(logFile, "Test Duration: %.1f hours (%s to %s)\n",
		duration.Hours(), actualStartTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(logFile, "Total Reboot Cycles: %d\n", actualTotalCycles)

	// Calculate failed reboots: any cycle with device changes is considered failed
	failedReboots := actualCyclesWithChanges
	successfulReboots := actualTotalCycles - failedReboots

	fmt.Fprintf(logFile, "Successful Reboots: %d\n", successfulReboots)
	fmt.Fprintf(logFile, "Failed Reboots: %d\n\n", failedReboots)

	fmt.Fprintf(logFile, "Device Stability Analysis:\n")
	var changePercentage float64
	if actualTotalCycles > 0 {
		changePercentage = float64(actualCyclesWithChanges) / float64(actualTotalCycles) * 100
	}
	fmt.Fprintf(logFile, "  Cycles with device changes: %d (%.1f%%)\n",
		actualCyclesWithChanges, changePercentage)
	var noChangePercentage float64
	if actualTotalCycles > 0 {
		noChangePercentage = float64(actualTotalCycles-actualCyclesWithChanges) / float64(actualTotalCycles) * 100
	}
	fmt.Fprintf(logFile, "  Cycles with no changes: %d (%.1f%%)\n",
		actualTotalCycles-actualCyclesWithChanges, noChangePercentage)
	fmt.Fprintf(logFile, "  \n")
	fmt.Fprintf(logFile, "  Device topology changes: %d cycles\n", actualTopologyChanges)
	fmt.Fprintf(logFile, "  lspci capability changes: %d cycles\n", actualLspciChanges)

	if mostAffectedDevice != "" {
		fmt.Fprintf(logFile, "    - Most affected device: %s (%d changes)\n", mostAffectedDevice, maxDeviceChanges)
	}
	if mostChangedField != "" {
		fmt.Fprintf(logFile, "    - Most changed field: %s (%d occurrences)\n", mostChangedField, maxFieldChanges)
	}

	// Per-cycle change list. For each cycle that triggered at least one
	// change, emit its number, timestamp, and a deduplicated set of reasons.
	// This gives users a fast way to locate the exact cycles they need to
	// investigate without searching the full reboot.log.
	writeAffectedCyclesSection(logFile)

	// Filtered devices section: lists every BDF the endpoint filter dropped
	// (bridges, legacy PCI, pcie_filter.txt excludes) so the user knows
	// exactly what the test did NOT cover and why.
	writeFilteredDevicesSection(logFile)

	// Generate PCI Config Space summary. Pass the parsed cycle total so per-row
	// occurrence ratios are correct even on the timestamp-expired exit path,
	// where the global totalRebootCycles was never set. noteworthyChanges
	// reports whether any genuinely volatile (irregular) register was seen.
	noteworthyConfigChanges := generateConfigSpaceSummary(logFile, actualTotalCycles)

	// Final result. A test is "perfect" only when there were no topology /
	// lspci changes AND no noteworthy (irregular) config-space changes. Benign
	// reboot-fixed register noise — vendor registers reset to the same value on
	// every boot — does NOT downgrade the verdict, since it indicates stable,
	// repeatable firmware behaviour rather than instability.
	switch {
	case actualCyclesWithChanges == 0 && !noteworthyConfigChanges:
		fmt.Fprintf(logFile, "\nTest Result: COMPLETED SUCCESSFULLY - PERFECT STABILITY\n")
		if cyclesWithConfigChanges > 0 {
			fmt.Fprintf(logFile, "No noteworthy config-space changes across %d reboot cycles.\n", actualTotalCycles)
			fmt.Fprintf(logFile, "Vendor-specific register changes are consistent across reboots and treated as benign firmware re-initialization.\n")
		} else {
			fmt.Fprintf(logFile, "System demonstrated excellent PCI device stability with zero changes across %d reboot cycles.\n", actualTotalCycles)
		}
	case actualCyclesWithChanges == 0 && noteworthyConfigChanges:
		fmt.Fprintf(logFile, "\nTest Result: COMPLETED - REVIEW NOTEWORTHY CHANGES\n")
		fmt.Fprintf(logFile, "Device topology was stable across %d reboot cycles, but irregular config-space changes were detected (see 'Noteworthy changes' above).\n", actualTotalCycles)
	default:
		fmt.Fprintf(logFile, "\nTest Result: COMPLETED - REVIEW NOTEWORTHY CHANGES\n")
		fmt.Fprintf(logFile, "Device topology and/or capability changes were detected across %d reboot cycles (see 'Affected Cycles' above).\n", actualTotalCycles)
	}
	fmt.Fprintf(logFile, "==========================================\n")

	// Clean up PCI config binary files after test completion
	initialFile := "/lpot/initial.bin"
	currentFile := "/lpot/current.bin"

	if fileExists(initialFile) {
		if err := os.Remove(initialFile); err != nil {
			fmt.Printf("Warning: Failed to remove %s: %v\n", initialFile, err)
		} else {
			fmt.Printf("Cleaned up: %s\n", initialFile)
		}
	}

	if fileExists(currentFile) {
		if err := os.Remove(currentFile); err != nil {
			fmt.Printf("Warning: Failed to remove %s: %v\n", currentFile, err)
		} else {
			fmt.Printf("Cleaned up: %s\n", currentFile)
		}
	}
}

// parseRebootLogForStats parses the reboot.log file to extract accurate statistics
func parseRebootLogForStats() (time.Time, int, int, int, int) {
	var startTime time.Time
	totalCycles := 0
	cyclesWithChanges := 0
	topologyChanges := 0
	lspciChanges := 0

	data, err := os.ReadFile(REBOOT_LOG)
	if err != nil {
		fmt.Printf("Warning: Failed to read reboot.log for stats: %v\n", err)
		return time.Now(), 0, 0, 0, 0
	}

	lines := strings.Split(string(data), "\n")
	cycleHasChanges := false
	cycleHasTopologyChanges := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse start time from first "Start to test" entry. Older logs used
		// slash-separated dates; current logs use dash-separated. Try both so
		// summaries still work when a test spans a format-change upgrade.
		if startTime.IsZero() && strings.Contains(line, "#########Start to test#########") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				timeStr := parts[0] + " " + parts[1]
				for _, layout := range []string{logTimeFormat, "2006/01/02 15:04:05"} {
					if parsedTime, err := time.Parse(layout, timeStr); err == nil {
						startTime = parsedTime
						break
					}
				}
			}
		}

		// Count reboot cycles
		if strings.Contains(line, "Reboot Count:") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "Count:" && i+1 < len(parts) {
					if count, err := strconv.Atoi(parts[i+1]); err == nil {
						if count > totalCycles {
							totalCycles = count
						}
					}
					break
				}
			}
		}

		// Detect device topology changes (NEW/REMOVED devices)
		if strings.Contains(line, "NEW Device:") || strings.Contains(line, "REMOVED Device:") {
			if !cycleHasTopologyChanges {
				topologyChanges++
				cycleHasTopologyChanges = true
			}
			if !cycleHasChanges {
				cyclesWithChanges++
				cycleHasChanges = true
			}
		}

		// Detect lspci capability changes
		if strings.Contains(line, "Had devices changed") {
			if !cycleHasChanges {
				cyclesWithChanges++
				cycleHasChanges = true
			}
			lspciChanges++
		}

		// Reset flags at start of new cycle
		if strings.Contains(line, "#########Start to test#########") && totalCycles > 1 {
			cycleHasChanges = false
			cycleHasTopologyChanges = false
		}
	}

	// If no start time found, use a reasonable default
	if startTime.IsZero() {
		startTime = time.Now().Add(-1 * time.Hour) // Assume 1 hour ago
	}

	return startTime, totalCycles, cyclesWithChanges, topologyChanges, lspciChanges
}

// generateConfigSpaceSummary generates the PCI config space analysis summary.
//
// totalCycles is the authoritative reboot-cycle count parsed from reboot.log;
// it is used as the denominator for per-(device,offset) occurrence ratios. It
// is passed in rather than read from the global totalRebootCycles because the
// timestamp-expired exit path generates the summary before that global is set,
// which previously left every ratio at 0% (the "82 (0%)" bug).
//
// It returns true when at least one genuinely volatile (irregular, < the
// reboot-fixed threshold) register change was observed, so the caller can pick
// an accurate final verdict.
func generateConfigSpaceSummary(logFile *os.File, totalCycles int) (noteworthy bool) {
	fmt.Fprintf(logFile, "\n========== PCI Config Space Analysis Summary ==========\n")

	// Count total monitored devices from initial.bin if it exists
	totalDevices := 0
	if data, err := os.ReadFile("/lpot/initial.bin"); err == nil {
		devices := splitDevices(data)
		totalDevices = len(devices)
	}

	// Analyze the PCI config changes log file
	configChangesFound := 0
	deviceChanges := make(map[string]map[string]int) // device -> offset -> count
	cyclesAffected := map[string]bool{}              // distinct [Cycle N] tags that had a change
	if data, err := os.ReadFile(CONFIG_CHANGES_LOG); err == nil {
		lines := strings.Split(string(data), "\n")
		var currentDevice string
		for _, line := range lines {
			// Count lines that indicate actual config changes (not just parsing info)
			if strings.Contains(line, "config space change detected") {
				configChangesFound++
				// Record which cycle this change belongs to so we can report
				// the number of distinct cycles affected, not just the raw
				// per-device occurrence count.
				if i := strings.Index(line, "[Cycle "); i >= 0 {
					if j := strings.Index(line[i:], "]"); j > 0 {
						cyclesAffected[line[i:i+j+1]] = true
					}
				}
				// Extract device BDF from the line
				if strings.Contains(line, "Device:") {
					parts := strings.Fields(line)
					for j, part := range parts {
						if part == "Device:" && j+1 < len(parts) {
							currentDevice = parts[j+1]
							break
						}
					}
				}
			} else if strings.Contains(line, "Value at offset") && currentDevice != "" {
				// Extract offset from "Value at offset 0xXX changed from..."
				if strings.Contains(line, "offset 0x") {
					parts := strings.Split(line, " ")
					for j, part := range parts {
						if part == "offset" && j+1 < len(parts) {
							offset := parts[j+1]
							if deviceChanges[currentDevice] == nil {
								deviceChanges[currentDevice] = make(map[string]int)
							}
							deviceChanges[currentDevice][offset]++
							break
						}
					}
				}
			}
		}
	}

	fmt.Fprintf(logFile, "Total devices monitored: %d\n", totalDevices)

	// Report raw change occurrences alongside the number of distinct reboot
	// cycles in which any change was seen. The previous "%% of cycles" figure
	// divided an occurrence count (one per device-change event, many per cycle)
	// by the cycle count, which is not a meaningful percentage.
	var cyclesAffectedPct float64
	if totalCycles > 0 {
		cyclesAffectedPct = float64(len(cyclesAffected)) / float64(totalCycles) * 100
	}
	fmt.Fprintf(logFile, "Config space changes detected: %d occurrences across %d/%d cycles (%.1f%%)\n",
		configChangesFound, len(cyclesAffected), totalCycles, cyclesAffectedPct)

	if configChangesFound > 0 {
		// Partition each (device, offset) row by occurrence ratio: anything
		// that fires in >= rebootFixedThreshold of the cycles is treated as
		// "reboot-fixed" noise (e.g. the controller scribbles the same byte
		// on every boot) and surfaced separately from genuinely volatile
		// registers. Rows are stable-sorted by BDF then offset for diffable
		// output.
		const rebootFixedThreshold = 0.80
		type rowKey struct{ device, offset string }
		type row struct {
			key   rowKey
			count int
			ratio float64
		}
		var fixedRows, volatileRows []row
		fixedDevices := map[string]bool{}
		volatileDevices := map[string]bool{}
		for device, offsets := range deviceChanges {
			for offset, count := range offsets {
				ratio := 0.0
				if totalCycles > 0 {
					ratio = float64(count) / float64(totalCycles)
				}
				r := row{key: rowKey{normalizeBDF(device), offset}, count: count, ratio: ratio}
				if ratio >= rebootFixedThreshold {
					fixedRows = append(fixedRows, r)
					fixedDevices[r.key.device] = true
				} else {
					volatileRows = append(volatileRows, r)
					volatileDevices[r.key.device] = true
				}
			}
		}
		rowLess := func(a, b row) bool {
			if a.key.device != b.key.device {
				return a.key.device < b.key.device
			}
			return a.key.offset < b.key.offset
		}
		sort.Slice(fixedRows, func(i, j int) bool { return rowLess(fixedRows[i], fixedRows[j]) })
		sort.Slice(volatileRows, func(i, j int) bool { return rowLess(volatileRows[i], volatileRows[j]) })

		writeRows := func(title string, rows []row) {
			if len(rows) == 0 {
				return
			}
			if title != "" {
				fmt.Fprintf(logFile, "\n%s:\n", title)
			}
			fmt.Fprintf(logFile, "┌─────────────────┬─────────────────┬─────────┬─────────┬─────────┐\n")
			fmt.Fprintf(logFile, "│ %-15s │ %-15s │ %-7s │ %-7s │ %-7s │\n", "Device BDF", "Change Count", "Offset", "Pattern", "Type")
			fmt.Fprintf(logFile, "├─────────────────┼─────────────────┼─────────┼─────────┼─────────┤\n")
			for _, r := range rows {
				changeType := "Config"
				switch {
				case r.key.offset == "0xa2":
					changeType = "Config"
				case r.key.offset == "0x3c" || r.key.offset == "0x3d":
					changeType = "IRQ"
				case strings.Contains(r.key.offset, "0x4") || strings.Contains(r.key.offset, "0x5"):
					changeType = "Control"
				case strings.Contains(r.key.offset, "0x6") || strings.Contains(r.key.offset, "0x7"):
					changeType = "Status"
				}
				// A register that changes in (almost) every cycle is a fixed
				// boot-time reset, not an erratic counter; label it accordingly
				// so the table itself signals "benign" vs "irregular".
				pattern := "Various"
				switch {
				case r.count == 1:
					pattern = "Single"
				case r.ratio >= rebootFixedThreshold:
					pattern = "Fixed"
				case r.count > 5:
					pattern = "Counter"
				}
				fmt.Fprintf(logFile, "│ %-15s │ %-15s │ %-7s │ %-7s │ %-7s │\n",
					r.key.device,
					fmt.Sprintf("%d (%.0f%%)", r.count, r.ratio*100),
					r.key.offset, pattern, changeType)
			}
			fmt.Fprintf(logFile, "└─────────────────┴─────────────────┴─────────┴─────────┴─────────┘\n")
		}
		// Surface the genuinely concerning changes FIRST so a reader sees what
		// (if anything) warrants attention before scrolling past the benign
		// boot-time noise. When there are no irregular changes, say so
		// explicitly \u2014 an empty section reads as "nothing to worry about".
		noteworthy = len(volatileRows) > 0
		fmt.Fprintf(logFile, "\n\u26a0\ufe0f  Noteworthy changes (occur in < %.0f%% of cycles \u2014 irregular, may indicate real instability):\n",
			rebootFixedThreshold*100)
		if noteworthy {
			writeRows("", volatileRows)
		} else {
			fmt.Fprintf(logFile, "    \u2014 none \u2014 all observed config-space changes are consistent boot-time register resets (benign).\n")
		}

		writeRows(fmt.Sprintf("Reboot-fixed register noise (occur in \u2265 %.0f%% of cycles \u2014 same value re-applied every boot, benign)",
			rebootFixedThreshold*100), fixedRows)

		stableDevices := totalDevices - len(volatileDevices) - len(fixedDevices)
		if stableDevices < 0 {
			stableDevices = 0
		}
		var stablePct, fixedPct, volPct float64
		if totalDevices > 0 {
			stablePct = float64(stableDevices) / float64(totalDevices) * 100
			fixedPct = float64(len(fixedDevices)) / float64(totalDevices) * 100
			volPct = float64(len(volatileDevices)) / float64(totalDevices) * 100
		}
		fmt.Fprintf(logFile, "\nStable devices: %d (%.1f%%)\n", stableDevices, stablePct)
		fmt.Fprintf(logFile, "Reboot-fixed-only devices: %d (%.1f%%)  <- benign boot-time noise\n", len(fixedDevices), fixedPct)
		fmt.Fprintf(logFile, "Truly volatile devices: %d (%.1f%%)  <- attention needed\n", len(volatileDevices), volPct)
	} else {
		fmt.Fprintf(logFile, "\nAll PCI devices maintained stable configuration throughout test.\n")
		fmt.Fprintf(logFile, "No configuration space changes detected (excluding timer-related registers).\n")
	}
	return noteworthy
}
