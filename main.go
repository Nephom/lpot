package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	version       = "2.6.15"
	serviceName   = "lpot.service"
	legacyService = "lpot_reboot.service"
	servicePath   = "/etc/systemd/system/" + serviceName
	legacyPath    = "/etc/systemd/system/" + legacyService
)

var buildTime = "development"

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
	// legacy code path keep working unchanged. skippedDevicesGlobal records
	// the BDFs that were filtered out, with their classification reason, so
	// the final summary can list them in a dedicated section.
	endpointFilterSet       map[string]bool
	classifiedDevicesGlobal []deviceClassification
	skippedDevicesGlobal    []deviceClassification

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

// pciDeviceInfo carries the header and link fields needed for link classification
// and for log enrichment. It is intentionally a small subset of the full
// PCIDeviceInfo struct so callers that only need the class/header data are not
// forced to parse the entire 256-byte config space.
type pciDeviceInfo struct {
	BDF           string
	Vendor        uint16 // config offset 0x00-0x01
	Device        uint16 // config offset 0x02-0x03
	SubClass      byte   // config offset 0x0a
	BaseClass     byte   // config offset 0x0b
	HeaderType    byte   // config offset 0x0e, masked with 0x7f (top bit = MFD)
	HasPCIeCap    bool   // PCI Express Capability (Cap ID 0x10) present in cap list
	CapOffset     byte   // PCI Express Capability offset in config space
	LinkSpeed     byte   // PCIe Link Capabilities speed code, zero when unavailable
	LinkWidth     byte   // PCIe Link Capabilities width, zero when unavailable
	LinkStaSpeed  byte   // PCIe Link Status speed code, zero when unavailable
	LinkStaWidth  byte   // PCIe Link Status width, zero when unavailable
	LspciLinkOK   bool   // lspci provided parseable LnkCap/LnkSta evidence
	LspciSpeed    byte
	LspciWidth    byte
	LspciStaSpeed byte
	LspciStaWidth byte
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
// link classification. Returns ok=false on any read failure so callers can
// treat the BDF as "unknown" rather than block the test.
func readPCIDeviceInfo(bdf string) (pciDeviceInfo, bool) {
	cfg := readSysfsConfig(bdf, 256)
	if len(cfg) < 0x40 {
		return pciDeviceInfo{BDF: bdf}, false
	}
	return pciDeviceInfo{
		BDF:          bdf,
		Vendor:       binary.LittleEndian.Uint16(cfg[0x00:0x02]),
		Device:       binary.LittleEndian.Uint16(cfg[0x02:0x04]),
		SubClass:     cfg[0x0a],
		BaseClass:    cfg[0x0b],
		HeaderType:   cfg[0x0e] & 0x7f,
		HasPCIeCap:   hasPCIeCapability(cfg),
		CapOffset:    byte(pciExpressCapabilityOffset(cfg)),
		LinkSpeed:    pciExpressLinkSpeed(cfg),
		LinkWidth:    pciExpressLinkWidth(cfg),
		LinkStaSpeed: pciExpressLinkStatusSpeed(cfg),
		LinkStaWidth: pciExpressLinkStatusWidth(cfg),
	}, true
}

// hasPCIeCapability walks the PCI capability list starting at offset 0x34 and
// returns true when Cap ID 0x10 (PCI Express) is present. It walks at most 48
// links to avoid pointer loops on a malformed list, and short-circuits if the
// Status register's Capabilities List bit (bit 4 of offset 0x06) is clear.
func hasPCIeCapability(cfg []byte) bool {
	return pciExpressCapabilityOffset(cfg) != 0
}

func pciExpressCapabilityOffset(cfg []byte) int {
	if len(cfg) < 0x35 {
		return 0
	}
	status := binary.LittleEndian.Uint16(cfg[0x06:0x08])
	if status&0x10 == 0 {
		return 0
	}
	next := int(cfg[0x34] & 0xfc)
	for i := 0; i < 48 && next != 0 && next+1 < len(cfg); i++ {
		if cfg[next] == 0x10 { // PCI Express
			return next
		}
		next = int(cfg[next+1] & 0xfc)
	}
	return 0
}

func pciExpressLinkSpeed(cfg []byte) byte {
	offset := pciExpressCapabilityOffset(cfg)
	if offset == 0 || offset+0x10 > len(cfg) {
		return 0
	}
	return cfg[offset+0x0c] & 0x0f
}

func pciExpressLinkWidth(cfg []byte) byte {
	offset := pciExpressCapabilityOffset(cfg)
	if offset == 0 || offset+0x10 > len(cfg) {
		return 0
	}
	// Link Capabilities is a 32-bit register at capability+0x0c. Maximum
	// Link Width is bits 9:4: bits 7:4 of byte 0 and bits 1:0 of byte 1.
	return (cfg[offset+0x0c] >> 4) | ((cfg[offset+0x0d] & 0x03) << 4)
}

func pciExpressLinkStatusSpeed(cfg []byte) byte {
	offset := pciExpressCapabilityOffset(cfg)
	if offset == 0 || offset+0x14 > len(cfg) {
		return 0
	}
	return cfg[offset+0x12] & 0x0f
}

func pciExpressLinkStatusWidth(cfg []byte) byte {
	offset := pciExpressCapabilityOffset(cfg)
	if offset == 0 || offset+0x14 > len(cfg) {
		return 0
	}
	return (cfg[offset+0x12] >> 4) | ((cfg[offset+0x13] & 0x03) << 4)
}

func lspciSpeedCode(value string) (byte, bool) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ",")
	value = strings.TrimSuffix(value, "GT/s")
	speed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	switch speed {
	case 2.5:
		return 1, true
	case 5:
		return 2, true
	case 8:
		return 3, true
	case 16:
		return 4, true
	case 32:
		return 5, true
	case 64:
		return 6, true
	default:
		return 0, false
	}
}

func parseLspciLinkLine(output []byte, marker string) (byte, byte, bool) {
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, marker+":") {
			continue
		}
		fields := strings.Fields(line)
		var speed byte
		var width byte
		for i, field := range fields {
			if field == "Speed" && i+1 < len(fields) {
				if parsed, ok := lspciSpeedCode(fields[i+1]); ok {
					speed = parsed
				}
			}
			if field == "Width" && i+1 < len(fields) {
				value := strings.TrimPrefix(strings.TrimSuffix(fields[i+1], ","), "x")
				if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 && parsed <= 255 {
					width = byte(parsed)
				}
			}
		}
		return speed, width, speed != 0 && width != 0
	}
	return 0, 0, false
}

func enrichLspciLinkInfo(info *pciDeviceInfo, bdf string) {
	if lspciPath == "" || rootCtx == nil {
		return
	}
	output, err := runExternal(lspciTimeout, lspciPath, "-s", bdf, "-vv")
	if err != nil {
		return
	}
	speed, width, capOK := parseLspciLinkLine(output, "LnkCap")
	staSpeed, staWidth, _ := parseLspciLinkLine(output, "LnkSta")
	if capOK {
		info.LspciLinkOK = true
		info.LspciSpeed = speed
		info.LspciWidth = width
		info.LspciStaSpeed = staSpeed
		info.LspciStaWidth = staWidth
	}
}

// isPCIeLinkCapable selects devices whose PCIe Link Capabilities can be
// compared. Root ports, bridges, system peripherals and endpoints are all
// valid candidates; their PCI header class is not a reason to exclude them.
// Only a missing PCIe capability or missing advertised link speed/width makes
// a device unsuitable for the link comparison.
//
// Returns (true, "") for link-capable devices and (false, reason) otherwise, where
// reason is a short human-readable string suitable for inclusion in the
// classification report and the final summary.
func isPCIeLinkCapable(info pciDeviceInfo) (bool, string) {
	if !info.HasPCIeCap {
		return false, "PCIe capability not found"
	}
	if info.LinkSpeed == 0 || info.LinkWidth == 0 {
		return false, "no PCIe link speed/width"
	}
	if !isValidPCIeSpeed(info.LinkSpeed) {
		return false, fmt.Sprintf("possible raw PCI config capability pointer/offset decode mismatch: invalid PCIe link speed code %d", info.LinkSpeed)
	}
	if !isValidPCIeWidth(info.LinkWidth) {
		if info.LinkWidth == 0 {
			return false, "possible raw PCI config capability pointer/offset decode mismatch: no PCIe link width"
		}
		return false, fmt.Sprintf("possible raw PCI config capability pointer/offset decode mismatch: invalid PCIe link width code %d", info.LinkWidth)
	}
	return true, ""
}

func isValidPCIeSpeed(code byte) bool { return code >= 1 && code <= 6 }

func isValidPCIeWidth(width byte) bool {
	switch width {
	case 1, 2, 4, 8, 12, 16, 32:
		return true
	default:
		return false
	}
}

// pcieFilterOverrides holds optional user-supplied include/exclude directives
// parsed from PCIE_FILTER_FILE. Exclude is a manual test omission; Include only
// changes the label for a device that already has a comparable PCIe link.
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
	KeptReason string // "link-capable", "manual include", ""
	SkipReason string // populated when Kept == false
}

// classifyDevices checks every BDF for a comparable PCIe link, then applies
// optional pcie_filter.txt exclusions. The classification is evidence only;
// raw config scanning retains every readable BDF so a decode mismatch cannot
// hide a changed byte offset.
func classifyDevices(bdfs []string, ov pcieFilterOverrides) []deviceClassification {
	out := make([]deviceClassification, 0, len(bdfs))
	for _, bdf := range bdfs {
		short := normalizeBDF(bdf)
		dc := deviceClassification{BDF: short}
		info, ok := readPCIDeviceInfo(bdf)
		if ok {
			enrichLspciLinkInfo(&info, bdf)
		}
		dc.Info = info
		dc.InfoOK = ok
		switch {
		case !ok:
			dc.Kept = false
			dc.SkipReason = "unreadable config space (unverified)"
		default:
			linkCapable, reason := isPCIeLinkCapable(info)
			mismatchReason := rawLspciLinkMismatchReason(info)
			if !linkCapable && info.LspciLinkOK {
				linkCapable = true
				reason = mismatchReason
			}
			if mismatchReason != "" {
				reason = mismatchReason
			}
			switch {
			case ov.Exclude[short]:
				dc.Kept = false
				dc.SkipReason = "manual exclude (-)"
			case linkCapable && ov.Include[short]:
				dc.Kept = true
				dc.KeptReason = "manual include (+)"
			case linkCapable:
				dc.Kept = true
				dc.KeptReason = "link-capable"
				if mismatchReason != "" {
					dc.KeptReason = mismatchReason
				}
			default:
				dc.SkipReason = reason
			}
		}
		out = append(out, dc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BDF < out[j].BDF })
	return out
}

// filterEndpoints applies classifyDevices() to bdfs and returns only the BDFs
// that pass. It is retained for callers that explicitly request the link-only
// set; the normal stability run uses the complete raw-config device set.
func filterEndpoints(bdfs []string, ov pcieFilterOverrides) (kept []string, skipped []deviceClassification) {
	return filterClassifiedEndpoints(bdfs, classifyDevices(bdfs, ov))
}

func filterClassifiedEndpoints(bdfs []string, decisions []deviceClassification) (kept []string, skipped []deviceClassification) {
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

func pcieSpeedLabel(code byte) string {
	labels := map[byte]string{
		1: "2.5GT/s",
		2: "5GT/s",
		3: "8GT/s",
		4: "16GT/s",
		5: "32GT/s",
		6: "64GT/s",
	}
	if label, ok := labels[code]; ok {
		return label
	}
	if code == 0 {
		return "none"
	}
	return fmt.Sprintf("code %d", code)
}

func pcieLinkLabel(speed, width byte) string {
	if speed == 0 || width == 0 {
		return "NO LINK"
	}
	if !isValidPCIeSpeed(speed) {
		return fmt.Sprintf("INVALID SPEED CODE %d", speed)
	}
	if !isValidPCIeWidth(width) {
		return fmt.Sprintf("INVALID WIDTH CODE %d", width)
	}
	return fmt.Sprintf("%s x%d", pcieSpeedLabel(speed), width)
}

func pcieLinkEvidence(info pciDeviceInfo, infoOK bool) (string, string) {
	if !infoOK {
		return "-", "unreadable"
	}
	if !info.HasPCIeCap {
		return "no", "no PCIe capability"
	}
	return pcieLinkLabel(info.LinkSpeed, info.LinkWidth), pcieLinkLabel(info.LinkStaSpeed, info.LinkStaWidth)
}

func rawLspciLinkMismatchReason(info pciDeviceInfo) string {
	if !info.LspciLinkOK {
		return ""
	}
	var reasons []string
	if rawCap := pcieLinkLabel(info.LinkSpeed, info.LinkWidth); rawCap != pcieLinkLabel(info.LspciSpeed, info.LspciWidth) {
		reasons = append(reasons, fmt.Sprintf("raw/lspci mismatch (possible raw PCI config capability pointer/offset decode mismatch): raw LnkCap=%s, lspci LnkCap=%s",
			rawCap, pcieLinkLabel(info.LspciSpeed, info.LspciWidth)))
	}
	if rawSta := pcieLinkLabel(info.LinkStaSpeed, info.LinkStaWidth); rawSta != pcieLinkLabel(info.LspciStaSpeed, info.LspciStaWidth) {
		reasons = append(reasons, fmt.Sprintf("raw/lspci mismatch (possible raw PCI config capability pointer/offset decode mismatch): raw LnkSta=%s, lspci LnkSta=%s",
			rawSta, pcieLinkLabel(info.LspciStaSpeed, info.LspciStaWidth)))
	}
	return strings.Join(reasons, "; ")
}

func buildClassificationReport(decisions []deviceClassification) classificationReport {
	report := classificationReport{Status: "PASS", Total: len(decisions)}
	for _, d := range decisions {
		item := classificationDevice{
			BDF: d.BDF, Decision: "SKIP", Verification: "VERIFIED",
			PCIeCap: "no", LinkCap: "-", LinkStatus: "-", Reason: d.SkipReason,
		}
		if !d.InfoOK {
			item.Verification = "UNVERIFIED"
			report.Unverified++
		} else {
			item.Vendor = fmt.Sprintf("%04x", d.Info.Vendor)
			item.Device = fmt.Sprintf("%04x", d.Info.Device)
			item.Class = fmt.Sprintf("0x%02x:%02x", d.Info.BaseClass, d.Info.SubClass)
			item.Header = fmt.Sprintf("Type %d", d.Info.HeaderType)
			item.LinkCap, item.LinkStatus = pcieLinkEvidence(d.Info, true)
			if d.Info.LspciLinkOK {
				item.LspciLinkCap = pcieLinkLabel(d.Info.LspciSpeed, d.Info.LspciWidth)
				item.LspciStatus = pcieLinkLabel(d.Info.LspciStaSpeed, d.Info.LspciStaWidth)
			}
			if d.Info.HasPCIeCap {
				item.PCIeCap = fmt.Sprintf("yes @ 0x%02x", d.Info.CapOffset)
			}
		}
		if d.Kept {
			item.Decision = "KEEP"
			report.Kept++
		} else {
			report.Skipped++
		}
		if d.KeptReason != "" {
			item.Reason = d.KeptReason
		}
		report.Devices = append(report.Devices, item)
	}
	if report.Unverified > 0 {
		report.Status = "UNVERIFIED"
	}
	return report
}

// printClassificationReport renders a deterministic, human-readable summary of
// every BDF and the keep/skip decision. It is used both by the -classify
// dry-run flag and by the post-test summary so users see exactly the same
// view.
func printClassificationReport(w io.Writer, decisions []deviceClassification) {
	fmt.Fprintf(w, "%-12s %-9s %-9s %-7s %-8s %-18s %-18s %-18s %-18s %s\n",
		"BDF", "Vendor", "Device", "Class", "HdrType", "Raw LnkCap", "Raw LnkSta", "lspci LnkCap", "lspci LnkSta", "Decision / Reason")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 190))
	for _, d := range decisions {
		var ven, dev, cls, hdr string
		linkCap, linkStatus := pcieLinkEvidence(d.Info, d.InfoOK)
		lspciCap, lspciStatus := "-", "-"
		if d.InfoOK {
			ven = fmt.Sprintf("%04x", d.Info.Vendor)
			dev = fmt.Sprintf("%04x", d.Info.Device)
			cls = fmt.Sprintf("0x%02x", d.Info.BaseClass)
			hdr = fmt.Sprintf("Type %d", d.Info.HeaderType)
			if d.Info.LspciLinkOK {
				lspciCap = pcieLinkLabel(d.Info.LspciSpeed, d.Info.LspciWidth)
				lspciStatus = pcieLinkLabel(d.Info.LspciStaSpeed, d.Info.LspciStaWidth)
			}
		} else {
			ven, dev, cls, hdr = "-", "-", "-", "-"
		}
		decision := "KEEP " + d.KeptReason
		if !d.Kept {
			decision = "SKIP " + d.SkipReason
		}
		fmt.Fprintf(w, "%-12s %-9s %-9s %-7s %-8s %-18s %-18s %-18s %-18s %s\n",
			d.BDF, ven, dev, cls, hdr, linkCap, linkStatus, lspciCap, lspciStatus, decision)
	}
}

func persistClassificationReport(decisions []deviceClassification) error {
	fp, err := openSecureAppend(CLASSIFY_LOG, 0644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(fp, "\n===== %s classify run (%d devices) =====\n",
		getCurrentTimestamp(), len(decisions)); err != nil {
		fp.Close()
		return err
	}
	printClassificationReport(fp, decisions)
	return fp.Close()
}

func configDumpPath(bdf string) (string, error) {
	normalized := normalizeBDF(bdf)
	if !shortBDFRegex.MatchString(normalized) && !bdfRegex.MatchString(normalized) {
		return "", fmt.Errorf("invalid PCI BDF %q", bdf)
	}
	return filepath.Join(CONFIG_DUMP_DIR, normalized+".txt"), nil
}

func formatConfigDump(cfg []byte) string {
	var out strings.Builder
	for offset := 0; offset < len(cfg); offset += 16 {
		end := offset + 16
		if end > len(cfg) {
			end = len(cfg)
		}
		fmt.Fprintf(&out, "%02x:", offset)
		for _, value := range cfg[offset:end] {
			fmt.Fprintf(&out, " %02x", value)
		}
		out.WriteByte('\n')
	}
	return out.String()
}

func persistClassificationConfigDumps(decisions []deviceClassification) error {
	if err := os.MkdirAll(CONFIG_DUMP_DIR, 0755); err != nil {
		return fmt.Errorf("create %s: %w", CONFIG_DUMP_DIR, err)
	}
	entries, err := os.ReadDir(CONFIG_DUMP_DIR)
	if err != nil {
		return fmt.Errorf("read %s: %w", CONFIG_DUMP_DIR, err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".txt") {
			if err := os.Remove(filepath.Join(CONFIG_DUMP_DIR, entry.Name())); err != nil {
				return fmt.Errorf("clear config dump %s: %w", entry.Name(), err)
			}
		}
	}
	for _, decision := range decisions {
		if !decision.Kept || !decision.InfoOK {
			continue
		}
		path, err := configDumpPath(decision.BDF)
		if err != nil {
			return err
		}
		cfg := readSysfsConfig(decision.BDF, 256)
		if len(cfg) == 0 {
			continue
		}
		if err := writeFileNoFollow(path, []byte(formatConfigDump(cfg)), 0644); err != nil {
			return fmt.Errorf("write config dump for %s: %w", decision.BDF, err)
		}
	}
	return nil
}

func writeClassificationReportToLog(logFp *os.File, decisions []deviceClassification) error {
	current := classificationSnapshot{Devices: make(map[string]string, len(decisions))}
	report := buildClassificationReport(decisions)
	if report.Unverified > 0 {
		return fmt.Errorf("classification baseline not updated: %d device(s) are unverified", report.Unverified)
	}
	for _, item := range report.Devices {
		encoded, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("marshal classification snapshot for %s: %w", item.BDF, err)
		}
		current.Devices[item.BDF] = string(encoded)
	}

	previous := classificationSnapshot{}
	data, readErr := os.ReadFile(CLASSIFY_STATE_FILE)
	if readErr == nil {
		if err := json.Unmarshal(data, &previous); err != nil {
			readErr = err
		}
	}
	if readErr != nil || len(previous.Devices) == 0 {
		fmt.Fprintf(logFp, "\n%s===== Complete PCI link classification (%d devices) =====\n", cycleTag(), len(decisions))
		printClassificationReport(logFp, decisions)
		if err := writeClassificationBaseline(current); err != nil {
			return fmt.Errorf("write classification baseline: %w", err)
		}
	} else {
		changed := make([]deviceClassification, 0)
		for _, decision := range decisions {
			if previous.Devices[decision.BDF] != current.Devices[decision.BDF] {
				changed = append(changed, decision)
			}
		}
		removed := make([]string, 0)
		for bdf := range previous.Devices {
			if _, ok := current.Devices[bdf]; !ok {
				removed = append(removed, bdf)
			}
		}
		sort.Strings(removed)
		if len(changed) == 0 && len(removed) == 0 {
			fmt.Fprintf(logFp, "%s %sPCIe classification matches baseline.\n", getCurrentTimestamp(), cycleTag())
		} else {
			fmt.Fprintf(logFp, "\n%s===== PCIe classification changes from baseline =====\n", cycleTag())
			if len(changed) > 0 {
				printClassificationReport(logFp, changed)
			}
			for _, bdf := range removed {
				fmt.Fprintf(logFp, "Removed: %s\n", bdf)
			}
		}
	}
	return nil
}

// writeClassificationBaseline publishes the first valid classification for a
// test run. It is deliberately separate from current-cycle reporting: later
// cycles are compared with this baseline and must never replace it.
func writeClassificationBaseline(snapshot classificationSnapshot) error {
	data := marshalClassificationSnapshot(snapshot)
	tmpPath := fmt.Sprintf("%s.tmp.%d", CLASSIFY_STATE_FILE, os.Getpid())
	if err := writeFileNoFollow(tmpPath, data, 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmpPath, os.O_WRONLY, 0600)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, CLASSIFY_STATE_FILE); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

type classificationSnapshot struct {
	Devices map[string]string `json:"devices"`
}

func marshalClassificationSnapshot(snapshot classificationSnapshot) []byte {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return []byte("{}\n")
	}
	return append(data, '\n')
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
func resolveBinaries(requireLSPCITools, requireRebootTools bool) error {
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")

	tools := []struct {
		name string
		dst  *string
	}{
		{"lspci", &lspciPath},
	}
	if requireLSPCITools {
		for _, t := range tools {
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
	}
	if requireRebootTools {
		for _, t := range []struct {
			name string
			dst  *string
		}{
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
// not reachable through a symlink. The directory is readable/traversable by
// non-root users for operational inspection, while files that control reboot
// execution remain root-owned and non-writable by other users.
func secureLpotDir() error {
	info, err := os.Lstat(LPOT_DIR)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", LPOT_DIR, err)
		}
		if err := os.MkdirAll(LPOT_DIR, 0755); err != nil {
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
	if info.Mode().Perm() != 0755 {
		if err := os.Chmod(LPOT_DIR, 0755); err != nil {
			return fmt.Errorf("chmod %s to 0755: %w", LPOT_DIR, err)
		}
	}
	tmpInfo, err := os.Lstat(TMP_DIR)
	if err == nil {
		if tmpInfo.Mode()&os.ModeSymlink != 0 || !tmpInfo.IsDir() {
			return fmt.Errorf("%s must be a real directory", TMP_DIR)
		}
		if st, ok := tmpInfo.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("%s must be owned by root (uid 0), found uid %d", TMP_DIR, st.Uid)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(TMP_DIR, 0755); err != nil {
			return fmt.Errorf("create %s: %w", TMP_DIR, err)
		}
	} else {
		return fmt.Errorf("stat %s: %w", TMP_DIR, err)
	}
	if err := os.Chmod(TMP_DIR, 0755); err != nil {
		return fmt.Errorf("chmod %s: %w", TMP_DIR, err)
	}
	return nil
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

// fileExists reports only a usable regular file. Permission and I/O errors are
// not silently converted into "exists", because doing so can make the next
// stage skip required initialization and produce misleading comparisons.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && info.Mode().IsRegular()
}

func installPersistentBinary(source string) error {
	if err := verifyRootRegularFileIfPresent(PERSISTENT_BINARY); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("resolve executable %q: %w", source, err)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("read executable %q: %w", resolved, err)
	}
	if target, targetErr := filepath.EvalSymlinks(PERSISTENT_BINARY); targetErr == nil && target == resolved {
		if err := os.Chmod(PERSISTENT_BINARY, 0755); err != nil {
			return fmt.Errorf("set executable mode on %s: %w", PERSISTENT_BINARY, err)
		}
		return nil
	}

	// Install through a closed temporary inode and rename it into place. Directly
	// truncating /lpot/lpot fails with ETXTBSY when the service is already running
	// that same binary.
	tmp, err := os.CreateTemp(LPOT_DIR, ".lpot-install-*")
	if err != nil {
		return fmt.Errorf("create temporary executable in %s: %w", LPOT_DIR, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		return fmt.Errorf("set temporary executable mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary executable: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	if err := os.Rename(tmpName, PERSISTENT_BINARY); err != nil {
		return fmt.Errorf("install executable at %s: %w", PERSISTENT_BINARY, err)
	}
	return nil
}

// Get current timestamp string
func getCurrentTimestamp() string {
	return time.Now().Format(logTimeFormat)
}

// Validate input parameters
func validateInputParameters(waitHours, waitSeconds, standbyTime int) bool {
	if waitHours < 1 || waitHours > 8760 {
		fmt.Fprintf(os.Stderr, "Invalid -t value: duration must be between 1 and 8760 hours.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-t 24` or bare `-t` for the 12-hour default.")
		return false
	}
	if waitSeconds < 10 || waitSeconds > 3600 {
		fmt.Fprintf(os.Stderr, "Invalid -s value: reboot wait must be between 10 and 3600 seconds.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-s 600`.")
		return false
	}
	if standbyTime < 10 || standbyTime > 3600 {
		fmt.Fprintf(os.Stderr, "Invalid -d value: driver wait must be between 10 and 3600 seconds.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-d 300`.")
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
	if err := os.Chmod(TIMESTAMP_FILE, 0644); err != nil {
		return fmt.Errorf("failed to set timestamp file mode: %v", err)
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
	if err := verifyRootRegularFileIfPresent(REBOOTCOUNT_FILE); err != nil {
		return 0, err
	}
	fp, err := os.OpenFile(REBOOTCOUNT_FILE, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, fmt.Errorf("failed to open reboot count file: %v", err)
	}
	defer fp.Close()
	if err := fp.Chmod(0600); err != nil {
		return 0, fmt.Errorf("failed to set reboot count mode: %w", err)
	}

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

func readRebootCount() (int, error) {
	data, err := os.ReadFile(REBOOTCOUNT_FILE)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read reboot count: %w", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse reboot count: %w", err)
	}
	return count, nil
}

func resetClassificationBaseline() error {
	err := os.Remove(CLASSIFY_STATE_FILE)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func prepareTestCycleLimit(limit int) (bool, error) {
	current, err := readRebootCount()
	if err != nil {
		return false, err
	}
	target, targetErr := readOptionalInteger(TM_TARGET_FILE)
	start, startErr := readOptionalInteger(TM_START_COUNT_FILE)
	cycleTarget := cycleTargetForReboots(limit)
	if targetErr != nil || startErr != nil || target <= 0 || start < 0 || current < start || current >= start+target {
		if err := resetClassificationBaseline(); err != nil {
			return false, fmt.Errorf("reset classification baseline: %w", err)
		}
		target = cycleTarget
		start = current
		if err := writeFileNoFollow(TM_TARGET_FILE, []byte(fmt.Sprintf("%d\n", target)), 0600); err != nil {
			return false, fmt.Errorf("write test cycle target: %w", err)
		}
		if err := writeFileNoFollow(TM_START_COUNT_FILE, []byte(fmt.Sprintf("%d\n", start)), 0600); err != nil {
			return false, fmt.Errorf("write test cycle start count: %w", err)
		}
	}
	return current-start >= target, nil
}

func cycleTargetForReboots(reboots int) int {
	return reboots + 1
}

func readOptionalInteger(path string) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return value, nil
}

func fixedCycleLimitReached(current int) (bool, error) {
	target, err := readOptionalInteger(TM_TARGET_FILE)
	if err != nil {
		return false, err
	}
	start, err := readOptionalInteger(TM_START_COUNT_FILE)
	if err != nil {
		return false, err
	}
	return target > 0 && current-start >= target, nil
}

func disableFixedCycleService() {
	if systemctlPath != "" {
		if _, err := runExternal(systemctlTimeout, systemctlPath, "disable", serviceName); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to disable %s after -tm completion: %v\n", serviceName, err)
		}
	}
	os.Remove(TM_TARGET_FILE)
	os.Remove(TM_START_COUNT_FILE)
}

// Log initial test information. Emits a clearly delimited cycle-start banner
// so `grep '===== Cycle'` pulls out every cycle boundary, and every event
// between two banners is known to belong to the enclosing cycle.
func logInitialInfo(logFp *os.File, rebootCount int) {
	timeStr := getCurrentTimestamp()
	fmt.Fprintf(logFp, "\n\n%s ===== Cycle %d START =====\n", timeStr, rebootCount)
	fmt.Fprintf(logFp, "%s #########Start to test#########\n", timeStr)
	fmt.Fprintf(logFp, "\t\t\tReboot Count: %d\n", rebootCount)
	fmt.Fprintf(logFp, "\t\t\tLPOT Version: %s (built %s)\n", version, buildTime)
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

// splitCustomCommandArgs removes -c and treats every following token as the
// custom command argv. LPOT flags must therefore appear before -c.
func splitCustomCommandArgs(args []string) ([]string, []string, error) {
	for i, arg := range args[1:] {
		if arg != "-c" && !strings.HasPrefix(arg, "-c=") {
			continue
		}

		index := i + 1
		var custom []string
		if strings.HasPrefix(arg, "-c=") {
			if value := strings.TrimPrefix(arg, "-c="); value != "" {
				custom = append(custom, value)
			}
			custom = append(custom, args[index+1:]...)
		} else {
			custom = append(custom, args[index+1:]...)
		}
		if len(custom) == 0 || custom[0] == "" {
			return nil, nil, fmt.Errorf("-c requires a command and optional arguments")
		}
		return append([]string{args[0]}, args[1:index]...), custom, nil
	}
	return args, nil, nil
}

// Create reboot script
func createRebootScript(args, customCommand []string) error {
	scriptPath := filepath.Join(LPOT_DIR, "reboot.sh")
	if err := verifyRootRegularFileIfPresent(scriptPath); err != nil {
		return err
	}

	// Install the binary under /lpot before writing the script. The original
	// download location may be /root, /tmp, or another transient directory;
	// systemd must have a stable executable path after reboot.
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	if err := installPersistentBinary(source); err != nil {
		return err
	}

	executablePath := PERSISTENT_BINARY
	_, err = os.Stat(executablePath)
	if err != nil {
		return fmt.Errorf("verify installed executable %s: %w", executablePath, err)
	}

	var script strings.Builder
	script.WriteString("#!/bin/bash\n")
	if len(customCommand) > 0 {
		for i, arg := range customCommand {
			if i > 0 {
				script.WriteString(" ")
			}
			script.WriteString(shellQuote(arg))
		}
		script.WriteString(" >> ")
		script.WriteString(shellQuote(COMMAND_USER_LOG))
		script.WriteString(" 2>&1 &\n")
	}
	script.WriteString("exec ")
	script.WriteString(shellQuote(executablePath))
	for _, arg := range args[1:] {
		script.WriteString(" ")
		script.WriteString(shellQuote(arg))
	}
	if len(customCommand) > 0 {
		script.WriteString(" -c")
		for _, arg := range customCommand {
			script.WriteString(" ")
			script.WriteString(shellQuote(arg))
		}
	}
	script.WriteByte('\n')
	if err := writeFileNoFollow(scriptPath, []byte(script.String()), 0700); err != nil {
		return fmt.Errorf("write reboot script %s: %w", scriptPath, err)
	}
	if err := os.Chmod(scriptPath, 0700); err != nil {
		return fmt.Errorf("set reboot script mode on %s: %w", scriptPath, err)
	}
	return nil
}

func persistentRebootArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-scan" || strings.HasPrefix(arg, "-scan=") ||
			arg == "-classify" || strings.HasPrefix(arg, "-classify=") {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

// disableSELinux best-effort puts SELinux into permissive mode immediately and
// disabled mode across the next reboot. It is safe on distributions without
// SELinux: a missing config file is treated as "not installed". The config
// rewrite handles enforcing, permissive, and whitespace variants.
// disableSELinux is implemented in systemd.go.

// systemdUnitExists distinguishes a missing optional unit from a unit that is
// installed but currently inactive. The latter must still be disabled for the
// next reboot.
// systemdUnitExists is implemented in systemd.go.

// stopAndDisableUnit stops an installed unit and disables it when it is enabled.
// Missing units are normal across RHEL, SLES, and Ubuntu and return nil.
// stopAndDisableUnit is implemented in systemd.go.

// disableFirewall stops and disables firewall services used by RHEL, SLES,
// and Ubuntu families. Missing services are expected and never abort the test.
// The explicit service list also covers older SLES installations that still
// expose SuSEfirewall2 rather than firewalld/nftables.
// disableFirewall is implemented in systemd.go.

// disableAppArmor stops and disables Ubuntu's AppArmor service. RHEL and SLES
// normally do not install it, so a missing unit is intentionally harmless.
// disableAppArmor is implemented in systemd.go.

// prepareHostPolicies is implemented in systemd.go.

// Reset lpot directory
func resetLpotDirectory() error {
	fmt.Println("Resetting /lpot directory...")
	if os.Geteuid() != 0 {
		return fmt.Errorf("reset requires effective uid 0")
	}
	if systemctlPath == "" {
		return fmt.Errorf("systemctl path was not resolved")
	}
	if err := verifyRootRegularFileIfPresent(servicePath); err != nil {
		return err
	}
	if err := stopAndDisableUnit(serviceName); err != nil {
		return fmt.Errorf("failed to stop and disable %s: %w", serviceName, err)
	}
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", servicePath, err)
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd after removing %s: %w", servicePath, err)
	}

	// Refuse to operate on LPOT_DIR if it is a symlink or not owned by root,
	// to avoid inadvertently deleting files outside of /lpot.
	info, err := os.Lstat(LPOT_DIR)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to reset: %s is a symlink", LPOT_DIR)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("refusing to reset: %s must be owned by root (uid 0), found uid %d", LPOT_DIR, st.Uid)
		}
	}

	if err := os.MkdirAll(LPOT_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", LPOT_DIR, err)
	}

	// Clean all files directly under /lpot. WalkDir does not descend into
	// symlinks by default; os.Remove removes the symlink entry itself rather
	// than following it, so both layers are safe against a symlink-redirected
	// delete.
	if err := filepath.WalkDir(LPOT_DIR, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && path != LPOT_DIR {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to remove runtime files under %s: %w", LPOT_DIR, err)
	}

	fmt.Println("Reset completed. You can now run lpot with normal parameters.")
	return nil
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

func printDryRunHostPolicyActions() {
	for _, service := range []string{"firewalld", "ufw", "nftables", "iptables", "ip6tables", "SuSEfirewall2", "apparmor"} {
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
	if setenforcePath != "" {
		printDryRunCommand(setenforcePath, "0")
	}
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

func runDryRunScanAudit() {
	fmt.Println("[DRY-RUN] scan audit mode; no scan result will be written")
	fmt.Printf("[DRY-RUN] WOULD READ %s for PCI configuration samples\n", SYS_PCI_DEVICES)
	fmt.Println("[DRY-RUN] WOULD COLLECT 5 read-only PCI samples at one-second intervals")
	fmt.Printf("[DRY-RUN] WOULD WRITE %s (generated volatile-byte ignore list)\n", IGNORE_LIST_FILE)
	fmt.Printf("[DRY-RUN] WOULD REMOVE temporary sample directory after analysis\n")
	fmt.Println("[DRY-RUN] scan audit complete")
}

func runDryRunClassifyAudit() {
	fmt.Println("[DRY-RUN] classify audit mode; no report or host policy will be written")
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fmt.Printf("[DRY-RUN] READ PCI devices failed: %v\n", err)
		return
	}
	ov, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
	if err != nil {
		fmt.Printf("[DRY-RUN] READ %s failed: %v\n", PCIE_FILTER_FILE, err)
		return
	}
	decisions := classifyDevices(bdfs, ov)
	var report bytes.Buffer
	printClassificationReport(&report, decisions)
	fmt.Printf("[DRY-RUN] WOULD WRITE %s\n", CLASSIFY_LOG)
	fmt.Printf("[DRY-RUN] CONTENT BEGIN %s\n%s[DRY-RUN] CONTENT END %s\n", CLASSIFY_LOG, report.String(), CLASSIFY_LOG)
	fmt.Println("[DRY-RUN] classify audit complete")
}

// runDryRunAudit performs the read-only portion of startup and prints every
// planned mutation. It is deliberately separate from the normal execution
// path: a dry run must remain safe even when a future write is added to the
// reboot loop and its author forgets to add another guard.
func runDryRunAudit(args []string, waitHours, standbyTime, waitSeconds int, stopService bool, scanOnly, classify bool) {
	if scanOnly {
		runDryRunScanAudit()
		return
	}
	if classify {
		runDryRunClassifyAudit()
		return
	}
	fmt.Println("[DRY-RUN] audit mode enabled; no filesystem or host-state mutation will occur")
	fmt.Printf("[DRY-RUN] parameters: duration=%dh driver-delay=%ds reboot-delay=%ds stop-on-error=%t\n",
		waitHours, standbyTime, waitSeconds, stopService)

	if info, err := os.Lstat(LPOT_DIR); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0755\n", LPOT_DIR)
		} else {
			fmt.Printf("[DRY-RUN] READ %s failed: %v\n", LPOT_DIR, err)
		}
	} else {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			LPOT_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}
	if info, err := os.Lstat(TMP_DIR); err != nil && os.IsNotExist(err) {
		fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0755\n", TMP_DIR)
	} else if err == nil {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			TMP_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}

	printDryRunHostPolicyActions()

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

	var script strings.Builder
	script.WriteString("#!/bin/bash\n")
	if len(customCommandArgs) > 0 {
		for i, arg := range customCommandArgs {
			if i > 0 {
				script.WriteString(" ")
			}
			script.WriteString(shellQuote(arg))
		}
		script.WriteString(" >> ")
		script.WriteString(shellQuote(COMMAND_USER_LOG))
		script.WriteString(" 2>&1 &\n")
	}
	script.WriteString("exec ")
	script.WriteString(shellQuote(PERSISTENT_BINARY))
	for _, arg := range args[1:] {
		script.WriteString(" ")
		script.WriteString(shellQuote(arg))
	}
	if len(customCommandArgs) > 0 {
		script.WriteString(" -c")
		for _, arg := range customCommandArgs {
			script.WriteString(" ")
			script.WriteString(shellQuote(arg))
		}
	}
	script.WriteByte('\n')
	printDryRunFile(PERSISTENT_BINARY, "replace", 0755, "[binary copied from the invoked executable]\n")
	printDryRunFile(filepath.Join(LPOT_DIR, "reboot.sh"), "replace", 0700, script.String())

	if info, err := os.Lstat(legacyPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
		printDryRunCommand(systemctlPath, "stop", legacyService)
		printDryRunCommand(systemctlPath, "disable", legacyService)
		fmt.Printf("[DRY-RUN] WOULD REMOVE %s\n", legacyPath)
	}
	target := "multi-user.target"
	if out := printDryRunReadCommand(systemctlTimeout, systemctlPath, "get-default"); strings.TrimSpace(string(out)) == "graphical.target" {
		target = "graphical.target"
	}
	fmt.Printf("[DRY-RUN] selected systemd WantedBy=%s\n", target)
	printDryRunFile(servicePath, "create", 0644, systemdServiceContent(filepath.Join(LPOT_DIR, "reboot.sh"), target))
	printDryRunCommand(systemctlPath, "daemon-reload")
	printDryRunCommand(systemctlPath, "enable", serviceName)

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
		CONFIG_CHANGES_LOG, CLASSIFY_LOG, LPOTSCAN_LOG, REBOOT_LOG, RESULT_FILE, COMMAND_USER_LOG,
	} {
		fmt.Printf("[DRY-RUN] WOULD WRITE/UPDATE %s (content generated from read-only PCI scan and comparison)\n", path)
	}
	fmt.Printf("[DRY-RUN] WOULD REMOVE generated temporary snapshots under %s\n", TMP_DIR)
	fmt.Printf("[DRY-RUN] WOULD WAIT %ds before reboot\n", waitSeconds)
	printDryRunCommand(rebootPath)
	fmt.Println("[DRY-RUN] audit complete; reboot command was not executed")
}

func rootPasswordHash() (string, error) {
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return "", fmt.Errorf("failed to read /etc/shadow: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) >= 2 && fields[0] == "root" {
			if fields[1] == "" || fields[1] == "!*" {
				return "", fmt.Errorf("root account has no usable password hash")
			}
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("root entry not found in /etc/shadow")
}

func authenticateDebug(hash string) error {
	if hash == "" {
		return fmt.Errorf("-g requires the encrypted root password value")
	}
	actual, err := rootPasswordHash()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(actual)) != 1 {
		return fmt.Errorf("debug authentication failed")
	}
	return nil
}

func flagWasProvided(name string) bool {
	prefix := "-" + name
	for _, arg := range os.Args[1:] {
		if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
			return true
		}
	}
	return false
}

var customCommandArgs []string

func applyDefaultDurationForBareT() {
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] != "-t" {
			continue
		}
		if i+1 == len(os.Args) || strings.HasPrefix(os.Args[i+1], "-") {
			os.Args[i] = "-t=12"
		}
	}
}

// Show help
func showHelp(programName string) {
	fmt.Printf("Usage: %s [OPTIONS]\n", programName)
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Author: Nephom,Chiang (Integrated by AI)\n")
	fmt.Printf("Running without -t only shows this help menu.\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -t <hours>   Setup runtime, default is 12 hours.\n")
	fmt.Printf("  -tm <count>  Reboot exactly this many times (test mode).\n")
	fmt.Printf("  -d <secs>    Setup delay time for driver ready, default is 300 seconds.\n")
	fmt.Printf("  -s <secs>    Setup delay time for reboot, default is 300 seconds.\n")
	fmt.Printf("  -p           Stop and disable future reboots on topology, raw config, or lspci differences.\n")
	fmt.Printf("  -c <command> Run the command and all following arguments in the background on every boot; output goes to %s. LPOT options must come before -c.\n", COMMAND_USER_LOG)
	fmt.Printf("  -g <hash>    Authenticated read-only audit; never changes the host.\n")
	fmt.Printf("  -k           Show encrypted root password value.\n")
	fmt.Printf("  -r           Reset /lpot directory and clean all files.\n")
	fmt.Printf("  -scan        Scan USB/bridge/volatile devices and write /lpot/ignore_list.txt, then exit.\n")
	fmt.Printf("  -classify    Print and save the PCI link-capability report, then exit.\n")
	fmt.Printf("  -ui          Open the local read-only result dashboard.\n")
	fmt.Printf("  -h, --help   Show Help menu\n")
	fmt.Printf("\nNOTE: PCI link-capability classification and volatile-byte scanning run automatically during every -t run.\n")
	fmt.Printf("NOTE: Link classification is reported separately; raw config scanning retains devices. Optional manual exclusions use %s.\n", PCIE_FILTER_FILE)
	fmt.Printf("\nExample:\n")
	fmt.Printf("  %s -t 24 -s 600    Run reboot during 24 hours and each reboot wait for 600 seconds\n", programName)
	fmt.Printf("  %s -r              Reset /lpot directory to clean state\n", programName)
	fmt.Printf("  %s -scan           Only scan PCI devices and generate ignore bits file\n", programName)
	fmt.Printf("  %s -classify       Print and save link-capability keep/skip decisions\n", programName)
	fmt.Printf("  %s -t              Run the default 12-hour reboot test\n", programName)
	fmt.Printf("  %s -tm 2           Reboot exactly two times\n", programName)
	fmt.Printf("  %s -t 24 -c /usr/bin/ping -t 192.168.1.1    Run ping in the background on every boot\n", programName)
}

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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Dashboard failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "Suggestion: verify that localhost is available and try -ui again.")
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Startup failed: unable to resolve required Linux tools: %v\n", err)
			fmt.Fprintln(os.Stderr, "Suggestion: install pciutils and systemd tools, then run this binary on the target Linux host.")
			os.Exit(1)
		}
	}

	if debugRequested {
		if err := authenticateDebug(debugHash); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
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
	if err := compactLegacyRebootLog(REBOOT_LOG); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to compact legacy verbose lspci entries: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "Suggestion: verify that /sys/bus/pci/devices is readable and that the process is running as root.")
			os.Exit(1)
		}
		return
	}

	// -classify prints how every PCI BDF would be treated by the link-capability filter
	// and appends the same report to /lpot. It does not change host policies.
	if *classify && !tRequested {
		bdfs, err := fetchPCIBDFs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Classification failed: unable to read PCI devices: %v\n", err)
			fmt.Fprintln(os.Stderr, "Suggestion: run on Linux with PCI sysfs mounted and execute as root.")
			os.Exit(1)
		}
		ov, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Classification failed: unable to load %s: %v\n", PCIE_FILTER_FILE, err)
			fmt.Fprintln(os.Stderr, "Suggestion: fix the filter file permissions or remove it to use automatic classification.")
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Classification failed: %d PCI devices could not be verified\n", report.Unverified)
			os.Exit(1)
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

	totalRebootCycles = rebootCount

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
		fmt.Printf("DEBUG: Found %d PCI devices (full raw-config set)\n", len(bdfs))
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
		if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to publish incomplete result report: %v\n", err)
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
	skippedDevicesGlobal = skipped
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
				fmt.Fprintf(os.Stderr, "Warning: unable to publish incomplete result report: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Warning: unable to evaluate -tm cycle limit: %v\n", err)
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
	fmt.Fprintf(logFp, "%s Wait %d seconds for reboot SUT. \n", timestampStr, *waitSeconds)
	logFp.Sync()
	if !sleepInterruptible(rootCtx, time.Duration(*waitSeconds)*time.Second) {
		if err := writeResultReportWithStatus(false, "INCOMPLETE"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: unable to publish incomplete result report: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "Warning: unable to publish incomplete result report: %v\n", err)
		}
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
			if reportErr := writeResultReportWithStatus(false, "INCOMPLETE"); reportErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: unable to publish incomplete result report: %v\n", reportErr)
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
			return fmt.Errorf("generate volatile-byte ignore list: %w", err)
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
		if err := executeLspci(bdf, ".txt"); err != nil {
			return fmt.Errorf("capture current lspci snapshot for %s: %w", bdf, err)
		}
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
			if ignoreSet[normalizeBDF(bdf)] {
				continue
			}
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

		// Do not ignore a device because PCIe capability decoding failed or
		// produced an unexpected value. Raw config samples are still useful for
		// finding changed byte offsets, and lspci can report a separate mismatch
		// during link classification.

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
		// Skip devices without comparable Link Capabilities when a link filter is active so the
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

		// Whole-device ignores currently include USB controllers only.
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
	device1, err := parseDeviceFile(filePath1)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	device2, err := parseDeviceFile(filePath2)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	if device1.DeviceID != device2.DeviceID {
		return ComparisonResult{
			Error: fmt.Errorf("device IDs do not match: %s vs %s", device1.DeviceID, device2.DeviceID),
		}
	}
	if ignoreSet[normalizeBDF(device1.DeviceID)] {
		return ComparisonResult{ScannedDeviceIDs: []string{device1.DeviceID}}
	}

	return compareDevices(device1, device2, stopServiceEnabled)
}

// parseDeviceFile reads and parses a device file containing lspci output
func parseDeviceFile(filePath string) (Device, error) {
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
	currentFieldIndent := -1
	isDevLnk := false
	finishField := func() {
		if currentFieldName != "" && currentFieldValue.Len() > 0 {
			currentDevice.Capabilities.DevLnkFields[currentFieldName] = strings.TrimSpace(currentFieldValue.String())
		}
		currentFieldName = ""
		currentFieldValue.Reset()
		currentFieldIndent = -1
	}

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		indent := leadingWhitespace(rawLine)

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
			if len(line) == 0 {
				finishField()
				continue
			}
			if strings.HasPrefix(line, "Capabilities") && isDevLnk {
				finishField()
				break
			}

			isDevLnkField := (strings.HasPrefix(line, "Dev") || strings.HasPrefix(line, "Lnk")) && !strings.HasPrefix(line, "Device")
			if isDevLnkField && indent <= currentFieldIndent {
				finishField()
			}
			if isDevLnkField && (currentFieldName == "" || indent <= currentFieldIndent) {
				isDevLnk = true
				colonIndex := strings.Index(line, ":")
				if colonIndex == -1 {
					continue
				}
				fieldName := strings.TrimSpace(line[:colonIndex])
				if isComparedLspciField(fieldName) {
					currentFieldName = fieldName
					currentFieldIndent = indent
					currentFieldValue.WriteString(strings.TrimSpace(line[colonIndex+1:]))
				}
				continue
			}

			// Any deeper-indented line is a continuation, even when its text
			// contains colons (for example AtomicOpsCap: or Transmit Margin:).
			if currentFieldName != "" && indent > currentFieldIndent {
				currentFieldValue.WriteString(" " + line)
				continue
			}
			finishField()
		}
	}

	// Save the last field if exists
	finishField()

	if err := scanner.Err(); err != nil {
		return currentDevice, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return currentDevice, nil
}

func leadingWhitespace(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' && r != '\t' {
			break
		}
		count++
	}
	return count
}

func isComparedLspciField(field string) bool {
	switch field {
	case "DevCap", "DevCtl", "DevSta", "LnkCap", "LnkCtl", "LnkSta",
		"DevCap2", "DevCtl2", "LnkCtl2", "LnkSta2":
		return true
	default:
		return false
	}
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

	// Compare the union of both snapshots. A missing Dev/Lnk field is itself a
	// change; silently skipping it would hide a disappeared LnkCap or LnkSta.
	keys := make(map[string]bool, len(device1.Capabilities.DevLnkFields)+len(device2.Capabilities.DevLnkFields))
	for key := range device1.Capabilities.DevLnkFields {
		keys[key] = true
	}
	for key := range device2.Capabilities.DevLnkFields {
		keys[key] = true
	}
	orderedKeys := make([]string, 0, len(keys))
	for key := range keys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Strings(orderedKeys)
	for _, key := range orderedKeys {
		value1, exists1 := device1.Capabilities.DevLnkFields[key]
		value2, exists2 := device2.Capabilities.DevLnkFields[key]
		if exists1 && exists2 && value1 == value2 {
			continue
		}
		if !exists1 {
			value1 = "<missing>"
		}
		if !exists2 {
			value2 = "<missing>"
		}

		result.HasDifferences = true
		logEntry := fmt.Sprintf("%s %s| %s | %s changed\n",
			logTimestamp(), cycleTag(), device1.DeviceID, key)

		// Track statistics
		deviceChangeStats[device1.DeviceID]++

		// Store log entry
		result.LogEntries = append(result.LogEntries, logEntry)
		logger.Println(logEntry)
		fmt.Print(logEntry)

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
func stopAndDisableService(serviceName string) error {
	output, err := runExternal(systemctlTimeout, systemctlPath, "stop", serviceName)
	if err != nil {
		return fmt.Errorf("failed to stop service %s: %w, output: %s", serviceName, err, string(output))
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "disable", serviceName); err != nil {
		return fmt.Errorf("failed to disable service %s: %w", serviceName, err)
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
	for scanner.Scan() {
		line := scanner.Text()

		// Avoid "No devices changed" meaningless messages
		if strings.Contains(line, "No devices changed on lspci lists.") {
			continue
		}

		// Preserve every approved Dev/Lnk change, including invalid raw values
		// and mismatch details. Do not discard a record merely because its raw
		// width/speed decode looks invalid.
		if isCompactLpotscanChange(line) || strings.Contains(line, "raw/lspci mismatch") {
			fmt.Fprintln(logFp, line)
		}
	}
}

func isCompactLpotscanChange(line string) bool {
	parts := strings.Split(line, " | ")
	if len(parts) < 3 {
		return false
	}
	field := strings.TrimSpace(strings.TrimSuffix(parts[len(parts)-1], " changed"))
	return isComparedLspciField(field)
}

func compactLegacyRebootLog(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var kept []string
	changed := false
	skipVerboseBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "----- BASELINE/PREVIOUS -----") {
			skipVerboseBlock = true
			changed = true
			continue
		}
		if skipVerboseBlock {
			if strings.HasPrefix(trimmed, "=====") {
				skipVerboseBlock = false
				kept = append(kept, line)
				continue
			}
			if strings.HasPrefix(trimmed, "----- DIFF -----") {
				skipVerboseBlock = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Before:") || strings.HasPrefix(trimmed, "After:") || strings.HasPrefix(trimmed, "Differences:") {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return nil
	}
	return writeFileNoFollow(path, []byte(strings.Join(kept, "\n")), 0644)
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

// writeFilteredDevicesSection prints the compact link-classification evidence
// used to decide which devices entered both comparison paths.
func writeFilteredDevicesSection(logFile *os.File) {
	report := buildClassificationReport(classifiedDevicesGlobal)
	if report.Total == 0 {
		return
	}
	fmt.Fprintf(logFile, "\nLink Classification: %s (KEEP %d, SKIP %d, UNVERIFIED %d / %d)\n",
		report.Status, report.Kept, report.Skipped, report.Unverified, report.Total)
	for _, d := range report.Devices {
		fmt.Fprintf(logFile, "  %-12s %-12s cap=%-12s LnkCap=%-16s LnkSta=%-16s %s\n",
			d.BDF, d.Decision, d.PCIeCap, d.LinkCap, d.LinkStatus, d.Reason)
	}
}

func stabilityMessage(name string, changes int) string {
	if changes == 0 {
		return fmt.Sprintf("%s stable", name)
	}
	return fmt.Sprintf("%s changed in %d cycle(s)", name, changes)
}

func buildResultReport(checkpoint bool, statusOverride string) resultReport {
	var startedAt time.Time
	totalCycles := 0
	cyclesWithChanges := 0
	topologyChanges := 0
	lspciChanges := 0
	cycles := make(map[int]*resultCycle)
	completedCycles := make(map[int]bool)
	var cycleOrder []int
	allLogData, _ := os.ReadFile(REBOOT_LOG)
	// Every Start to test marker belongs to a reboot cycle. The report must
	// account for the complete run instead of trimming to the last cycle.
	data := allLogData
	current := 0
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if startedAt.IsZero() && strings.Contains(line, "#########Start to test#########") {
			if ts := lineTimestamp(line); ts != "" {
				startedAt, _ = time.Parse(logTimeFormat, ts)
			}
		}
		if n := lineCycleNumber(line); n > 0 {
			current = n
			if _, ok := cycles[n]; !ok {
				cycles[n] = &resultCycle{Number: n, Status: "RUNNING", Topology: "PASS", LSPCI: "PASS", ConfigSpace: "PASS"}
				cycleOrder = append(cycleOrder, n)
			}
		}
		if current == 0 {
			continue
		}
		cycle := cycles[current]
		if ts := lineTimestamp(line); ts != "" {
			if cycle.StartedAt == "" {
				cycle.StartedAt = ts
			}
		}
		if strings.Contains(line, "===== Cycle") && strings.Contains(line, " END (") {
			completedCycles[current] = true
			cycle.FinishedAt = lineTimestamp(line)
			if strings.Contains(line, "changes detected") {
				cycle.Status = "FAIL"
			} else if strings.Contains(line, "config noise") {
				cycle.Status = "INFO"
			} else {
				cycle.Status = "PASS"
			}
		}
		if strings.Contains(line, "NEW Device:") || strings.Contains(line, "REMOVED Device:") {
			cycle.Topology = "FAIL"
			problem := resultProblem{Severity: "FAIL", Category: "TOPOLOGY", Cycle: current, Timestamp: lineTimestamp(line), Message: line}
			if strings.Contains(line, "NEW Device:") {
				problem.BDF = parseBDFAfterMarker(line, "NEW Device:")
			} else {
				problem.BDF = parseBDFAfterMarker(line, "REMOVED Device:")
			}
			problem.DetailsLog = REBOOT_LOG
			cycle.Events = append(cycle.Events, problem)
		}
		if strings.Contains(line, "Had devices changed") {
			cycle.LSPCI = "FAIL"
			cycle.Status = "FAIL"
			problem := resultProblem{Severity: "FAIL", Category: "LSPCI", Cycle: current, Timestamp: lineTimestamp(line), Message: "lspci capability changes detected", DetailsLog: LPOTSCAN_LOG}
			cycle.Events = append(cycle.Events, problem)
		}
	}
	for _, cycle := range cycles {
		totalCycles++
		if cycle.Topology == "FAIL" {
			topologyChanges++
		}
		if cycle.LSPCI == "FAIL" {
			lspciChanges++
		}
		if cycle.Status == "FAIL" {
			cyclesWithChanges++
		}
	}

	configChanges := parseConfigResultChanges()
	cycleSets := make(map[string]map[int]struct{})
	for _, change := range configChanges {
		key := change.device + "\x00" + change.offset
		if cycleSets[key] == nil {
			cycleSets[key] = make(map[int]struct{})
		}
		cycleSets[key][change.cycle] = struct{}{}
	}
	configProblems := make([]resultProblem, 0, len(configChanges))
	noteworthyConfig := 0
	benignConfig := 0
	noteworthyPatterns := make(map[string]bool)
	benignPatterns := make(map[string]bool)
	for _, change := range configChanges {
		ratio := 0.0
		completedCount := len(completedCycles)
		if completedCount > 0 {
			ratio = float64(len(cycleSets[change.device+"\x00"+change.offset])) / float64(completedCount)
		}
		severity := "INFO"
		classification := "benign reboot-fixed register reset"
		if ratio < 0.80 {
			severity = "NOTICE"
			classification = "noteworthy config-space change"
			noteworthyPatterns[change.device+"\x00"+change.offset] = true
		} else {
			benignPatterns[change.device+"\x00"+change.offset] = true
		}
		problem := resultProblem{
			Severity: severity, Category: "CONFIG_SPACE", Cycle: change.cycle,
			Timestamp: change.timestamp, BDF: change.device,
			Message:    fmt.Sprintf("%s at %s changed from %s to %s (%s)", classification, change.offset, change.before, change.after, formatRatio(ratio)),
			DetailsLog: CONFIG_CHANGES_LOG,
		}
		configProblems = append(configProblems, problem)
		if cycle := cycles[change.cycle]; cycle != nil {
			if severity == "NOTICE" {
				cycle.ConfigSpace = "NOTICE"
				if cycle.Status == "PASS" {
					cycle.Status = "NOTICE"
				}
			} else if cycle.ConfigSpace == "PASS" {
				cycle.ConfigSpace = "INFO"
				if cycle.Status == "PASS" {
					cycle.Status = "INFO"
				}
			}
			cycle.Events = append(cycle.Events, problem)
		}
	}
	noteworthyConfig = len(noteworthyPatterns)
	benignConfig = len(benignPatterns)

	sort.Ints(cycleOrder)
	orderedCycles := make([]resultCycle, 0, len(cycleOrder))
	problems := make([]resultProblem, 0, len(configProblems))
	for _, number := range cycleOrder {
		cycle := *cycles[number]
		orderedCycles = append(orderedCycles, cycle)
		problems = append(problems, cycle.Events...)
	}
	if len(problems) == 0 {
		problems = configProblems
	}
	status := "RUNNING"
	message := "Test continues after reboot"
	if !checkpoint {
		if totalCycles == 0 {
			status = "INCOMPLETE"
			message = "No completed reboot cycle was recorded"
		} else if cyclesWithChanges > 0 {
			status = "FAIL"
			message = "Noteworthy PCI topology, lspci, or config-space changes were detected"
		} else if noteworthyConfig > 0 {
			status = "PASS"
			message = "PCI topology and lspci capability are stable; config-space notices require review"
		} else {
			status = "PASS"
			message = "PCI topology, lspci capability, and PCI config are stable"
		}
	}
	if statusOverride != "" {
		status = statusOverride
		message = "Test stopped before the planned reboot cycle completed"
	}
	completed := 0
	failed := 0
	for _, cycle := range orderedCycles {
		if completedCycles[cycle.Number] {
			completed++
		}
		if cycle.Status == "FAIL" {
			failed++
		}
	}
	runID := startedAt.Format(time.RFC3339)
	if startedAt.IsZero() {
		runID = time.Now().Format(time.RFC3339)
	}
	result := resultReport{
		SchemaVersion: 1, Version: version, RunID: runID, Status: status,
		Checkpoint: checkpoint, Message: message, UpdatedAt: time.Now().Format(time.RFC3339),
		TotalCycles: totalCycles, CompletedCycles: completed,
		SuccessfulCycles: completed - failed, FailedCycles: failed,
		Classification: classificationReportFromBaseline(),
		Checks: resultChecks{
			Topology:    resultCheck{Status: resultStatus(topologyChanges), ChangedCycles: topologyChanges, Message: stabilityMessage("topology", topologyChanges)},
			LSPCI:       resultCheck{Status: resultStatus(lspciChanges), ChangedCycles: lspciChanges, Message: stabilityMessage("Dev/Lnk", lspciChanges)},
			ConfigSpace: resultCheck{Status: configSpaceResultStatus(noteworthyConfig), Noteworthy: noteworthyConfig, Message: configSpaceStabilityMessage(noteworthyConfig)},
			ConfigNoise: resultCheck{Status: resultInfoStatus(benignConfig), BenignChanges: benignConfig, Message: fmt.Sprintf("%d recurring benign register change(s)", benignConfig)},
		},
		Cycles: orderedCycles, Problems: problems,
		Artifacts: map[string]string{"result": RESULT_FILE, "summary": REBOOT_LOG, "lspci": LPOTSCAN_LOG, "config_space": CONFIG_CHANGES_LOG},
	}
	if !startedAt.IsZero() {
		result.StartedAt = startedAt.Format(time.RFC3339)
	}
	if !checkpoint {
		result.FinishedAt = time.Now().Format(time.RFC3339)
	}
	return result
}

func configSpaceResultStatus(notices int) string {
	if notices > 0 {
		return "NOTICE"
	}
	return "PASS"
}

func configSpaceStabilityMessage(notices int) string {
	if notices > 0 {
		return fmt.Sprintf("raw config has %d notice pattern(s) requiring review", notices)
	}
	return "raw config stable"
}

func classificationReportFromBaseline() classificationReport {
	data, err := os.ReadFile(CLASSIFY_STATE_FILE)
	if err != nil {
		return classificationReport{Status: "UNVERIFIED"}
	}
	var snapshot classificationSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil || len(snapshot.Devices) == 0 {
		return classificationReport{Status: "UNVERIFIED"}
	}
	report := classificationReport{Status: "PASS", Total: len(snapshot.Devices)}
	for _, encoded := range snapshot.Devices {
		var device classificationDevice
		if err := json.Unmarshal([]byte(encoded), &device); err != nil {
			report.Status = "UNVERIFIED"
			report.Unverified++
			continue
		}
		report.Devices = append(report.Devices, device)
		switch device.Decision {
		case "KEEP":
			report.Kept++
		case "SKIP":
			report.Skipped++
		}
		if device.Verification != "VERIFIED" {
			report.Unverified++
			report.Status = "UNVERIFIED"
		}
	}
	sort.Slice(report.Devices, func(i, j int) bool { return report.Devices[i].BDF < report.Devices[j].BDF })
	return report
}

func writeResultReportWithStatus(checkpoint bool, statusOverride string) error {
	result := buildResultReport(checkpoint, statusOverride)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result report: %w", err)
	}
	data = append(data, '\n')
	if err := verifyRootRegularFileIfPresent(RESULT_FILE); err != nil {
		return err
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", RESULT_FILE, os.Getpid())
	if err := writeFileNoFollow(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temporary result report: %w", err)
	}
	f, err := os.OpenFile(tmpPath, os.O_WRONLY, 0644)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("open temporary result report: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync temporary result report: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temporary result report: %w", err)
	}
	if err := os.Rename(tmpPath, RESULT_FILE); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("publish result report: %w", err)
	}
	return nil
}

func writeResultReport(checkpoint bool) error {
	return writeResultReportWithStatus(checkpoint, "")
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LPOT Test Dashboard</title>
<style>
:root { color-scheme: dark; --bg:#10151d; --panel:#18212d; --line:#2b3a4d; --text:#e7edf5; --muted:#9eacbd; --green:#43d17c; --red:#ff6b6b; --yellow:#f4c95d; --blue:#6eb6ff; }
* { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
main { max-width:1280px; margin:0 auto; padding:28px 20px 60px; } h1,h2 { margin:0; } h1 { font-size:28px; letter-spacing:.02em; } h2 { font-size:16px; margin-bottom:14px; }
.sub { color:var(--muted); margin:4px 0 24px; } .hero,.panel { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px; }
.hero { display:flex; align-items:center; justify-content:space-between; gap:20px; margin-bottom:18px; } .status { font-size:30px; font-weight:800; letter-spacing:.06em; }
 .PASS,.KEEP { color:var(--green); } .FAIL,.UNVERIFIED { color:var(--red); } .INFO,.NOTICE,.RUNNING { color:var(--yellow); } .INCOMPLETE,.SKIP { color:var(--blue); }
.reason { color:var(--muted); text-align:right; max-width:560px; } .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }
.metric { background:#121a24; border:1px solid var(--line); border-radius:10px; padding:14px; } .metric b { display:block; font-size:22px; } .metric span { color:var(--muted); }
.columns { display:grid; grid-template-columns:1fr 1.35fr; gap:18px; margin-bottom:18px; } .check { display:flex; justify-content:space-between; border-bottom:1px solid var(--line); padding:10px 0; } .check:last-child { border:0; }
 .table-wrap { overflow:auto; } table { border-collapse:collapse; width:100%; min-width:680px; } th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; } th { color:var(--muted); font-weight:600; }
 select { background:#121a24; color:var(--text); border:1px solid var(--line); border-radius:6px; padding:7px 10px; margin-bottom:10px; } .empty { color:var(--muted); padding:12px 0; }
 .help-button { float:right; width:28px; height:28px; border:1px solid var(--blue); border-radius:50%; background:transparent; color:var(--blue); font-weight:800; cursor:pointer; }
 .help-backdrop { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; padding:20px; background:rgba(0,0,0,.7); z-index:10; }
 .help-backdrop[hidden] { display:none; }
 .help-dialog { max-width:680px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:22px; box-shadow:0 18px 60px rgba(0,0,0,.45); }
 .help-dialog h2 { margin-bottom:12px; } .help-dialog p { color:var(--muted); } .help-dialog code { color:var(--text); }
 .help-close { float:right; border:0; background:transparent; color:var(--muted); font-size:20px; cursor:pointer; }
 .config-button { display:inline-block; padding:4px 8px; border:1px solid var(--blue); border-radius:5px; color:var(--blue); text-decoration:none; white-space:nowrap; }
 .config-button.disabled { border-color:var(--line); color:var(--muted); opacity:.55; cursor:not-allowed; }
a { color:var(--blue); } code { color:#cbd8e8; } @media (max-width:800px) { .hero { display:block; } .reason { text-align:left; margin-top:10px; } .grid { grid-template-columns:repeat(2,1fr); } .columns { grid-template-columns:1fr; } }
</style></head>
<body><main>
<div class="hero"><div><h1>LPOT PCIe Stability Test</h1><div class="sub" id="run">Loading result...</div></div><div class="status" id="status">...</div><div class="reason" id="reason"></div></div>
<div class="grid" id="metrics"></div>
<div class="columns"><section class="panel"><h2>Checks</h2><div id="checks"></div></section><section class="panel"><h2>Run Information</h2><div id="info"></div></section></div>
<section class="panel" style="margin-bottom:18px"><h2>PCIe Link Evidence <button class="help-button" id="linkHelp" title="Explain PCIe link fields">?</button></h2><div class="sub">Source: sysfs raw PCI configuration space. lspci capability comparison is shown separately in Checks.</div><div class="table-wrap" id="classificationDevices"></div></section>
 <section class="panel" style="margin-bottom:18px"><h2>Problems and Events</h2><select id="severity"><option value="ALL">All severities</option><option value="FAIL">FAIL only</option><option value="NOTICE">NOTICE only</option><option value="INFO">INFO only</option></select><div class="table-wrap" id="problems"></div></section>
<section class="panel" style="margin-bottom:18px"><h2>Artifacts</h2><div id="artifacts"></div></section>
<section class="panel"><h2>Cycle Timeline</h2><div class="table-wrap" id="cycles"></div></section>
<div class="help-backdrop" id="linkHelpDialog" hidden><div class="help-dialog" role="dialog" aria-modal="true" aria-labelledby="linkHelpTitle"><button type="button" class="help-close" id="linkHelpClose" aria-label="Close" onclick="document.getElementById('linkHelpDialog').hidden=true; return false;">x</button><h2 id="linkHelpTitle">PCIe Link Field Guide</h2><p><b>PCIe Cap</b> means the PCI Express capability was found in the raw PCI configuration space. The value is the capability offset, not a speed or bandwidth.</p><p><b>LnkCap (Max)</b> is the link capability advertised by the device: the maximum supported link speed and width, such as <code>16GT/s x16</code>.</p><p><b>LnkSta (Current)</b> is the currently negotiated link speed and width, such as <code>8GT/s x8</code>. <code>NO LINK</code> means no active width or speed was reported. An invalid width code is not treated as a usable link.</p><p>The table values come from sysfs raw PCI configuration bytes. The lspci check separately compares the selected <code>Dev*</code> and <code>Lnk*</code> capability fields.</p></div></div>
</main><script>
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge = s => '<b class="'+esc(s)+'">'+esc(s)+'</b>';
function render(d) {
  const status = document.getElementById('status'); status.className='status '+esc(d.status); status.textContent=d.status;
  document.getElementById('reason').textContent=d.message||'';
  document.getElementById('run').textContent='Run '+(d.run_id||'unknown')+' | Updated '+(d.updated_at||'unknown');
  document.getElementById('metrics').innerHTML=[['Total cycles',d.total_cycles],['Completed',d.completed_cycles],['Successful',d.successful_cycles],['Failed',d.failed_cycles]].map(x=>'<div class="metric"><b>'+esc(x[1])+'</b><span>'+x[0]+'</span></div>').join('');
  const checks=[['Topology',d.checks?.topology],['lspci',d.checks?.lspci],['Config space',d.checks?.config_space],['Config noise',d.checks?.config_noise]];
  document.getElementById('checks').innerHTML=checks.map(x=>'<div class="check"><span>'+x[0]+'<small style="display:block;color:var(--muted)">'+esc(x[1]?.message||'')+'</small></span>'+badge(x[1]?.status||'UNKNOWN')+'</div>').join('');
  document.getElementById('info').innerHTML='<div class="check"><span>Started</span><code>'+esc(d.started_at||'-')+'</code></div><div class="check"><span>Finished</span><code>'+esc(d.finished_at||'-')+'</code></div><div class="check"><span>Checkpoint</span><code>'+esc(d.checkpoint)+'</code></div>';
  const cl=d.classification||{};
  const devices=cl.devices||[]; document.getElementById('classificationDevices').innerHTML=devices.length?'<table><thead><tr><th>BDF</th><th>Decision</th><th>PCIe Cap</th><th>Raw LnkCap</th><th>Raw LnkSta</th><th>lspci LnkCap</th><th>lspci LnkSta</th><th>Config Space</th><th>Reason</th></tr></thead><tbody>'+devices.map(x=>{const keep=x.decision==='KEEP'; const view=keep?'<a class="config-button" href="/api/config?bdf='+encodeURIComponent(x.bdf)+'" target="_blank" rel="noopener">View</a>':'<span class="config-button disabled" aria-disabled="true">View</span>'; return '<tr><td><code>'+esc(x.bdf)+'</code></td><td>'+badge(x.decision||'UNKNOWN')+'</td><td>'+esc(x.pcie_capability||'-')+'</td><td>'+esc(x.link_capability||'-')+'</td><td>'+esc(x.link_status||'-')+'</td><td>'+esc(x.lspci_link_capability||'-')+'</td><td>'+esc(x.lspci_link_status||'-')+'</td><td>'+view+'</td><td>'+esc(x.reason||x.verification||'-')+'</td></tr>'}).join('')+'</tbody></table>':'<div class="empty">No classification data.</div>';
  const filter=document.getElementById('severity').value; const problems=(d.problems||[]).filter(p=>filter==='ALL'||p.severity===filter);
  document.getElementById('problems').innerHTML=problems.length?'<table><thead><tr><th>Severity</th><th>Category</th><th>Cycle</th><th>Device</th><th>Message</th><th>Log</th></tr></thead><tbody>'+problems.map(p=>'<tr><td>'+badge(p.severity)+'</td><td>'+esc(p.category)+'</td><td>'+esc(p.cycle)+'</td><td>'+esc(p.bdf||'-')+'</td><td>'+esc(p.message)+'</td><td><code>'+esc(p.details_log||'-')+'</code></td></tr>').join('')+'</tbody></table>':'<div class="empty">No matching problems.</div>';
  document.getElementById('artifacts').innerHTML=Object.entries(d.artifacts||{}).map(([name,path])=>'<div class="check"><span>'+esc(name)+'</span><a href="/api/log?name='+encodeURIComponent(name)+'" target="_blank">'+esc(path)+'</a></div>').join('')||'<div class="empty">No artifacts.</div>';
  const cycles=d.cycles||[]; document.getElementById('cycles').innerHTML=cycles.length?'<table><thead><tr><th>Cycle</th><th>Status</th><th>Topology</th><th>lspci</th><th>Config</th><th>Events</th></tr></thead><tbody>'+cycles.slice().reverse().map(c=>'<tr><td>'+String(c.number).padStart(3,'0')+'</td><td>'+badge(c.status)+'</td><td>'+badge(c.topology)+'</td><td>'+badge(c.lspci)+'</td><td>'+badge(c.config_space)+'</td><td>'+esc((c.events||[]).length)+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No completed cycles.</div>';
}
document.getElementById('severity').addEventListener('change',()=>window.current&&render(window.current));
const linkHelp=document.getElementById('linkHelpDialog'); document.getElementById('linkHelp').addEventListener('click',()=>linkHelp.hidden=false); document.getElementById('linkHelpClose').addEventListener('click',()=>linkHelp.hidden=true); linkHelp.addEventListener('click',e=>{if(e.target===linkHelp)linkHelp.hidden=true}); document.addEventListener('keydown',e=>{if(e.key==='Escape')linkHelp.hidden=true});
fetch('/api/result',{cache:'no-store'}).then(r=>r.json()).then(d=>{window.current=d;render(d)}).catch(e=>{document.getElementById('reason').textContent='Unable to load /lpot/result.json: '+e});
</script></body></html>`

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
	classification := classificationReportFromBaseline()
	rawConfigStatus := "STABLE"
	if cyclesWithConfigChanges > 0 {
		rawConfigStatus = "CHANGED"
	}
	lspciStatus := "STABLE"
	if actualLspciChanges > 0 {
		lspciStatus = "CHANGED"
	}
	fmt.Fprintf(logFile, "\nValidation Coverage:\n")
	fmt.Fprintf(logFile, "  PCIe Link-capable devices: KEEP %d / SKIP %d / UNVERIFIED %d\n",
		classification.Kept, classification.Skipped, classification.Unverified)
	fmt.Fprintf(logFile, "  Raw config-space comparison: %s\n", rawConfigStatus)
	fmt.Fprintf(logFile, "  lspci Dev/Lnk comparison: %s\n", lspciStatus)
	if classification.Unverified > 0 {
		fmt.Fprintf(logFile, "  WARNING: classification evidence is incomplete; PASS is not trustworthy\n")
	}

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

	// Link classification section: lists every BDF the link filter dropped
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
		fmt.Fprintf(logFile, "\nTest Result: COMPLETED WITH NOTICE\n")
		fmt.Fprintf(logFile, "Device topology and lspci capability were stable across %d reboot cycles; irregular config-space changes require review (see 'Noteworthy changes' above).\n", actualTotalCycles)
	default:
		fmt.Fprintf(logFile, "\nTest Result: COMPLETED - REVIEW NOTEWORTHY CHANGES\n")
		fmt.Fprintf(logFile, "Device topology and/or capability changes were detected across %d reboot cycles (see 'Affected Cycles' above).\n", actualTotalCycles)
	}
	fmt.Fprintf(logFile, "==========================================\n")
	if err := writeResultReport(false); err != nil {
		fatalOperation("Finalization failed: cannot publish /lpot/result.json", err,
			"check /lpot permissions and available disk space before reviewing the report")
	}

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
