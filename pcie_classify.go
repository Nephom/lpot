package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

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
		return pciDeviceInfo{}, false
	}
	return pciDeviceInfo{
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
// filter and the -classify report. KeptReason is set only for kept
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

// filterClassifiedEndpoints partitions bdfs into the BDFs classifyDevices()
// marked KEEP (link-capable, i.e. comparable via lspci Dev/Lnk fields) versus
// SKIP (bridges, legacy PCI, manually excluded, or unverified), using an
// already-computed classification report. This is the KEEP/SKIP filter used
// everywhere in the pipeline (main.go's endpointFilterSet construction,
// -classify's report, and the -tm/-t startup path).
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
// flag and by the post-test summary so users see exactly the same view.
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

// configDumpKindSuffix maps a dump kind to its filename suffix.
// "baseline" is the one-time initial snapshot (see persistClassificationConfigDumps);
// "latest" is refreshed every cycle.
func configDumpKindSuffix(kind string) (string, error) {
	switch kind {
	case "baseline":
		return "_baseline.txt", nil
	case "latest", "":
		return "_latest.txt", nil
	default:
		return "", fmt.Errorf("invalid config dump kind %q", kind)
	}
}

// configDumpPath returns the on-disk path for a device's raw config-space
// dump. kind selects "baseline" (captured once, never overwritten) or
// "latest" (refreshed every cycle); an empty kind means "latest" for
// backward compatibility with callers that don't care about the baseline.
func configDumpPath(bdf, kind string) (string, error) {
	normalized := normalizeBDF(bdf)
	if !shortBDFRegex.MatchString(normalized) && !bdfRegex.MatchString(normalized) {
		return "", fmt.Errorf("invalid PCI BDF %q", bdf)
	}
	suffix, err := configDumpKindSuffix(kind)
	if err != nil {
		return "", err
	}
	return filepath.Join(CONFIG_DUMP_DIR, normalized+suffix), nil
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

// persistClassificationConfigDumps writes /lpot/config_dump/<bdf>_latest.txt
// for every KEEP device on every cycle (overwritten each time, same as
// before), and additionally captures /lpot/config_dump/<bdf>_baseline.txt
// exactly once per device -- the first cycle that device is KEEP and
// readable -- and never overwrites it again. This gives the dashboard a
// stable "initial config space" page to compare the latest snapshot and the
// pci-config-changes.log diffs against, which a constantly-overwritten
// single file could never provide.
func persistClassificationConfigDumps(decisions []deviceClassification) error {
	if err := os.MkdirAll(CONFIG_DUMP_DIR, 0755); err != nil {
		return fmt.Errorf("create %s: %w", CONFIG_DUMP_DIR, err)
	}
	entries, err := os.ReadDir(CONFIG_DUMP_DIR)
	if err != nil {
		return fmt.Errorf("read %s: %w", CONFIG_DUMP_DIR, err)
	}
	for _, entry := range entries {
		// Only clear the "latest" snapshots; "_baseline.txt" files must
		// survive for the lifetime of the test.
		if strings.HasSuffix(entry.Name(), "_latest.txt") {
			if err := os.Remove(filepath.Join(CONFIG_DUMP_DIR, entry.Name())); err != nil {
				return fmt.Errorf("clear config dump %s: %w", entry.Name(), err)
			}
		}
	}
	for _, decision := range decisions {
		if !decision.Kept || !decision.InfoOK {
			continue
		}
		cfg := readSysfsConfig(decision.BDF, 256)
		if len(cfg) == 0 {
			continue
		}
		dump := []byte(formatConfigDump(cfg))

		latestPath, err := configDumpPath(decision.BDF, "latest")
		if err != nil {
			return err
		}
		if err := writeFileNoFollow(latestPath, dump, 0644); err != nil {
			return fmt.Errorf("write latest config dump for %s: %w", decision.BDF, err)
		}

		baselinePath, err := configDumpPath(decision.BDF, "baseline")
		if err != nil {
			return err
		}
		if !fileExists(baselinePath) {
			if err := writeFileNoFollow(baselinePath, dump, 0644); err != nil {
				return fmt.Errorf("write baseline config dump for %s: %w", decision.BDF, err)
			}
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
				// A classification change (e.g. KEEP -> SKIP, or an LnkCap value
				// shift) is a real topology/link-capability difference, exactly
				// like the NEW/REMOVED Device handling in processPCIDevices().
				// Without this, the change was written to reboot.log but never
				// entered changedCycles, so it was invisible to the cycle-end
				// banner, writeAffectedCyclesSection, and the -p stop-on-
				// difference gate — a genuinely noteworthy event that could
				// silently pass through an entire -p run.
				for _, decision := range changed {
					reason := decision.KeptReason + decision.SkipReason
					recordCycleChange(fmt.Sprintf("PCIe classification changed for %s: now %s (%s)", decision.BDF, decisionLabel(decision), reason))
				}
			}
			for _, bdf := range removed {
				fmt.Fprintf(logFp, "%s Removed: %s\n", getCurrentTimestamp(), bdf)
				recordCycleChange(fmt.Sprintf("PCIe classification entry removed for %s", bdf))
			}
		}
	}
	return nil
}

// decisionLabel renders a deviceClassification's KEEP/SKIP decision for the
// recordCycleChange reason string above.
func decisionLabel(d deviceClassification) string {
	if d.Kept {
		return "KEEP"
	}
	return "SKIP"
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
