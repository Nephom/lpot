package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PCIDeviceInfo stores key information about a PCI device
type PCIDeviceInfo struct {
	BusID             string
	VendorID          uint16
	DeviceID          uint16
	SubsystemVendorID uint16
	SubsystemID       uint16
	ConfigData        []byte // Store raw config data for comparison
	// Truncated is true when ConfigData was shorter than the 64-byte minimum
	// PCI header, so VendorID/DeviceID above are zero-valued placeholders
	// rather than a real "vendor 0000 device 0000" device. Callers must check
	// this before printing VendorID/DeviceID so a read failure is never
	// mistaken for a genuine (and vanishingly rare) all-zero device ID.
	Truncated bool
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

// timerRelatedOffsets is a hardcoded fallback list of known timer/counter
// registers. It overlaps by design with the auto-detected volatile bytes
// produced by detectVolatileBytesWithSamples() (which is always run before
// every -t cycle's comparison as of the auto-scan-on-every-run change in
// main()) and persisted into ignore_list.txt (read back as timerPatterns in
// compareAndLogDeviceChanges). This hardcoded set exists only as a safety net
// for the narrow window where a comparison could run against a fresh
// initial.bin before an auto-scan has ever completed for this device (e.g. a
// first cycle interrupted between initial.bin creation and the scan step);
// once ignore_list.txt reflects that device, these entries are redundant
// with the auto-detected ones for the same offsets, not a competing source
// of truth.
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

// scanAndGenerateIgnoreBits scans PCI devices and generates ignore bits file.
// logFp is optional (nil when called from the standalone -scan flag, which
// has no open reboot.log); when present, per-device sample/read anomalies are
// also written there instead of being visible only on stdout.
func scanAndGenerateIgnoreBits(logFp *os.File) error {
	timestamp := getCurrentTimestamp()
	fmt.Printf("%s Starting volatile byte detection (this will take about 5 seconds)...\n", timestamp)

	ignoreBits, _, err := detectVolatileBytesWithSamples(logFp)
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
func runConfigScan(logFp *os.File) error {
	initialFile := INITIAL_BIN_FILE

	// Check if ignore_list.txt exists, if not run scan first
	if !fileExists(IGNORE_LIST_FILE) {
		if err := scanAndGenerateIgnoreBits(logFp); err != nil {
			return fmt.Errorf("generate volatile-byte ignore list: %w", err)
		}
	}

	// Check if initial.bin exists
	if !fileExists(initialFile) {
		timestamp := getCurrentTimestamp()
		fmt.Printf("%s Initial PCI config not found, creating %s\n", timestamp, initialFile)

		failedBDFs, err := savePCIConfigReportingFailures(initialFile)
		if err != nil {
			return fmt.Errorf("error saving initial PCI config: %v", err)
		}
		logSavePCIConfigFailures(logFp, failedBDFs)
		fmt.Printf("%s Initial PCI config saved.\n", timestamp)
		return nil
	}

	// Compare initial snapshot against freshly-sampled stable config
	timestamp := getCurrentTimestamp()
	fmt.Printf("%s Comparing PCI configs...\n", timestamp)
	return compareDeviceConfigs(initialFile, CONFIG_CHANGES_LOG, logFp)
}

// logSavePCIConfigFailures writes one reboot.log warning line per BDF whose
// /sys/.../config read failed during a raw config-space snapshot, so the
// device a user most needs to investigate is never silently absent from
// every persisted artifact (previously these failures were stdout-only).
func logSavePCIConfigFailures(logFp *os.File, failedBDFs []string) {
	if logFp == nil || len(failedBDFs) == 0 {
		return
	}
	for _, entry := range failedBDFs {
		logWarnFp(logFp, "could not read raw PCI config space for %s; this device is excluded from config-space comparison this cycle", entry)
	}
}

// detectVolatileBytesWithSamples detects frequently changing bytes and returns sample data.
// logFp is optional (nil from the standalone -scan flag); when present, both
// per-device sample-read failures and devices that dropped out of one or more
// of the 5 samples are additionally logged there.
func detectVolatileBytesWithSamples(logFp *os.File) (map[string]DeviceIgnoreBits, []map[string][]byte, error) {
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
	sampleFailedSet := make(map[string]bool)
	for i, tmpFile := range tmpFiles {
		fmt.Printf("Collecting sample %d/%d...\n", i+1, len(tmpFiles))
		failedBDFs, err := savePCIConfigReportingFailures(tmpFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create sample %d: %v", i+1, err)
		}
		for _, entry := range failedBDFs {
			sampleFailedSet[entry] = true
		}

		if i < len(tmpFiles)-1 {
			time.Sleep(1 * time.Second)
		}
	}
	if len(sampleFailedSet) > 0 {
		failedList := make([]string, 0, len(sampleFailedSet))
		for entry := range sampleFailedSet {
			failedList = append(failedList, entry)
		}
		sort.Strings(failedList)
		logSavePCIConfigFailures(logFp, failedList)
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

		if !validDevice {
			// This device did not appear in every one of the 5 samples (e.g. a
			// flapping link that briefly drops out of sysfs). It is skipped here
			// silently before this fix, meaning it never entered ignore_list.txt
			// and later per-cycle byte comparisons had no volatile-byte baseline
			// for it, risking false-positive "changed" reports. Recording it
			// explicitly lets the operator know this device's stability could
			// not be assessed by this scan.
			if logFp != nil {
				logWarnFp(logFp, "device %s was missing from one or more of the %d volatile-byte detection samples; its ignore-bits could not be computed this scan", normalizeBDF(busID), sampleCount)
			} else {
				fmt.Printf("Warning: device %s was missing from one or more of the %d volatile-byte detection samples; its ignore-bits could not be computed this scan\n", normalizeBDF(busID), sampleCount)
			}
			continue
		}

		// Do not ignore a device because PCIe capability decoding failed or
		// produced an unexpected value. Raw config samples are still useful for
		// finding changed byte offsets, and lspci can report a separate mismatch
		// during link classification.

		// Check if it's a USB Controller. Keep this explicit classification in
		// the record for readable diagnostics even though IgnoreDevice is the
		// field consumed by saveIgnoreBits.
		// Reading index 11 requires a slice of length >= 12, not >= 11: the
		// previous ">= 11" bound let a device whose config read returned
		// exactly 11 bytes reach deviceData[0][11] and panic with an
		// index-out-of-range, aborting the entire -scan/auto-scan for every
		// device instead of just skipping this one malformed read.
		if len(deviceData[0]) >= 12 {
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

// savePCIConfigReportingFailures saves PCI configuration space to file.
// It additionally returns the list of BDFs whose /sys/.../config read
// failed, so callers that have a log file open (runConfigScan, via main())
// can write an explicit reboot.log line naming the affected BDF and reason
// instead of the failure being visible only on stdout — previously the only
// trace of a per-device read failure, which meant the exact device a user
// most needed to investigate left no mark in any persisted artifact.
func savePCIConfigReportingFailures(outputFile string) ([]string, error) {
	pciPath := SYS_PCI_DEVICES
	files, err := os.ReadDir(pciPath)
	if err != nil {
		return nil, err
	}

	var failedBDFs []string
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
			failedBDFs = append(failedBDFs, fmt.Sprintf("%s (%v)", normalizeBDF(busID), err))
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
		writeDeviceConfigXXD(&buffer, normalizeBDF(busID), configData)
	}
	if err := writeFileNoFollow(outputFile, buffer.Bytes(), 0644); err != nil {
		return failedBDFs, err
	}
	return failedBDFs, nil
}

// writeDeviceConfigXXD appends one device's raw config bytes to buffer in
// the XXD-like format splitDevices() parses back: a "# <short-bdf>" header
// followed by 16-byte hex/ASCII rows. Currently called only from
// savePCIConfigReportingFailures(), which writes the immutable INITIAL_BIN_FILE
// baseline exactly once (when it does not yet exist) and every cycle's
// current-snapshot temp file; initial.bin itself is never rewritten again
// after that first write (Issue #21: the raw config-space baseline, like the
// lspci and classification baselines, must stay fixed for the run's lifetime).
func writeDeviceConfigXXD(buffer *bytes.Buffer, shortBDF string, configData []byte) {
	buffer.WriteString(fmt.Sprintf("# %s\n", shortBDF))
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

// splitDevices splits device data from XXD-like format
func splitDevices(data []byte) map[string][]byte {
	devices := make(map[string][]byte)
	// Every device section in this format (see writeDeviceConfigXXD) starts
	// with a "# <bdf>" header line. bytes.Split on "\n# " strips that "# "
	// prefix from every section EXCEPT the very first one in the file,
	// because the first section has no preceding "\n" for the separator to
	// match against — its header line still reads literally "# <bdf>".
	// Trimming a single leading "# " from the whole input before splitting
	// makes every section (including the first) go through bytes.Split with
	// the identical "\n# " separator shape, so lines[0] is the same "<bdf>"
	// text in every section instead of "# <bdf>" for the first one only.
	// Without this, the first device recorded in ANY XXD-format file
	// (initial.bin, a -scan sample, a config_dump snapshot) had its BusID
	// parsed as the literal string "# <bdf>", which never matches
	// normalizeBDF()/bdfRegex, silently breaking every map lookup keyed by
	// that device's BDF for the first device in the file — including
	// making it look like a permanently NEW device every cycle relative to
	// any other device recorded in the same file.
	trimmed := bytes.TrimPrefix(data, []byte("# "))
	deviceSections := bytes.Split(trimmed, []byte("\n# "))
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
	buffer.WriteString("# Generated at: " + getCurrentTimestamp() + "\n")
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
//
// Baseline immutability (Issue #21): initialFile (initial.bin) is the
// one-time, immutable raw config-space baseline for the lifetime of the
// run. initialDevices (parsed from it) is NEVER written back to disk by
// this function — a device going absent does not erase its baseline entry,
// and a device reappearing does not adopt a new baseline. Present/absent
// transition dedup for the human-readable log and recordCycleChange is
// instead tracked in topologyState (device_state.go, "rawconfig"
// namespace), completely independent of the baseline file's contents.
//
// Read-failure handling (Issue #23): a baselined BDF that is still
// enumerated in sysfs (pciDeviceEnumeratedInSysfs, a direct os.Stat check —
// NOT this cycle's link classification, which can drop a still-present
// device for one bad cycle) but has no stable sample this cycle is
// distinguished from one that has genuinely left sysfs, and reported as
// UNAVAILABLE (NOTICE severity, retried by collectStableConfig's own
// sampling) rather than REMOVED.
func compareDeviceConfigs(initialFile, reportFile string, logFp *os.File) error {
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
	stableConfigs, sampleFailedBDFs, err := collectStableConfig(3, 200)
	if err != nil {
		return fmt.Errorf("failed to collect stable config: %v", err)
	}
	logSavePCIConfigFailures(logFp, sampleFailedBDFs)

	logFile, err := openSecureAppend(reportFile, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	initialDevices := splitDevices(initialData)

	timestamp := getCurrentTimestamp()
	fmt.Printf("%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))
	fmt.Fprintf(logFile, "%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))

	// Track if any NOTICE-or-worse config change is found in this cycle, so
	// the final recordCycleNoise/recordCycleNotice call below (Issue #25)
	// picks the right severity: only when EVERY byte change this cycle is
	// confirmed recurring boot-time noise does this stay pure INFO.
	// changedThisCycle collects every (bdf, offset) changed this cycle so
	// noteworthiness can be evaluated ONCE, after the per-device loop below,
	// with a single CONFIG_CHANGES_LOG read — rather than re-reading the
	// whole file inside the loop for every device that changed.
	configChangesFoundInThisCycle := false
	var changedThisCycle []struct{ bdf, offset string }

	topoState := loadTopologyState()
	topoStateDirty := false
	unavailState := loadUnavailableState()
	unavailStateDirty := false
	nowTs := time.Now()
	currentCycleNum := currentCycle.Load()

	// Check for new devices. This is the raw config-space path's own
	// topology check, independent of the lspci-text path in
	// processPCIDevices(). It must call recordCycleChange AND write a
	// "NEW Device:"/"REMOVED Device:" line to reboot.log (logFp) in the same
	// shape processPCIDevices() uses: without this, a device that only this
	// path noticed (e.g. because its _init.txt lspci snapshot happened to
	// fail while its raw config sample succeeded) would never flip the
	// cycle-end banner, never trigger -p, and never appear in result.json's
	// TOPOLOGY problems.
	for busID, stableCfg := range stableConfigs {
		if _, exists := initialDevices[busID]; !exists {
			if ignoreDevices[busID] {
				continue
			}
			currentInfo := parsePCIConfig(stableCfg.Data)
			currentInfo.BusID = busID
			logDeviceChange(logFile, nil, &currentInfo, "NEW DEVICE")
			bdf := normalizeBDF(busID)
			if logFp != nil {
				fmt.Fprintf(logFp, "%s %sNEW Device: %s (raw config-space)\n", getCurrentTimestamp(), cycleTag(), bdf)
			}
			recordCycleChange(fmt.Sprintf("raw config-space: device added: %s", bdf))
			// A genuinely new BDF never had a baseline entry, so it is simply
			// not tracked as "absent" — no topology-state update needed. Note
			// initialDevices itself is deliberately NOT updated here (Issue
			// #21): initial.bin is never rewritten, so this BDF has no raw
			// config-space comparison baseline for the rest of the run (it
			// remains visible only via the lspci-text path's own baseline).
		}
	}

	// For each baselined device, determine this cycle's transition: still
	// present & readable (compare), freshly REMOVED (dedup via topoState),
	// still absent (already recorded), REAPPEARED (dedup via topoState), or
	// UNAVAILABLE (still enumerated in sysfs but unreadable this cycle,
	// distinct from REMOVED — Issue #23).
	for busID, configData := range initialDevices {
		normBusID := normalizeBDF(busID)
		if ignoreDevices[busID] {
			continue
		}
		stableCfg, exists := stableConfigs[busID]
		if !exists {
			// A genuine presence check against sysfs itself, NOT this cycle's
			// link classification (endpointFilterAllows would conflate "read
			// looked bad this cycle" with "device is gone" whenever a
			// still-present device's link speed/width happens to decode as
			// invalid mid-retrain — see pciDeviceEnumeratedInSysfs's doc
			// comment).
			stillEnumerated := pciDeviceEnumeratedInSysfs(busID)
			if stillEnumerated {
				// Present in sysfs but no stable sample this cycle:
				// UNAVAILABLE, not REMOVED. This mirrors
				// processPCIDevices()' lspci-side UNAVAILABLE handling but is
				// evaluated independently, since a device's raw config-space
				// sample and its lspci snapshot can fail independently of
				// each other.
				unavailDesc := unavailableMark(&unavailState, topologyNamespaceRawConfig, normBusID, currentCycleNum, nowTs)
				unavailStateDirty = true
				if logFp != nil {
					fmt.Fprintf(logFp, "%s %sUNAVAILABLE Device: %s (raw config-space unreadable this cycle; %s)\n",
						getCurrentTimestamp(), cycleTag(), normBusID, unavailDesc)
				}
				recordCycleNotice(fmt.Sprintf("device unreadable (raw config-space): %s (%s)", normBusID, unavailDesc))
				continue
			}
			// Genuinely gone from sysfs: REMOVED, deduped against topoState so
			// a device absent for many cycles is reported exactly once.
			wasAbsent := topologyIsAbsent(topoState, topologyNamespaceRawConfig, normBusID)
			if !wasAbsent {
				initialInfo := parsePCIConfig(configData)
				initialInfo.BusID = busID
				logDeviceChange(logFile, &initialInfo, nil, "DEVICE DISAPPEARED")
				if logFp != nil {
					fmt.Fprintf(logFp, "%s %sREMOVED Device: %s (raw config-space)\n", getCurrentTimestamp(), cycleTag(), normBusID)
				}
				recordCycleChange(fmt.Sprintf("raw config-space: device removed: %s", normBusID))
				topologyMarkAbsent(&topoState, topologyNamespaceRawConfig, normBusID)
				topoStateDirty = true
			}
			// Also clear any stale UNAVAILABLE marker: a device that goes
			// fully absent is no longer merely "unavailable".
			if recovered := unavailableClear(&unavailState, topologyNamespaceRawConfig, normBusID, nowTs); recovered != "" {
				unavailStateDirty = true
			}
			continue
		}

		// This BDF has a stable sample this cycle: clear any UNAVAILABLE
		// marker and, if it was previously marked REMOVED, report REAPPEARED
		// exactly once (still comparing against the SAME immutable baseline,
		// per Issue #21 — no rebase).
		if recovered := unavailableClear(&unavailState, topologyNamespaceRawConfig, normBusID, nowTs); recovered != "" {
			unavailStateDirty = true
			if logFp != nil {
				fmt.Fprintf(logFp, "%s %sDevice %s is readable again (raw config-space) — %s\n", getCurrentTimestamp(), cycleTag(), normBusID, recovered)
			}
		}
		if topologyIsAbsent(topoState, topologyNamespaceRawConfig, normBusID) {
			if logFp != nil {
				fmt.Fprintf(logFp, "%s %sREAPPEARED Device: %s (raw config-space; comparing against original baseline)\n", getCurrentTimestamp(), cycleTag(), normBusID)
			}
			recordCycleChange(fmt.Sprintf("raw config-space: device reappeared: %s", normBusID))
			topologyMarkPresent(&topoState, topologyNamespaceRawConfig, normBusID)
			topoStateDirty = true
		}

		initialInfo := parsePCIConfig(configData)
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

		// Pass stableCfg.UnstableBytes for live timer filtering.
		//
		// Deliberately NOT rebased on change (Issue #21): compareAndLogDeviceChanges'
		// byte-level diffs stay anchored to the ORIGINAL one-time initial.bin
		// for the lifetime of the run by design. classifyConfigChangeRatio
		// (result_helpers.go/summary.go) classifies a (device, offset) row
		// as benign "reboot-fixed" noise specifically because it recurs in
		// >= rebootFixedThreshold (80%) of ALL completed cycles when
		// compared against that fixed baseline — the classic pattern for a
		// register that resets to the same value on every boot regardless
		// of its pre-test initial value. Rebasing after the first detected
		// change would make that register look "clean" from the very next
		// cycle onward, permanently hiding the fixed/reproducible pattern
		// this ratio-based classification exists to surface.
		changedOffsets := compareAndLogDeviceChanges(logFile, initialInfo, currentInfo, combinedIgnore, stableCfg.UnstableBytes)
		if len(changedOffsets) > 0 {
			configChangesFoundInThisCycle = true
			normBusID := normalizeBDF(busID)
			for _, offset := range changedOffsets {
				changedThisCycle = append(changedThisCycle, struct{ bdf, offset string }{normBusID, offset})
			}
		}
	}

	// Issue #25: re-evaluate THIS cycle's changed (device, offset) rows
	// against the whole-run occurrence ratio, using the SAME
	// classifyConfigChangeRatio() function result_helpers.go and
	// buildResultReport() use. If any row is not yet confirmed recurring
	// noise (below rebootFixedThreshold, OR fewer than 2 completed cycles
	// have run so far — a single-cycle 100% occurrence must never be
	// classified as benign), this cycle's raw config-space contribution is a
	// NOTICE, not silent INFO noise, and must satisfy the -p stop condition.
	configNoticeFoundInThisCycle := false
	if len(changedThisCycle) > 0 {
		completedCyclesSoFar := 0
		if current := currentCycle.Load(); current > 0 {
			completedCyclesSoFar = int(current)
		}
		counts := configChangeOccurrenceCounts()
		for _, row := range changedThisCycle {
			count := counts[row.bdf+"\x00"+row.offset]
			if _, noteworthy := classifyConfigChangeRatio(count, completedCyclesSoFar); noteworthy {
				configNoticeFoundInThisCycle = true
				break
			}
		}
	}

	if topoStateDirty {
		saveTopologyState(topoState)
	}
	if unavailStateDirty {
		saveUnavailableState(unavailState)
	}

	// Persisted immediately (not an in-memory `cyclesWithConfigChanges++`)
	// because generateFinalSummary()'s raw-config STABLE/CHANGED line must
	// reflect the entire multi-cycle run, and each reboot cycle runs in a
	// brand-new process. Severity (Issue #25): a config-space change is only
	// ever recorded as benign INFO noise when EVERY changed (device, offset)
	// row this cycle is already confirmed recurring noise; if even one row
	// is not yet confirmed (or there have been fewer than 2 completed
	// cycles), the whole cycle's raw config-space contribution is a NOTICE,
	// satisfying the -p stop condition and never collapsing to a clean/PASS
	// banner.
	if configChangesFoundInThisCycle {
		recordConfigSpaceChangeCycle()
		if configNoticeFoundInThisCycle {
			recordCycleNotice("PCI config-space byte change(s) not yet confirmed as recurring noise")
		} else {
			recordCycleNoise("PCI config-space byte changes detected")
		}
	}

	return nil
}

// parsePCIConfig parses binary configuration data into structured PCI device information
func parsePCIConfig(rawConfig []byte) PCIDeviceInfo {
	info := PCIDeviceInfo{
		ConfigData: rawConfig,
	}
	if len(rawConfig) < 64 {
		// Data is insufficient to parse a PCI header (64 bytes minimum). Mark
		// Truncated so callers print an explicit "read incomplete" notice
		// instead of a fake 0000:0000 vendor:device pair.
		info.Truncated = true
		return info
	}
	// Parse header
	info.VendorID = binary.LittleEndian.Uint16(rawConfig[0:2])
	info.DeviceID = binary.LittleEndian.Uint16(rawConfig[2:4])

	headerType := rawConfig[14] & 0x7F
	// Read Subsystem IDs (only applicable for Type 0 header)
	if headerType == 0 && len(rawConfig) >= 48 {
		info.SubsystemVendorID = binary.LittleEndian.Uint16(rawConfig[44:46])
		info.SubsystemID = binary.LittleEndian.Uint16(rawConfig[46:48])
	}

	return info
}

// formatDeviceInfo formats device information into human-readable string. A
// Truncated info (config read returned fewer than 64 bytes) prints an
// explicit notice instead of a fake "0000:0000" vendor:device pair, since
// that all-zero ID would otherwise look like a real (if extremely unusual)
// device rather than a failed read.
func formatDeviceInfo(info PCIDeviceInfo) string {
	if info.Truncated {
		return fmt.Sprintf(" %s (config read incomplete: got %d of 64+ required bytes)", info.BusID, len(info.ConfigData))
	}
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

// compareAndLogDeviceChanges compares two devices' PCI config data and logs
// differences.
//
// Filter priority (highest to lowest):
//  1. unstableBytes: bytes flagged as timer noise by live stability analysis (collectStableConfig)
//  2. timerPatterns: static offset ignore list from ignore_list.txt
//  3. timerRelatedOffsets: hardcoded known timer registers
//  4. volatileStatusBits: volatile status bits masked in the Status register
//
// Returns the hex-string offsets ("0xNN", matching parseConfigResultChanges'
// output) of every non-timer byte that changed this cycle, or nil if none
// did. The caller (compareDeviceConfigs) uses this to evaluate Issue #25's
// per-row noteworthy/recurring-noise classification for THIS cycle's changes
// without waiting for a later result.json build.
func compareAndLogDeviceChanges(logFile *os.File, initialInfo, currentInfo PCIDeviceInfo,
	timerPatterns map[int]bool, unstableBytes map[int]bool) []string {
	// A truncated read (< 64 bytes) cannot be meaningfully diffed byte-by-byte
	// against a full header; report the read failure explicitly instead of
	// silently comparing whatever partial bytes happen to overlap, which could
	// either report spurious changes or (if both sides truncated identically)
	// falsely report stability.
	if initialInfo.Truncated || currentInfo.Truncated {
		timestamp := getCurrentTimestamp()
		fmt.Fprintf(logFile, "%s %sDevice: %s (config read incomplete, comparison skipped this cycle)\n",
			timestamp, cycleTag(), formatDeviceInfo(currentInfo))
		fmt.Fprintln(logFile, "---")
		return nil
	}
	var changes []string
	var changedOffsets []string

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
			changedOffsets = append(changedOffsets, fmt.Sprintf("0x%02x", i))
		}
	}

	if len(changes) > 0 {
		timestamp := getCurrentTimestamp()
		fmt.Fprintf(logFile, "%s %sDevice: %s (config space change detected)\n",
			timestamp, cycleTag(), formatDeviceInfo(currentInfo))

		for _, change := range changes {
			fmt.Fprintln(logFile, change)
		}
		fmt.Fprintln(logFile, "---")
		return changedOffsets
	}
	return nil
}

// logDeviceChange logs device appearance/disappearance
func logDeviceChange(logFile *os.File, initialInfo, currentInfo *PCIDeviceInfo, changeType string) {
	var info PCIDeviceInfo
	if initialInfo != nil {
		info = *initialInfo
	} else if currentInfo != nil {
		info = *currentInfo
	}

	timestamp := getCurrentTimestamp()
	fmt.Fprintf(logFile, "%s %sDevice: %s (%s)\n", timestamp, cycleTag(), formatDeviceInfo(info), changeType)
	fmt.Fprintln(logFile, "---")
}

// readIgnoreDevicesAndOffsets reads ignore_list.txt for the raw config-space
// comparison path (compareDeviceConfigs). Its semantics deliberately differ
// from loadIgnoreList (used by the lspci comparison path, processPCIDevices):
// a bare-BDF line (no offsets) here means "ignore this whole device"
// (ignoreDevices), while a BDF line WITH offsets means "ignore only those
// specific offsets, still compare the rest of the device" (ignoreOffsets).
// loadIgnoreList instead treats ANY line for a BDF — with or without offsets
// — as "ignore the whole device" for the lspci path, because lspci comparison
// has no notion of a partial per-offset ignore.
//
// This asymmetry is intentional and currently safe only because
// saveIgnoreBits() (the sole writer of ignore_list.txt) always writes a bare
// BDF for whole-device ignores (USB controllers) and a BDF+offsets line only
// for partial timer-offset ignores — so the two readers happen to agree on
// every line saveIgnoreBits produces. If a user hand-edits ignore_list.txt to
// add a BDF+offsets line intending "only ignore these offsets", the lspci
// path (loadIgnoreList) will silently ignore the ENTIRE device instead,
// which is a real footgun for manual edits.
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
// collectStableConfig returns the stable per-device snapshot together with
// the deduplicated set of BDF/error strings that failed to read during any
// of the samples, so the caller can log exactly which device could not be
// verified this cycle instead of that information being visible only on
// stdout via the underlying savePCIConfigReportingFailures calls.
func collectStableConfig(sampleCount int, intervalMs int) (map[string]StableConfig, []string, error) {
	if sampleCount < 2 {
		sampleCount = 2
	}

	// Randomised private directory under /tmp so the predictable filenames
	// inside cannot be pre-seeded by a local attacker.
	sampleDir, err := os.MkdirTemp("", "lpot-stable-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sample directory: %v", err)
	}
	defer os.RemoveAll(sampleDir)

	tmpFiles := make([]string, sampleCount)
	for i := range tmpFiles {
		tmpFiles[i] = filepath.Join(sampleDir, fmt.Sprintf("sample-%d.bin", i))
	}

	fmt.Printf("Collecting %d stability samples (%dms apart)...\n", sampleCount, intervalMs)
	failedSet := make(map[string]bool)
	for i, f := range tmpFiles {
		failedBDFs, err := savePCIConfigReportingFailures(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to collect sample %d: %v", i+1, err)
		}
		for _, entry := range failedBDFs {
			failedSet[entry] = true
		}
		if i < sampleCount-1 {
			time.Sleep(time.Duration(intervalMs) * time.Millisecond)
		}
	}

	samples := make([]map[string][]byte, sampleCount)
	for i, f := range tmpFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read sample %d: %v", i+1, err)
		}
		samples[i] = splitDevices(data)
	}

	failedBDFs := make([]string, 0, len(failedSet))
	for entry := range failedSet {
		failedBDFs = append(failedBDFs, entry)
	}
	sort.Strings(failedBDFs)
	return analyzeStableConfig(samples), failedBDFs, nil
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

// loadIgnoreList reads ignore_list.txt for the lspci comparison path
// (processPCIDevices -> compareDeviceFiles). A line is "ignore the whole
// device" ONLY when it is a bare BDF with no offsets (saveIgnoreBits()
// writes this shape exclusively for USB controllers / other IgnoreDevice
// cases). A line that also lists specific offsets (the shape saveIgnoreBits
// writes for every device that has ANY timer/volatile byte, which in
// practice is nearly every device on the system, since timerRelatedOffsets
// is unconditionally copied into every device's ignore bytes) must NOT
// cause the whole device to be skipped here: lspci's Dev/Lnk field
// comparison has no notion of ignoring individual PCI config-space byte
// offsets, so an offset-qualified line is simply not applicable to this
// path and must be treated as "no whole-device ignore for this BDF" here.
//
// This previously treated ANY line for a BDF (with or without offsets) as
// "ignore the whole device", which meant every device that ever had a
// single timer-related ignore byte recorded (effectively all of them, via
// the unconditional timerRelatedOffsets copy in
// detectVolatileBytesWithSamples) was silently skipped from the entire
// lspci Dev/Lnk comparison — the exact "footgun" scenario this function's
// old comment warned about for hand-edited files was in fact happening on
// every normal -t run, disabling the comparison for essentially the whole
// system.
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

		// Only a bare BDF (exactly one field, no offsets) means "ignore the
		// whole device" for the lspci comparison path. Normalise to short
		// form so the lookup in parseDeviceFile() (which uses lspci-text's
		// short BDF) succeeds even when the file on disk uses long form.
		fields := strings.Fields(line)
		if len(fields) == 1 {
			ignoreSet[normalizeBDF(fields[0])] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ignore list file %s: %w", filePath, err)
	}

	return ignoreSet, nil
}
