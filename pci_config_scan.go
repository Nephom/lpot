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

// scanAndGenerateIgnoreBits scans PCI devices and generates ignore bits file
func scanAndGenerateIgnoreBits() error {
	timestamp := getCurrentTimestamp()
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
		timestamp := getCurrentTimestamp()
		fmt.Printf("%s Initial PCI config not found, creating %s\n", timestamp, initialFile)

		if err := savePCIConfig(initialFile); err != nil {
			return fmt.Errorf("error saving initial PCI config: %v", err)
		}
		fmt.Printf("%s Initial PCI config saved.\n", timestamp)
		return nil
	}

	// Compare initial snapshot against freshly-sampled stable config
	timestamp := getCurrentTimestamp()
	fmt.Printf("%s Comparing PCI configs...\n", timestamp)
	return compareDeviceConfigs(initialFile, CONFIG_CHANGES_LOG)
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

		if !validDevice {
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
	if deviceChangeStats == nil {
		deviceChangeStats = make(map[string]int)
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

	timestamp := getCurrentTimestamp()
	fmt.Printf("%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))
	fmt.Fprintf(logFile, "%s %sParsed %d initial devices, %d current devices\n",
		timestamp, cycleTag(), len(initialDevices), len(stableConfigs))

	// Track if any config changes are found in this cycle
	configChangesFoundInThisCycle := false

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

	// For each initial device, either it disappeared (not present in the
	// current stable snapshot) or it is still present and gets compared for
	// configuration changes. These two outcomes are mutually exclusive, so a
	// single walk over initialDevices with an if/else covers both cases.
	for busID, configData := range initialDevices {
		stableCfg, exists := stableConfigs[busID]
		if !exists {
			if ignoreDevices[busID] {
				continue
			}
			initialInfo := parsePCIConfig(configData)
			initialInfo.BusID = busID
			logDeviceChange(logFile, &initialInfo, nil, "DEVICE DISAPPEARED")
			continue
		}
		if ignoreDevices[busID] {
			continue
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
		ConfigData: rawConfig,
	}
	if len(rawConfig) < 64 {
		return info // Return empty info as data is insufficient
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
		timestamp := getCurrentTimestamp()
		fmt.Fprintf(logFile, "%s %sDevice: %s (config space change detected)\n",
			timestamp, cycleTag(), formatDeviceInfo(currentInfo))

		for _, change := range changes {
			fmt.Fprintln(logFile, change)
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

	timestamp := getCurrentTimestamp()
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
