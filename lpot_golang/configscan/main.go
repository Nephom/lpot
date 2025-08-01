package main

import (
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

// Define which registers are timer-related
var timerRelatedOffsets = map[int]bool{
	0x0D: true, // LatencyTimer
	0x3E: true, // MinGnt
	0x3F: true, // MaxLat
	0xc8: true, // PTR
	0xc9: true, // PTR
	0xe4: true,
	0xe5: true,
	// Add more timer-related offsets here if needed
}

// Define volatile status bits - these often change during normal operation
var volatileStatusBits = uint16(0x00F8) // Bits 3-7 of Status register (offset 0x06)

// 分析位元級別的變化模式，用於偵測計時器位元
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

	// 檢查是否有遞增模式 (典型的計時器行為)
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

	// 檢查位元翻轉模式 (某些計時器會有位元翻轉)
	bitFlips := make([]int, 8)
	for i := 1; i < len(values); i++ {
		xor := values[i] ^ values[i-1]
		for bit := 0; bit < 8; bit++ {
			if (xor>>bit)&1 == 1 {
				bitFlips[bit]++
			}
		}
	}

	// 如果某個位元翻轉頻繁，可能是計時器位元
	for bit, flips := range bitFlips {
		if flips >= len(values)/2 {
			return true, fmt.Sprintf("bit_%d_flipping", bit)
		}
	}

	// 檢查是否有週期性變化
	uniqueValues := make(map[byte]bool)
	for _, v := range values {
		uniqueValues[v] = true
	}

	// 如果有多個不同值且變化頻繁，可能是計時器
	if len(uniqueValues) >= 3 {
		return true, "multiple_values"
	}

	return false, ""
}

// 生成詳細的波動位元組分析報告
func saveVolatileAnalysisReport(filePath string, ignoreBits map[string]DeviceIgnoreBits, samples []map[string][]byte) error {
	var buffer bytes.Buffer

	buffer.WriteString("# PCI Configuration Space Volatile Byte Analysis Report\n")
	buffer.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n")
	buffer.WriteString(fmt.Sprintf("# Based on %d samples collected over %d seconds\n", len(samples), len(samples)-1))
	buffer.WriteString("# \n")
	buffer.WriteString("# Legend:\n")
	buffer.WriteString("# - Timer: Detected timer-like behavior (monotonic or bit-flipping patterns)\n")
	buffer.WriteString("# - Volatile: Frequently changing values\n")
	buffer.WriteString("# - Status: Known status register bits\n")
	buffer.WriteString("# \n")

	// 將映射轉換為有序列表
	var busIDs []string
	for busID := range ignoreBits {
		busIDs = append(busIDs, busID)
	}
	sort.Strings(busIDs)

	for _, busID := range busIDs {
		device := ignoreBits[busID]
		if len(device.IgnoreBytes) == 0 {
			continue
		}

		buffer.WriteString(fmt.Sprintf("\n## Device: %s\n", busID))

		// 將忽略位元組轉換為有序列表
		var offsets []int
		for offset := range device.IgnoreBytes {
			offsets = append(offsets, offset)
		}
		sort.Ints(offsets)

		for _, offset := range offsets {
			// Skip known timer registers and status registers - only log unexpected volatile bytes
			if timerRelatedOffsets[offset] || offset == 6 || offset == 7 {
				continue
			}

			// Check if this is a detected timer pattern
			var deviceSamples [][]byte
			for _, sample := range samples {
				if data, exists := sample[busID]; exists {
					deviceSamples = append(deviceSamples, data)
				}
			}

			isTimer := false
			if len(deviceSamples) > 0 {
				isTimer, _ = analyzeBitPatterns(deviceSamples, offset)
			}

			// Only log non-timer volatile registers
			if !isTimer {
				buffer.WriteString(fmt.Sprintf("0x%02x: Unexpected volatile register\n", offset))
			}
		}
	}

	return os.WriteFile(filePath, buffer.Bytes(), 0644)
}

// DeviceIgnoreBits 結構，用於存儲要忽略的位元組列表
type DeviceIgnoreBits struct {
	BusID           string
	IgnoreBytes     map[int]bool
	IsUSBController bool
}

// Modify splitDevices to handle XXD-like format
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
			hexPart = strings.TrimSpace(strings.SplitN(hexPart, ": ", 2)[1])
			// Remove spaces and convert to hex string
			hexPart = strings.ReplaceAll(hexPart, " ", "")
			hexBuilder.WriteString(hexPart)
		}
		configData, err := hex.DecodeString(hexBuilder.String())
		if err == nil {
			devices[busID] = configData
		}
	}
	return devices
}

// Parse binary configuration data into structured PCI device information
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
	info.Class[2] = rawConfig[8]  // Base Class

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

	// Parse Capability Pointer
	capPointerOffset := uint8(52) // Default for Type 0
	switch headerType {
	case 0:
		capPointerOffset = 52
	case 1:
		capPointerOffset = 34
	default:
		capPointerOffset = 52 // Use Type 0 default for unknown types
	}
	if len(rawConfig) > int(capPointerOffset) && (info.Status&0x0010) != 0 {
		capPointer := rawConfig[capPointerOffset]
		parseCapabilities(rawConfig, capPointer, &info)
	}

	return info
}

// Parse PCI capability structures
func parseCapabilities(data []byte, capPointer uint8, info *PCIDeviceInfo) {
	visited := make(map[uint8]bool)
	for capPointer != 0 && !visited[capPointer] && int(capPointer) < len(data)-2 {
		visited[capPointer] = true
		capID := data[capPointer]
		capNext := data[capPointer+1]

		// Determine length for different capability structures
		var capLength uint8 = 2 // Default minimum length

		// Set correct length for known capability structures
		switch capID {
		case 0x01: // PCI Power Management
			if int(capPointer)+8 <= len(data) {
				capLength = 8
			}
		case 0x05: // MSI
			if int(capPointer)+10 <= len(data) {
				capLength = 10
				// Check if it has 64-bit capability
				if data[capPointer+2]&0x80 != 0 && int(capPointer)+14 <= len(data) {
					capLength = 14
				}
			}
		case 0x10: // PCIe
			if int(capPointer)+20 <= len(data) {
				capLength = 20
			}
		default:
			// For other capabilities, use default length
			if int(capPointer)+4 <= len(data) {
				capLength = 4
			}
		}

		// Ensure we don't exceed boundaries
		if int(capPointer)+int(capLength) > len(data) {
			capLength = uint8(len(data) - int(capPointer))
		}

		// Store capability information
		capData := data[capPointer : capPointer+capLength]
		info.Capabilities[capID] = PCICapability{
			ID:     capID,
			Next:   capNext,
			Length: capLength,
			Data:   capData,
		}

		// Move to next capability structure
		capPointer = capNext

		// Prevent cyclic references
		if len(visited) > 16 {
			break
		}
	}
}

// Format device information into human-readable string
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

func saveIgnoreBits(filePath string, ignoreBits map[string]DeviceIgnoreBits) error {
	var buffer bytes.Buffer

	buffer.WriteString("# Auto-generated list of volatile PCI configuration bytes to ignore\n")
	buffer.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n")
	buffer.WriteString("# Format: BusID [0xXX 0xYY ...] (offsets are timer-related, no offsets means USB device)\n")
	buffer.WriteString("# These bytes are identified as timer-related or frequently changing\n")

	// 將映射轉換為有序列表，以便按BusID排序
	var busIDs []string
	for busID := range ignoreBits {
		busIDs = append(busIDs, busID)
	}
	sort.Strings(busIDs)

	for _, busID := range busIDs {
		device := ignoreBits[busID]

		// 檢查是否為 USB Controller (Class 0x0c, Subclass 0x03)
		if device.IsUSBController {
			// USB Controller - 忽略整個設備
			buffer.WriteString(busID + "\n")
		} else if len(device.IgnoreBytes) > 0 {
			// 有計時器偏移量 - 只忽略特定偏移量
			buffer.WriteString(busID)

			// 將忽略位元組轉換為有序列表
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

	return os.WriteFile(filePath, buffer.Bytes(), 0644)
}

// 偵測頻繁變動的位元組並返回樣本數據用於分析報告
func detectVolatileBytesWithSamples() (map[string]DeviceIgnoreBits, []map[string][]byte, error) {
	ignoreBits := make(map[string]DeviceIgnoreBits)

	// 創建5個臨時檔案以獲得更準確的分析
	tmpFiles := []string{
		"/tmp/pci_config_tmp1.bin",
		"/tmp/pci_config_tmp2.bin",
		"/tmp/pci_config_tmp3.bin",
		"/tmp/pci_config_tmp4.bin",
		"/tmp/pci_config_tmp5.bin",
	}

	fmt.Println("Collecting PCI config samples for volatile byte detection...")

	// 收集5個樣本，每次間隔1秒
	for i, tmpFile := range tmpFiles {
		fmt.Printf("Collecting sample %d/%d...\n", i+1, len(tmpFiles))
		if err := savePCIConfig(tmpFile); err != nil {
			return nil, nil, fmt.Errorf("failed to create sample %d: %v", i+1, err)
		}

		if i < len(tmpFiles)-1 {
			time.Sleep(1 * time.Second)
		}
	}

	// 讀取樣本數據
	var samples []map[string][]byte
	for _, tmpFile := range tmpFiles {
		data, err := os.ReadFile(tmpFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read %s: %v", tmpFile, err)
		}

		devices := splitDevices(data)
		samples = append(samples, devices)
	}

	// 查找所有樣本中共有的裝置
	deviceIDs := make(map[string]bool)
	for _, sample := range samples {
		for busID := range sample {
			deviceIDs[busID] = true
		}
	}

	// 分析每個裝置
	for busID := range deviceIDs {
		var deviceData [][]byte

		// 檢查所有樣本中是否都有這個裝置
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

		// 檢查是否為 USB Controller
		if len(deviceData[0]) >= 11 {
			classCode := deviceData[0][11] // Base Class
			subClass := deviceData[0][10]  // Sub Class
			if classCode == 0x0c && subClass == 0x03 {
				// USB Controller - 忽略整個設備
				ignoreBits[busID] = DeviceIgnoreBits{
					BusID:           busID,
					IgnoreBytes:     make(map[int]bool),
					IsUSBController: true,
				}
				fmt.Printf("Device %s: USB Controller detected, ignoring entire device\n", busID)
				continue
			}
		}

		ignoreBytes := make(map[int]bool)

		// 複製基本的timer相關偏移量
		for offset := range timerRelatedOffsets {
			ignoreBytes[offset] = true
		}

		// 改進的波動位元組偵測算法
		statusOffset := 6
		for i := 0; i < len(deviceData[0]) && i < 256; i++ {
			// 特殊處理狀態暫存器 (offsets 0x06-0x07)
			if i == statusOffset || i == statusOffset+1 {
				continue
			}

			// 統計此位元組的變化次數和不同值的數量
			changeCount := 0
			valueSet := make(map[byte]bool)

			// 收集所有值
			for j := 0; j < len(deviceData); j++ {
				if len(deviceData[j]) > i {
					valueSet[deviceData[j][i]] = true
				}
			}

			// 計算相鄰樣本間的變化次數
			for j := 1; j < len(deviceData); j++ {
				if len(deviceData[j]) <= i || len(deviceData[j-1]) <= i {
					continue
				}

				if deviceData[j][i] != deviceData[j-1][i] {
					changeCount++
				}
			}

			// 使用位元模式分析來更準確地偵測計時器
			isTimer, pattern := analyzeBitPatterns(deviceData, i)

			// 如果有多個不同值或變化次數超過閾值，或者偵測到計時器模式
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
			}
		}
	}

	// 刪除臨時檔案
	for _, tmpFile := range tmpFiles {
		os.Remove(tmpFile)
	}

	return ignoreBits, samples, nil
}

func savePCIConfig(outputFile string) error {
	pciPath := "/sys/bus/pci/devices/"
	files, err := os.ReadDir(pciPath)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	for _, file := range files {
		busID := file.Name()
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

		header := PCIConfigHeader{}
		binary.Read(bytes.NewBuffer(configData), binary.LittleEndian, &header)

		// Note: We now include USB devices for volatile byte detection
		// USB devices will be handled in the ignore logic during comparison

		// XXD-like output format
		buffer.WriteString(fmt.Sprintf("# %s\n", busID))
		for i := 0; i < len(configData); i += 16 {
			// Write offset
			buffer.WriteString(fmt.Sprintf("%04x: ", i))
			// Write hex representation
			for j := 0; j < 16; j++ {
				if i+j < len(configData) {
					buffer.WriteString(fmt.Sprintf("%02x ", configData[i+j]))
				} else {
					buffer.WriteString(" ")
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
	return os.WriteFile(outputFile, buffer.Bytes(), 0644)
}

// 增強的比較設備配置函數，考慮忽略設備和計時器模式
func compareDeviceConfigs(initialFile, currentFile, reportFile string) error {
	initialData, err := os.ReadFile(initialFile)
	if err != nil {
		return err
	}
	currentData, err := os.ReadFile(currentFile)
	if err != nil {
		return err
	}

	// 讀取要忽略的設備和偏移量列表
	ignoreDevices, ignoreOffsets, err := readIgnoreDevicesAndOffsets("/lpot/ignore_bits.txt")
	if err != nil {
		return fmt.Errorf("failed to read ignore devices: %v", err)
	}

	// 分析現有日誌中的計時器模式
	timerPatterns := analyzeTimerPatterns(reportFile)

	logFile, err := os.OpenFile(reportFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logFile.Close()

	initialDevices := splitDevices(initialData)
	currentDevices := splitDevices(currentData)

	timestamp := time.Now().Format(time.RFC3339)
	uniqueInitialBusIDs := len(initialDevices)
	uniqueCurrentBusIDs := len(currentDevices)
	fmt.Printf("%s Parsed %d initial devices, %d current devices\n",
		timestamp, uniqueInitialBusIDs, uniqueCurrentBusIDs)
	logFile.WriteString(fmt.Sprintf("%s Parsed %d initial devices, %d current devices\n",
		timestamp, uniqueInitialBusIDs, uniqueCurrentBusIDs))

	// 檢查消失的設備
	for busID, configData := range initialDevices {
		if _, exists := currentDevices[busID]; !exists {
			if ignoreDevices[busID] {
				continue
			}
			initialInfo := parsePCIConfig(configData)
			initialInfo.BusID = busID
			logDeviceChange(logFile, &initialInfo, nil, "DEVICE DISAPPEARED")
		}
	}

	// 檢查新設備
	for busID, configData := range currentDevices {
		if _, exists := initialDevices[busID]; !exists {
			if ignoreDevices[busID] {
				continue
			}
			currentInfo := parsePCIConfig(configData)
			currentInfo.BusID = busID
			logDeviceChange(logFile, nil, &currentInfo, "NEW DEVICE")
		}
	}

	// 比較配置變化
	for busID, initialConfigData := range initialDevices {
		if currentConfigData, exists := currentDevices[busID]; exists {
			if ignoreDevices[busID] {
				continue
			}

			initialInfo := parsePCIConfig(initialConfigData)
			initialInfo.BusID = busID
			currentInfo := parsePCIConfig(currentConfigData)
			currentInfo.BusID = busID

			// 合併計時器模式和忽略偏移量
			deviceTimerPatterns := map[int]bool{}
			if patterns, exists := timerPatterns[busID]; exists {
				for offset := range patterns {
					deviceTimerPatterns[offset] = true
				}
			}
			if offsets, exists := ignoreOffsets[busID]; exists {
				for offset := range offsets {
					deviceTimerPatterns[offset] = true
				}
			}

			compareAndLogDeviceChanges(logFile, initialInfo, currentInfo, deviceTimerPatterns)
		}
	}

	return nil
}

// 增強的比較設備變更函數，使用計時器模式過濾
func compareAndLogDeviceChanges(logFile *os.File, initialInfo, currentInfo PCIDeviceInfo,
	timerPatterns map[int]bool) {
	var changes []string

	for i := 0; i < len(initialInfo.ConfigData) && i < len(currentInfo.ConfigData); i++ {
		// 如果此偏移量是已知的計時器模式，則跳過比較
		if timerPatterns[i] || timerRelatedOffsets[i] {
			continue
		}

		// 特殊處理狀態暫存器 (offsets 0x06-0x07)
		if i == 6 || i == 7 {
			statusOffset := 6
			initialStatus := binary.LittleEndian.Uint16(initialInfo.ConfigData[statusOffset : statusOffset+2])
			currentStatus := binary.LittleEndian.Uint16(currentInfo.ConfigData[statusOffset : statusOffset+2])

			// 遮蔽易變的狀態位元
			initialStatus &= ^volatileStatusBits
			currentStatus &= ^volatileStatusBits

			if (i == 6 && (initialStatus&0xFF) == (currentStatus&0xFF)) ||
				(i == 7 && ((initialStatus>>8)&0xFF) == ((currentStatus>>8)&0xFF)) {
				continue
			}
		}

		// 比較非計時器相關的位元組
		if initialInfo.ConfigData[i] != currentInfo.ConfigData[i] {
			changes = append(changes, fmt.Sprintf("Value at offset 0x%02x changed from 0x%02x to 0x%02x",
				i, initialInfo.ConfigData[i], currentInfo.ConfigData[i]))
		}
	}

	if len(changes) > 0 {
		timestamp := time.Now().Format(time.RFC3339)
		fmt.Fprintf(logFile, "%s Device: %s (config space change detected)\n", timestamp, formatDeviceInfo(currentInfo))
		for _, change := range changes {
			fmt.Fprintln(logFile, change)
		}
		fmt.Fprintln(logFile, "---")
	}
}

// logDeviceChange logs device appearance/disappearance
func logDeviceChange(logFile *os.File, initialInfo, currentInfo *PCIDeviceInfo, changeType string) {
	var info PCIDeviceInfo
	if initialInfo != nil {
		info = *initialInfo
	} else if currentInfo != nil {
		info = *currentInfo
	}

	timestamp := time.Now().Format(time.RFC3339)
	fmt.Fprintf(logFile, "%s Device: %s (%s)\n", timestamp, formatDeviceInfo(info), changeType)
	fmt.Fprintln(logFile, "---")
}

func main() {
	initialFile := "/lpot/initial.bin"
	currentFile := "/lpot/current.bin"
	ignoreBitsFile := "/lpot/ignore_bits.txt"
	reportFile := "/lpot/pci-config-changes.log"

	// 檢查是否有 -scan 參數
	if len(os.Args) > 1 && os.Args[1] == "-scan" {
		timestamp := time.Now().Format(time.RFC3339)
		fmt.Printf("%s Starting volatile byte detection (this will take about 5 seconds)...\n", timestamp)

		// 檢測波動字節並存儲忽略列表
		ignoreBits, _, err := detectVolatileBytesWithSamples()
		if err != nil {
			fmt.Printf("%s Warning: Failed to detect volatile bytes: %v\n", timestamp, err)
		} else {
			// 保存忽略位元組列表
			err = saveIgnoreBits(ignoreBitsFile, ignoreBits)
			if err != nil {
				fmt.Printf("%s Warning: Failed to save ignore bits: %v\n", timestamp, err)
			} else {
				fmt.Printf("%s Successfully saved ignore bits for %d devices\n", timestamp, len(ignoreBits))
			}

			// Analysis report generation removed - no longer needed during scan
		}
		return
	}

	// Check if initial.bin exists
	_, err := os.Stat(initialFile)
	if os.IsNotExist(err) {
		timestamp := time.Now().Format(time.RFC3339)
		fmt.Printf("%s Initial PCI config not found, creating %s\n", timestamp, initialFile)

		// 保存初始PCI配置
		err = savePCIConfig(initialFile)
		if err != nil {
			fmt.Printf("%s Error saving initial PCI config: %v\n", timestamp, err)
			return
		}
		fmt.Printf("%s Initial PCI config saved. Run again to compare.\n", timestamp)
		return
	}

	// initial.bin already exists, generate current.bin
	timestamp := time.Now().Format(time.RFC3339)
	fmt.Printf("%s Saving current PCI config to %s\n", timestamp, currentFile)
	err = savePCIConfig(currentFile)
	if err != nil {
		fmt.Printf("%s Error saving current PCI config: %v\n", timestamp, err)
		return
	}

	// Compare initial.bin and current.bin
	fmt.Printf("%s Comparing PCI configs...\n", timestamp)
	err = compareDeviceConfigs(initialFile, currentFile, reportFile)
	if err != nil {
		fmt.Printf("%s Error comparing PCI configs: %v\n", timestamp, err)
	}

	// Generate detailed analysis report during normal comparison mode
	analysisReportFile := "/lpot/volatile_analysis_report.txt"
	// Read current samples for analysis
	currentData, err := os.ReadFile(currentFile)
	if err == nil {
		currentDevices := splitDevices(currentData)
		samples := []map[string][]byte{currentDevices}
		
		// Read ignore bits to generate meaningful report
		ignoreDevices, ignoreOffsets, err := readIgnoreDevicesAndOffsets("/lpot/ignore_bits.txt")
		if err == nil {
			// Convert ignore data to DeviceIgnoreBits format for report
			ignoreBits := make(map[string]DeviceIgnoreBits)
			for busID := range ignoreDevices {
				ignoreBits[busID] = DeviceIgnoreBits{
					BusID:           busID,
					IgnoreBytes:     make(map[int]bool),
					IsUSBController: true,
				}
			}
			for busID, offsets := range ignoreOffsets {
				ignoreBits[busID] = DeviceIgnoreBits{
					BusID:           busID,
					IgnoreBytes:     offsets,
					IsUSBController: false,
				}
			}
			
			err = saveVolatileAnalysisReport(analysisReportFile, ignoreBits, samples)
			if err != nil {
				fmt.Printf("%s Warning: Failed to save analysis report: %v\n", timestamp, err)
			} else {
				fmt.Printf("%s Analysis report updated: %s\n", timestamp, analysisReportFile)
			}
		}
	}
}

// 分析日誌中的重複變化模式，自動識別計時器相關的偏移量
func analyzeTimerPatterns(logFile string) map[string]map[int]bool {
	timerPatterns := make(map[string]map[int]bool)

	data, err := os.ReadFile(logFile)
	if err != nil {
		return timerPatterns
	}

	lines := strings.Split(string(data), "\n")
	deviceOffsetCount := make(map[string]map[int]int)
	currentDevice := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 檢查是否是設備行
		if strings.Contains(line, "Device:") && strings.Contains(line, "config space change detected") {
			// 提取設備ID，格式如: "2025-07-18T10:39:23Z Device:  10003:0a:00.0 (1e0f:002e..."
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				currentDevice = parts[2] // 設備ID在第3個字段
				if deviceOffsetCount[currentDevice] == nil {
					deviceOffsetCount[currentDevice] = make(map[int]int)
				}
			}
		} else if strings.Contains(line, "Value at offset") && currentDevice != "" {
			// 解析偏移量，格式如: "Value at offset 0xd2 changed from 0x7c to 0x00"
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				offsetStr := strings.TrimPrefix(parts[3], "0x")
				offset, err := strconv.ParseInt(offsetStr, 16, 64)
				if err == nil {
					deviceOffsetCount[currentDevice][int(offset)]++
				}
			}
		} else if line == "---" {
			// 重置當前設備
			currentDevice = ""
		}
	}

	// 識別頻繁變化的偏移量作為計時器
	for deviceID, offsets := range deviceOffsetCount {
		if timerPatterns[deviceID] == nil {
			timerPatterns[deviceID] = make(map[int]bool)
		}
		for offset, count := range offsets {
			// 如果某個偏移量變化次數超過閾值，標記為計時器
			if count >= 3 {
				timerPatterns[deviceID][offset] = true
			}
		}
	}

	return timerPatterns
}

// 讀取忽略設備和偏移量列表
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

		bdf := parts[0]
		// 驗證 BDF 格式
		if len(bdf) < 7 || !strings.Contains(bdf, ":") {
			continue
		}

		if len(parts) == 1 {
			// 只有 BDF，忽略整個設備 (USB Controller)
			ignoreDevices[bdf] = true
		} else {
			// 有偏移量，只忽略特定偏移量 (計時器)
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
