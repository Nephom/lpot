package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Device struct to hold parsed data
type Device struct {
	DeviceID     string
	BDF          string
	Capabilities struct {
		DevLnkFields map[string]string
	}
}

type ComparisonResult struct {
	HasDifferences   bool
	Error            error
	LogEntries       []string
	ScannedDeviceIDs []string
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
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Extract BusID (first field before any space)
		fields := strings.Fields(line)
		if len(fields) > 0 {
			busID := fields[0]
			ignoreSet[busID] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ignore list file %s: %w", filePath, err)
	}

	return ignoreSet, nil
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
		line := strings.TrimSpace(scanner.Text())

		// Extract device ID from the first line
		if currentDevice.DeviceID == "" && len(line) >= 7 {
			// Extract full BusID (format: 0000:xx:yy.z)
			fields := strings.Fields(line)
			if len(fields) > 0 {
				currentDevice.DeviceID = fields[0]
			} else {
				currentDevice.DeviceID = line[:7]
			}
			remainingDesc := strings.TrimSpace(line[7:])
			
			// Check if this device should be ignored
			if ignoreSet[currentDevice.DeviceID] {
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
			if strings.HasPrefix(line, "\t") && currentFieldName != "" {
				currentFieldValue.WriteString(" " + strings.TrimSpace(line))
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

// stopService stops a systemd service
func stopService(serviceName string) error {
	cmd := exec.Command("systemctl", "stop", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop service %s: %w, output: %s", serviceName, err, string(output))
	}
	fmt.Printf("Service %s stopped successfully\n", serviceName)
	return nil
}

// compareDevices compares two devices and returns the comparison result
func compareDevices(device1, device2 Device, stopServiceEnabled bool) ComparisonResult {
	result := ComparisonResult{HasDifferences: false}

	// Record the scanned device ID
	result.ScannedDeviceIDs = append(result.ScannedDeviceIDs, device1.DeviceID)

	// Open log file
	logFilePath := "/tmp/lpotscan.log"
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
		logEntry := fmt.Sprintf("%s | %s | %s\nBefore: %s\nAfter: %s\n",
			time.Now().Format(time.RFC3339), device1.DeviceID, key, value1, value2)

		// Add detailed differences
		if differences := findDifferences(value1, value2); differences != "" {
			logEntry += fmt.Sprintf("\tDifferences: %s\n", differences)
		}

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

// Simple function to find differences between two strings
func findDifferences(value1, value2 string) string {
	var diff []string

	// Split both values into words for comparison
	words1 := strings.Fields(value1)
	words2 := strings.Fields(value2)

	// Compare words and find differences
	for i := 0; i < len(words1) || i < len(words2); i++ {
		if i < len(words1) && i < len(words2) {
			if words1[i] != words2[i] {
				diff = append(diff, fmt.Sprintf("'%s' to '%s'", words1[i], words2[i]))
			}
		} else if i < len(words1) {
			diff = append(diff, fmt.Sprintf("'%s' (only in 1)", words1[i]))
		} else if i < len(words2) {
			diff = append(diff, fmt.Sprintf("'%s' (only in 2)", words2[i]))
		}
	}

	return strings.Join(diff, ", ")
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <file1> <file2> ... <true|false>\n", os.Args[0])
		os.Exit(1)
	}

	stopServiceEnabled, err := strconv.ParseBool(os.Args[len(os.Args)-1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid stop service flag. Use true or false.\n")
		os.Exit(1)
	}

	// Load ignore list
	ignoreSet, err := loadIgnoreList("/lpot/ignore_bits.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load ignore list: %v\n", err)
		os.Exit(1)
	}

	logFilePath := "/tmp/lpotscan.log"
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)

	hasAnyChanges := false
	var allResults []ComparisonResult

	for i := 1; i < len(os.Args)-2; i += 2 {
		filePath1 := os.Args[i]
		filePath2 := os.Args[i+1]

		device1, err := parseDeviceFile(filePath1, ignoreSet)
		if err != nil {
			// Check if error is due to device being in ignore list
			if strings.Contains(err.Error(), "is in ignore list") {
				fmt.Printf("Skipping device in %s: %v\n", filePath1, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "Error parsing file %s: %v\n", filePath1, err)
			continue
		}

		device2, err := parseDeviceFile(filePath2, ignoreSet)
		if err != nil {
			// Check if error is due to device being in ignore list
			if strings.Contains(err.Error(), "is in ignore list") {
				fmt.Printf("Skipping device in %s: %v\n", filePath2, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "Error parsing file %s: %v\n", filePath2, err)
			continue
		}

		if device1.DeviceID != device2.DeviceID {
			fmt.Fprintf(os.Stderr, "Warning: Device IDs do not match for files: %s (%s) and %s (%s)\n",
				filePath1, device1.DeviceID, filePath2, device2.DeviceID)
			continue
		}

		result := compareDevices(device1, device2, stopServiceEnabled)
		allResults = append(allResults, result)
		if result.HasDifferences {
			hasAnyChanges = true
		}

		if result.Error != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
		}
	}

	// Log results when no changes detected
	if !hasAnyChanges {
		now := time.Now().Format("2006-01-02 15:04:05")

		for _, result := range allResults {
			for _, deviceID := range result.ScannedDeviceIDs {
				fmt.Printf("%s - %s - No change\n", now, deviceID)
			}
		}

		// 只寫入一次 "No devices changed" 到日誌
		logger.Println("No devices changed")
	}

	os.Exit(btoi(hasAnyChanges))
}

// btoi (bool to int) 讓程式返回 0 或 1
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
