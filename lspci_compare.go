package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Device struct for lspci comparison
type Device struct {
	DeviceID     string
	Capabilities struct {
		DevLnkFields map[string]string
	}
}

// ComparisonResult for device comparison
type ComparisonResult struct {
	HasDifferences bool
	Error          error
}

// compareDeviceFiles compares two device files using lspci logic
func compareDeviceFiles(filePath1, filePath2 string, ignoreSet map[string]bool, logFile *os.File) ComparisonResult {
	device1, err := parseDeviceFile(filePath1)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	device2, err := parseDeviceFile(filePath2)
	if err != nil {
		return ComparisonResult{Error: err}
	}

	// Normalise both BDFs before comparing: parseDeviceFile() may read a long
	// ("0000:21:00.4") or short ("21:00.4") form depending on which lspci
	// invocation produced the dump, and comparing the raw strings would
	// falsely report "device IDs do not match" for the same physical device.
	if normalizeBDF(device1.DeviceID) != normalizeBDF(device2.DeviceID) {
		return ComparisonResult{
			Error: fmt.Errorf("device IDs do not match: %s vs %s", device1.DeviceID, device2.DeviceID),
		}
	}
	if ignoreSet[normalizeBDF(device1.DeviceID)] {
		return ComparisonResult{}
	}

	return compareDevices(device1, device2, logFile)
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

		// Extract device ID from the first line that actually looks like a BDF
		// (short "bb:dd.f" or long "dddd:bb:dd.f" form). lspci -vv's first
		// output line always starts with the BDF, but a stray warning line
		// (e.g. from lspci itself) could otherwise be accepted verbatim as the
		// DeviceID, causing an unrelated later device1.DeviceID != device2.DeviceID
		// mismatch. A line that fails validation is skipped so a genuine BDF
		// line further down is still picked up.
		if currentDevice.DeviceID == "" && len(line) >= 7 {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			candidate := fields[0]
			if !bdfRegex.MatchString(candidate) && !shortBDFRegex.MatchString(candidate) {
				continue
			}
			currentDevice.DeviceID = candidate
			remainingDesc := strings.TrimSpace(strings.TrimPrefix(line, candidate))

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
		"DevCap2", "DevCtl2", "LnkCap2", "LnkCtl2", "LnkSta2":
		return true
	default:
		return false
	}
}

// compareDevices compares two devices and returns the comparison result
func compareDevices(device1, device2 Device, logFile *os.File) ComparisonResult {
	result := ComparisonResult{HasDifferences: false}

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
		logEntry := fmt.Sprintf("%s %s%s | %s changed | before: %s | after: %s\n",
			getCurrentTimestamp(), cycleTag(), device1.DeviceID, key, value1, value2)

		// Track statistics
		// Keyed by normalizeBDF() so multi-domain hosts (where the same device
		// might be seen in long or short form across different call paths) do
		// not fragment this device's count across two different map keys.
		deviceChangeStats[normalizeBDF(device1.DeviceID)]++

		fmt.Fprint(logFile, logEntry)
		fmt.Print(logEntry)

	}

	return result
}

// filterLpotscanErrors filters lpotscan errors and writes to log.
// bufio.Scanner.Text() strips the terminating newline, so we must re-append it
// with Fprintln; writing "%s" would collapse every filtered line into a single
// unreadable run.
func filterLpotscanErrors(errorLogPath string, logFp *os.File) {
	errorLog, err := os.Open(errorLogPath)
	if err != nil {
		// This is the only record of "what changed" for this cycle; if it
		// cannot be opened, say so in reboot.log (not just stdout) so the
		// gap is visible to anyone reviewing the log after the fact.
		logWarnFp(logFp, "could not open %s to extract lspci change details: %v", errorLogPath, err)
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

// isCompactLpotscanChange reports whether line is a compact per-field change
// record written by compareDevices(): "<...bdf> | <field> changed | before:
// ... | after: ...". The field name lives in the second " | "-separated
// segment now that before/after values occupy the trailing two segments, so
// this no longer assumes the field name is the last segment.
func isCompactLpotscanChange(line string) bool {
	field := lspciChangeField(line)
	return field != "" && isComparedLspciField(field)
}

// lspciChangeField extracts the field name from a compact per-field change
// record produced by compareDevices(), or "" if line doesn't match that
// shape. Shared by isCompactLpotscanChange and the result-report parser so
// both agree on what a "compact change" line looks like. Requires at least 4
// " | "-separated segments (not exactly 4): if a before/after value itself
// contains " | ", there will be more than 4 segments, and the trailing two
// are still the before/after values (see lspciChangeParts), so this must not
// reject the line outright.
func lspciChangeField(line string) string {
	parts := strings.Split(line, " | ")
	if len(parts) < 4 {
		return ""
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "changed"))
}

// lspciChangeParts extracts (bdf, field, before, after) from a compact
// per-field change record produced by compareDevices(). ok is false when line
// has fewer than 4 " | "-separated segments or the field isn't a compared
// Dev/Lnk field. Used by buildResultReport() to feed per-field LSPCI changes
// into result.json with the same fidelity CONFIG_SPACE changes already have.
//
// The shape is "<ts prefix> | <field> changed | before: ... | after: ...".
// before/after are taken from the last two segments (not parts[2]/parts[3])
// so a before or after value that itself contains " | " produces more than 4
// segments without being silently dropped by filterLpotscanErrors or the
// result.json parser — it previously required exactly 4 segments, which
// would have discarded the entire line in that case.
func lspciChangeParts(line string) (bdf, field, before, after string, ok bool) {
	parts := strings.Split(line, " | ")
	if len(parts) < 4 {
		return "", "", "", "", false
	}
	field = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "changed"))
	if !isComparedLspciField(field) {
		return "", "", "", "", false
	}
	// parts[0] is "<ts> [Cycle N] <bdf>" (or "<ts> <bdf>" without a cycle tag);
	// the BDF is always the last whitespace-separated token.
	if fields := strings.Fields(parts[0]); len(fields) > 0 {
		bdf = fields[len(fields)-1]
	}
	last := len(parts) - 1
	before = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[last-1]), "before:"))
	after = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[last]), "after:"))
	return bdf, field, before, after, true
}
