package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	ts := getCurrentTimestamp()
	fmt.Fprintf(logFile, "\n%s ========== Test Session Summary ==========\n", ts)
	fmt.Fprintf(logFile, "%s Test Duration: %.1f hours (%s to %s)\n",
		ts, duration.Hours(), actualStartTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(logFile, "%s Total Reboot Cycles: %d\n", ts, actualTotalCycles)

	// Calculate failed reboots: any cycle with device changes is considered failed
	failedReboots := actualCyclesWithChanges
	successfulReboots := actualTotalCycles - failedReboots

	fmt.Fprintf(logFile, "%s Successful Reboots: %d\n", ts, successfulReboots)
	fmt.Fprintf(logFile, "%s Failed Reboots: %d\n\n", ts, failedReboots)

	fmt.Fprintf(logFile, "%s Device Stability Analysis:\n", ts)
	var changePercentage float64
	if actualTotalCycles > 0 {
		changePercentage = float64(actualCyclesWithChanges) / float64(actualTotalCycles) * 100
	}
	fmt.Fprintf(logFile, "%s   Cycles with device changes: %d (%.1f%%)\n",
		ts, actualCyclesWithChanges, changePercentage)
	var noChangePercentage float64
	if actualTotalCycles > 0 {
		noChangePercentage = float64(actualTotalCycles-actualCyclesWithChanges) / float64(actualTotalCycles) * 100
	}
	fmt.Fprintf(logFile, "%s   Cycles with no changes: %d (%.1f%%)\n",
		ts, actualTotalCycles-actualCyclesWithChanges, noChangePercentage)
	fmt.Fprintf(logFile, "\n")
	fmt.Fprintf(logFile, "%s   Device topology changes: %d cycles\n", ts, actualTopologyChanges)
	fmt.Fprintf(logFile, "%s   lspci capability changes: %d cycles\n", ts, actualLspciChanges)
	classification := classificationReportFromBaseline()
	rawConfigStatus := "STABLE"
	if cyclesWithConfigChanges > 0 {
		rawConfigStatus = "CHANGED"
	}
	lspciStatus := "STABLE"
	if actualLspciChanges > 0 {
		lspciStatus = "CHANGED"
	}
	fmt.Fprintf(logFile, "\n%s Validation Coverage:\n", ts)
	fmt.Fprintf(logFile, "%s   PCIe Link-capable devices: KEEP %d / SKIP %d / UNVERIFIED %d\n",
		ts, classification.Kept, classification.Skipped, classification.Unverified)
	fmt.Fprintf(logFile, "%s   Raw config-space comparison: %s\n", ts, rawConfigStatus)
	fmt.Fprintf(logFile, "%s   lspci Dev/Lnk comparison: %s\n", ts, lspciStatus)
	if classification.Unverified > 0 {
		fmt.Fprintf(logFile, "%s   Warning: some devices could not be fully checked, so this PASS result may not be accurate.\n", ts)
	}

	if mostAffectedDevice != "" {
		fmt.Fprintf(logFile, "%s     - Most affected device: %s (%d changes)\n", ts, mostAffectedDevice, maxDeviceChanges)
	}
	if mostChangedField != "" {
		fmt.Fprintf(logFile, "%s     - Most changed field: %s (%d occurrences)\n", ts, mostChangedField, maxFieldChanges)
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
		fmt.Fprintf(logFile, "\n%s Test Result: COMPLETED SUCCESSFULLY - PERFECT STABILITY\n", ts)
		if cyclesWithConfigChanges > 0 {
			fmt.Fprintf(logFile, "%s No noteworthy config-space changes across %d reboot cycles.\n", ts, actualTotalCycles)
			fmt.Fprintf(logFile, "%s Some hardware settings reset to the same value every reboot. This is normal and not a problem.\n", ts)
		} else {
			fmt.Fprintf(logFile, "%s All PCI devices stayed exactly the same across %d reboots. No issues found.\n", ts, actualTotalCycles)
		}
	case actualCyclesWithChanges == 0 && noteworthyConfigChanges:
		fmt.Fprintf(logFile, "\n%s Test Result: COMPLETED WITH NOTICE\n", ts)
		fmt.Fprintf(logFile, "%s The devices themselves did not change across %d reboots, but some settings changed in an unusual way. Please check the 'Noteworthy changes' section above.\n", ts, actualTotalCycles)
	default:
		fmt.Fprintf(logFile, "\n%s Test Result: COMPLETED - REVIEW NOTEWORTHY CHANGES\n", ts)
		fmt.Fprintf(logFile, "%s Some devices changed or disappeared during the %d reboots. See 'Affected Cycles' above for details.\n", ts, actualTotalCycles)
	}
	fmt.Fprintf(logFile, "%s ==========================================\n", ts)
	if err := writeResultReport(false); err != nil {
		fatalOperation("Finalization failed: cannot publish /lpot/result.json", err,
			"check /lpot permissions and available disk space before reviewing the report")
	}

	// Clean up PCI config binary files after test completion
	initialFile := "/lpot/initial.bin"
	currentFile := "/lpot/current.bin"

	if fileExists(initialFile) {
		if err := os.Remove(initialFile); err != nil {
			logWarn("could not delete %s: %v", initialFile, err)
		} else {
			fmt.Printf("Cleaned up: %s\n", initialFile)
		}
	}

	if fileExists(currentFile) {
		if err := os.Remove(currentFile); err != nil {
			logWarn("could not delete %s: %v", currentFile, err)
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
		logWarn("could not read reboot.log for stats: %v", err)
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
		if strings.Contains(line, "#########Start to test#########") && totalCycles > 0 {
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
	ts := getCurrentTimestamp()
	fmt.Fprintf(logFile, "\n%s ========== PCI Config Space Analysis Summary ==========\n", ts)

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

	fmt.Fprintf(logFile, "%s Total devices monitored: %d\n", ts, totalDevices)

	// Report raw change occurrences alongside the number of distinct reboot
	// cycles in which any change was seen. The previous "%% of cycles" figure
	// divided an occurrence count (one per device-change event, many per cycle)
	// by the cycle count, which is not a meaningful percentage.
	var cyclesAffectedPct float64
	if totalCycles > 0 {
		cyclesAffectedPct = float64(len(cyclesAffected)) / float64(totalCycles) * 100
	}
	fmt.Fprintf(logFile, "%s Config space changes detected: %d occurrences across %d/%d cycles (%.1f%%)\n",
		ts, configChangesFound, len(cyclesAffected), totalCycles, cyclesAffectedPct)

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
		fmt.Fprintf(logFile, "\n\u26a0\ufe0f  Changes that happened only sometimes (may be a real problem):\n")
		if noteworthy {
			writeRows("", volatileRows)
		} else {
			fmt.Fprintf(logFile, "    \u2014 None. Every change seen was just a normal reset that happens on every reboot \u2014 not a problem.\n")
		}

		writeRows("Changes that happen on almost every reboot (normal, not a problem)", fixedRows)

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
		fmt.Fprintf(logFile, "%s Stable devices: %d (%.1f%%)\n", ts, stableDevices, stablePct)
		fmt.Fprintf(logFile, "%s Reboot-fixed-only devices: %d (%.1f%%)  <- benign boot-time noise\n", ts, len(fixedDevices), fixedPct)
		fmt.Fprintf(logFile, "%s Truly volatile devices: %d (%.1f%%)  <- attention needed\n", ts, len(volatileDevices), volPct)
	} else {
		fmt.Fprintf(logFile, "\n%s All PCI devices maintained stable configuration throughout test.\n", ts)
		fmt.Fprintf(logFile, "%s No configuration space changes detected (excluding timer-related registers).\n", ts)
	}
	return noteworthy
}
