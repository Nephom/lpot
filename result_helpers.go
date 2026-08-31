package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func formatRatio(ratio float64) string { return fmt.Sprintf("%.0f%% of cycles", ratio*100) }

func resultStatus(changes int) string {
	if changes > 0 {
		return "FAIL"
	}
	return "PASS"
}

func resultInfoStatus(changes int) string {
	if changes > 0 {
		return "INFO"
	}
	return "PASS"
}

func lineTimestamp(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := time.Parse(logTimeFormat, fields[0]+" "+fields[1]); err == nil {
			return fields[0] + " " + fields[1]
		}
	}
	return ""
}

func lineCycleNumber(line string) int {
	marker := "Cycle "
	start := strings.Index(line, marker)
	if start < 0 {
		return 0
	}
	value := strings.TrimSpace(line[start+len(marker):])
	value = strings.TrimSuffix(value, "]")
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(fields[0])
	return n
}

func parseBDFAfterMarker(line, marker string) string {
	index := strings.Index(line, marker)
	if index < 0 {
		return ""
	}
	value := strings.TrimSpace(line[index+len(marker):])
	if fields := strings.Fields(value); len(fields) > 0 {
		return strings.TrimSuffix(fields[0], ":")
	}
	return ""
}

func parseConfigResultChanges() []configResultChange {
	data, err := os.ReadFile(CONFIG_CHANGES_LOG)
	if err != nil {
		return nil
	}
	var changes []configResultChange
	cycle := 0
	timestamp := ""
	device := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if n := lineCycleNumber(line); n > 0 {
			cycle = n
		}
		if ts := lineTimestamp(line); ts != "" {
			timestamp = ts
		}
		if strings.Contains(line, "Device:") && strings.Contains(line, "config space change detected") {
			device = parseBDFAfterMarker(line, "Device:")
			continue
		}
		if !strings.Contains(line, "Value at offset") || device == "" {
			continue
		}
		fields := strings.Fields(line)
		offset := ""
		before := ""
		after := ""
		for i, field := range fields {
			switch field {
			case "offset":
				if i+1 < len(fields) {
					offset = fields[i+1]
				}
			case "from":
				if i+1 < len(fields) {
					before = fields[i+1]
				}
			case "to":
				if i+1 < len(fields) {
					after = fields[i+1]
				}
			}
		}
		if offset != "" {
			changes = append(changes, configResultChange{cycle, timestamp, device, offset, before, after})
		}
	}
	return changes
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

	ts := getCurrentTimestamp()
	fmt.Fprintf(logFile, "\n%s Affected Cycles:\n", ts)
	if len(snapshot) == 0 {
		fmt.Fprintf(logFile, "%s   (none — every cycle was clean)\n", ts)
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
	fmt.Fprintf(logFile, "%s   Total affected cycles: %d\n", ts, len(order))
}

// writeFilteredDevicesSection prints the compact link-classification evidence
// used to decide which devices entered both comparison paths.
func writeFilteredDevicesSection(logFile *os.File) {
	report := buildClassificationReport(classifiedDevicesGlobal)
	if report.Total == 0 {
		return
	}
	fmt.Fprintf(logFile, "\n%s Link Classification: %s (KEEP %d, SKIP %d, UNVERIFIED %d / %d)\n",
		getCurrentTimestamp(), report.Status, report.Kept, report.Skipped, report.Unverified, report.Total)
	for _, d := range report.Devices {
		fmt.Fprintf(logFile, "  %-12s %-12s cap=%-12s LnkCap=%-16s LnkSta=%-16s %s\n",
			d.BDF, d.Decision, d.PCIeCap, d.LinkCap, d.LinkStatus, d.Reason)
	}
}

func stabilityMessage(name string, changes int) string {
	if changes == 0 {
		return fmt.Sprintf("%s stable", name)
	}
	return fmt.Sprintf("%s changed %d time(s) during the test", name, changes)
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
