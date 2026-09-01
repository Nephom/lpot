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

func lineTimestamp(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		// Only format validity is checked here (the parsed value itself is
		// discarded), so the UTC-default of plain time.Parse would not
		// itself corrupt anything in THIS function. ParseInLocation with
		// time.Local is used anyway for consistency with every other
		// logTimeFormat parse site in this codebase (see
		// loadPersistedCycleChanges and buildResultReport), all of which
		// parse getCurrentTimestamp()'s local-time-formatted strings and
		// therefore must anchor to time.Local, not UTC, to avoid a
		// silent timezone-offset error in duration calculations.
		if _, err := time.ParseInLocation(logTimeFormat, fields[0]+" "+fields[1], time.Local); err == nil {
			return fields[0] + " " + fields[1]
		}
	}
	return ""
}

// lineCycleNumber extracts the cycle number from any log line containing a
// "Cycle N" marker. Real log lines take two shapes:
//   - banner form: "===== Cycle 7 START =====" / "... END (...) =====" where
//     the number is followed by a space and more banner text (no immediate "]").
//   - tag form: "[Cycle 7] Device: ..." / "[Cycle 7] <bdf> | field changed | ..."
//     where the number is immediately followed by "]".
//
// The previous implementation called strings.TrimSuffix on the *entire*
// remainder of the line, which only strips a "]" that happens to be the very
// last character of the line. Every tag-form line (used by CONFIG_CHANGES_LOG
// and LPOTSCAN_LOG, i.e. every config-space and lspci change record) has text
// after the "]", so the suffix trim never fired and strconv.Atoi always failed
// on tokens like "7]", silently returning 0. That made every config-space and
// lspci problem in result.json collapse onto cycle 0, which is never a valid
// cycle key, so those events were dropped from their cycle or from the report
// entirely. Trimming the suffix off the first whitespace-separated token
// (not the whole remainder) handles both shapes correctly.
func lineCycleNumber(line string) int {
	marker := "Cycle "
	start := strings.Index(line, marker)
	if start < 0 {
		return 0
	}
	value := strings.TrimSpace(line[start+len(marker):])
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	token := strings.TrimSuffix(fields[0], "]")
	n, err := strconv.Atoi(token)
	if err != nil {
		return 0
	}
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

// parseLspciResultChanges reads lpotscan.log and extracts one
// lspciResultChange per compact "<bdf> | <field> changed | before: ... |
// after: ..." line compareDevices() writes, mirroring
// parseConfigResultChanges so lspci Dev/Lnk changes get the same BDF/before/
// after fidelity in result.json.
func parseLspciResultChanges() []lspciResultChange {
	data, err := os.ReadFile(LPOTSCAN_LOG)
	if err != nil {
		return nil
	}
	var changes []lspciResultChange
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		bdf, field, before, after, ok := lspciChangeParts(line)
		if !ok {
			continue
		}
		changes = append(changes, lspciResultChange{
			cycle:     lineCycleNumber(line),
			timestamp: lineTimestamp(line),
			device:    bdf,
			field:     field,
			before:    before,
			after:     after,
		})
	}
	return changes
}

// configChangeOccurrenceCounts re-derives the same per-(device, offset)
// distinct-cycle occurrence counts buildResultReport() computes (via its own
// cycleSets map), by re-reading CONFIG_CHANGES_LOG. It is the single shared
// implementation so pci_config_scan.go's live, same-cycle severity decision
// (compareDeviceConfigs' post-loop batch check, Issue #25) and result.json's
// after-the-fact NOTICE/INFO classification always agree on what "count" means for a given
// row: the number of DISTINCT cycles in which that (device, offset) pair was
// seen to change, not the raw number of "Value at offset" lines (a single
// device could in principle log the same offset more than once per cycle,
// though in practice compareAndLogDeviceChanges only does so once).
func configChangeOccurrenceCounts() map[string]int {
	changes := parseConfigResultChanges()
	cycleSets := make(map[string]map[int]struct{}, len(changes))
	for _, change := range changes {
		key := normalizeBDF(change.device) + "\x00" + change.offset
		if cycleSets[key] == nil {
			cycleSets[key] = make(map[int]struct{})
		}
		cycleSets[key][change.cycle] = struct{}{}
	}
	counts := make(map[string]int, len(cycleSets))
	for key, cycles := range cycleSets {
		counts[key] = len(cycles)
	}
	return counts
}

// writeAffectedCyclesSection emits a deduplicated per-cycle breakdown of every
// recorded change, sorted by cycle number. If no changes were recorded the
// section is reduced to a single line noting perfect stability, so summaries
// remain compact for clean runs.
//
// The snapshot is read from CHANGE_LOG_FILE (loadPersistedCycleChanges),
// not from the in-memory changedCycles slice: generateFinalSummary() (the
// only caller) usually runs in a different process than most of the cycles
// it is summarising, since each reboot cycle re-execs the binary. Reading
// the in-memory slice here would only ever show whichever single cycle
// happened to run in the current process, silently losing every earlier
// cycle's recorded changes from the final report.
func writeAffectedCyclesSection(logFile *os.File) {
	snapshot := loadPersistedCycleChanges()

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

// classifyConfigChangeRatio computes the occurrence ratio for a (device,
// offset) change count against the total completed cycles, and reports
// whether that ratio is noteworthy (below rebootFixedThreshold) or benign
// reboot-fixed noise (at or above it). It is the single arithmetic source
// shared by generateConfigSpaceSummary (summary.go, reboot.log's human-
// readable table) and buildResultReport (result.json's CONFIG_SPACE
// problems), so the two artifacts always draw the same benign/noteworthy
// line for the same underlying counts.
func classifyConfigChangeRatio(count, totalCycles int) (ratio float64, noteworthy bool) {
	if totalCycles > 0 {
		ratio = float64(count) / float64(totalCycles)
	}
	// Issue #25: fewer than 2 completed cycles is not enough evidence to call
	// a change "recurring reboot-fixed noise" no matter how high the ratio
	// comes out. A single cycle with one change always computes to a 100%
	// occurrence ratio (count/totalCycles == 1/1), which would otherwise sit
	// at or above rebootFixedThreshold and be misclassified as benign on the
	// very first cycle it is ever seen — exactly the false-negative the
	// issue calls out. At least 2 completed cycles are required before a
	// ratio can be trusted to describe a genuinely recurring pattern.
	if totalCycles < 2 {
		return ratio, true
	}
	return ratio, ratio < rebootFixedThreshold
}

// finalVerdictKind enumerates the three possible end-of-run outcomes.
type finalVerdictKind int

const (
	verdictPerfect finalVerdictKind = iota // no topology/lspci changes, no noteworthy config-space changes
	verdictNotice                          // no topology/lspci changes, but noteworthy config-space changes
	verdictFail                            // topology or lspci changes occurred in at least one cycle
)

// classifyFinalVerdict is the single classifier for the end-of-run outcome,
// shared by generateFinalSummary (reboot.log's "Test Result:" line) and
// buildResultReport (result.json's top-level status/message), so the two
// artifacts can never disagree about whether a run was a full pass, a
// pass-with-notice, or a fail. cyclesWithChanges counts cycles where a
// topology or lspci difference was recorded (a confirmed FAIL);
// hasNoticeEvents reports whether any cycle recorded a NOTICE-severity event
// (e.g. a device that could not be read — Issue #23) that never escalated to
// a confirmed FAIL; noteworthyConfigChanges reports whether any config-space
// change fell below the reboot-fixed threshold.
func classifyFinalVerdict(cyclesWithChanges int, hasNoticeEvents bool, noteworthyConfigChanges bool) finalVerdictKind {
	switch {
	case cyclesWithChanges > 0:
		return verdictFail
	case hasNoticeEvents || noteworthyConfigChanges:
		return verdictNotice
	default:
		return verdictPerfect
	}
}

func stabilityMessage(name string, changes int) string {
	if changes == 0 {
		return fmt.Sprintf("%s stable", name)
	}
	return fmt.Sprintf("%s changed %d time(s) during the test", name, changes)
}

func buildResultReport(checkpoint bool, statusOverride string) resultReport {
	// completedCyclesFromLog is the single authoritative reboot-cycle count,
	// parsed once here and shared as the ratio denominator for config-space
	// noteworthy/benign classification below. generateConfigSpaceSummary()
	// (summary.go) is handed the identical number by generateFinalSummary(),
	// so reboot.log's "Noteworthy changes" verdict and result.json's
	// ConfigSpace check can never disagree about how many cycles actually ran.
	_, completedCyclesFromLog, _, _, _, _ := parseRebootLogForStats()
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
				// See loadPersistedCycleChanges (reboot_cycle.go) for why
				// this must anchor to time.Local, not UTC: getCurrentTimestamp()
				// formats every log timestamp with time.Now() in the host's
				// local timezone, and logTimeFormat itself carries no zone
				// offset.
				startedAt, _ = time.ParseInLocation(logTimeFormat, ts, time.Local)
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
			// "(notice)" must be checked BEFORE the bare "changes detected"
			// substring match: cycleEndStatus (reboot_cycle.go) can print
			// "changes detected (notice)", which also contains the plain
			// "changes detected" substring. Checking the more specific marker
			// first prevents a NOTICE-only cycle (e.g. a device that could not
			// be read this cycle, with no topology/lspci FAIL) from being
			// misclassified as FAIL here (Issue #25's "-p / severity must not
			// collapse to FAIL or to clean" requirement, applied consistently
			// to the per-cycle status too).
			switch {
			case strings.Contains(line, "changes detected (notice)"):
				cycle.Status = "NOTICE"
			case strings.Contains(line, "changes detected"):
				cycle.Status = "FAIL"
			case strings.Contains(line, "config noise"):
				cycle.Status = "INFO"
			default:
				cycle.Status = "PASS"
			}
		}
		if strings.Contains(line, "NEW Device:") || strings.Contains(line, "REMOVED Device:") || strings.Contains(line, "REAPPEARED Device:") {
			cycle.Topology = "FAIL"
			problem := resultProblem{Severity: "FAIL", Category: "TOPOLOGY", Cycle: current, Timestamp: lineTimestamp(line), Message: line}
			switch {
			case strings.Contains(line, "NEW Device:"):
				problem.BDF = parseBDFAfterMarker(line, "NEW Device:")
			case strings.Contains(line, "REMOVED Device:"):
				problem.BDF = parseBDFAfterMarker(line, "REMOVED Device:")
			default:
				problem.BDF = parseBDFAfterMarker(line, "REAPPEARED Device:")
			}
			problem.DetailsLog = REBOOT_LOG
			cycle.Events = append(cycle.Events, problem)
		}
		if strings.Contains(line, "UNAVAILABLE Device:") {
			// A device that could not be read this cycle (Issue #23): NOTICE
			// severity, distinct from a confirmed TOPOLOGY FAIL. Only raises
			// cycle.Status to NOTICE, never downgrades an existing FAIL.
			if cycle.Status == "PASS" || cycle.Status == "RUNNING" || cycle.Status == "INFO" {
				cycle.Status = "NOTICE"
			}
			problem := resultProblem{
				Severity: "NOTICE", Category: "AVAILABILITY", Cycle: current, Timestamp: lineTimestamp(line),
				BDF: parseBDFAfterMarker(line, "UNAVAILABLE Device:"), Message: line, DetailsLog: REBOOT_LOG,
			}
			cycle.Events = append(cycle.Events, problem)
		}
		if strings.Contains(line, "Had devices changed") {
			cycle.LSPCI = "FAIL"
			cycle.Status = "FAIL"
			// Per-field detail (BDF, before/after) is attached below from
			// parseLspciResultChanges() once lpotscan.log has been parsed, so
			// this cycle gets one specific problem per changed field instead
			// of a single generic line.
		}
	}
	cyclesWithNotices := 0
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
		if cycle.Status == "NOTICE" {
			cyclesWithNotices++
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
		count := len(cycleSets[change.device+"\x00"+change.offset])
		ratio, noteworthyRow := classifyConfigChangeRatio(count, completedCyclesFromLog)
		severity := "INFO"
		classification := "benign reboot-fixed register reset"
		if noteworthyRow {
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
	// ConfigNoise is purely informational: it is "INFO" whenever any benign
	// (reboot-fixed) register reset was observed, and "PASS" otherwise. Inlined
	// at the point of use since it previously lived in a one-line helper
	// (resultInfoStatus) with no other caller.
	configNoiseStatus := "PASS"
	if benignConfig > 0 {
		configNoiseStatus = "INFO"
	}

	// lspci Dev/Lnk field changes get the same per-BDF, before/after fidelity
	// as config-space changes, parsed straight from lpotscan.log rather than
	// the single generic "Had devices changed" line in reboot.log. Every
	// field change is inherently noteworthy (recordCycleChange, not
	// recordCycleNoise, is what triggers "Had devices changed" in the first
	// place), so severity is always FAIL.
	lspciFieldChanges := parseLspciResultChanges()
	lspciProblems := make([]resultProblem, 0, len(lspciFieldChanges))
	configChangeCounts := make(map[string]int, len(configChanges))
	for _, change := range configChanges {
		configChangeCounts[normalizeBDF(change.device)]++
	}
	for _, change := range lspciFieldChanges {
		problem := resultProblem{
			Severity: "FAIL", Category: "LSPCI", Cycle: change.cycle,
			Timestamp: change.timestamp, BDF: change.device,
			Message:    fmt.Sprintf("%s changed (before: %s, after: %s)", change.field, change.before, change.after),
			DetailsLog: LPOTSCAN_LOG,
		}
		lspciProblems = append(lspciProblems, problem)
		if cycle := cycles[change.cycle]; cycle != nil {
			cycle.Events = append(cycle.Events, problem)
		}
	}

	sort.Ints(cycleOrder)
	orderedCycles := make([]resultCycle, 0, len(cycleOrder))
	problems := make([]resultProblem, 0, len(configProblems)+len(lspciProblems))
	for _, number := range cycleOrder {
		cycle := *cycles[number]
		orderedCycles = append(orderedCycles, cycle)
		problems = append(problems, cycle.Events...)
	}
	if len(problems) == 0 {
		problems = append(append(problems, configProblems...), lspciProblems...)
	}
	status := "RUNNING"
	message := "Test continues after reboot"
	if !checkpoint {
		if totalCycles == 0 {
			status = "INCOMPLETE"
			message = "No completed reboot cycle was recorded"
		} else {
			// classifyFinalVerdict is the same classifier generateFinalSummary()
			// (summary.go) uses for reboot.log's "Test Result:" line, so the two
			// artifacts never disagree about pass/notice/fail for the same run.
			switch classifyFinalVerdict(cyclesWithChanges, cyclesWithNotices > 0, noteworthyConfig > 0) {
			case verdictFail:
				status = "FAIL"
				message = "Noteworthy PCI topology, lspci, or config-space changes were detected"
			case verdictNotice:
				status = "PASS"
				// The message must name the ACTUAL source of the notice: it can be
				// an unconfirmed raw config-space change, one or more cycles where
				// a still-enumerated device could not be read (Issue #23), or
				// both — pointing the operator only at "config-space" when the
				// real cause was an unreadable device would send them to the
				// wrong section of reboot.log.
				switch {
				case noteworthyConfig > 0 && cyclesWithNotices > 0:
					message = "PCI topology and lspci capability are stable; config-space and device-availability notices require review"
				case cyclesWithNotices > 0:
					message = "PCI topology and lspci capability are stable; one or more cycles had a device that could not be read and require review"
				default:
					message = "PCI topology and lspci capability are stable; config-space notices require review"
				}
			default:
				status = "PASS"
				message = "PCI topology, lspci capability, and PCI config are stable"
			}
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
	// Annotate the classification list with whether raw config-space ever
	// changed for that device, so the dashboard can offer a "changed only"
	// filter without a second API round-trip.
	classification := classificationReportFromBaseline()
	for i := range classification.Devices {
		if count := configChangeCounts[normalizeBDF(classification.Devices[i].BDF)]; count > 0 {
			classification.Devices[i].ConfigChanged = true
			classification.Devices[i].ConfigChangeCount = count
		}
	}
	result := resultReport{
		SchemaVersion: 1, Version: version, RunID: runID, Status: status,
		Checkpoint: checkpoint, Message: message, UpdatedAt: time.Now().Format(time.RFC3339),
		TotalCycles: totalCycles, CompletedCycles: completed,
		SuccessfulCycles: completed - failed, FailedCycles: failed,
		Classification: classification,
		Checks: resultChecks{
			Topology:     resultCheck{Status: resultStatus(topologyChanges), ChangedCycles: topologyChanges, Message: stabilityMessage("topology", topologyChanges)},
			LSPCI:        resultCheck{Status: resultStatus(lspciChanges), ChangedCycles: lspciChanges, Message: stabilityMessage("Dev/Lnk", lspciChanges)},
			ConfigSpace:  resultCheck{Status: configSpaceResultStatus(noteworthyConfig), Noteworthy: noteworthyConfig, Message: configSpaceStabilityMessage(noteworthyConfig)},
			ConfigNoise:  resultCheck{Status: configNoiseStatus, BenignChanges: benignConfig, Message: fmt.Sprintf("%d recurring benign register change(s)", benignConfig)},
			Availability: resultCheck{Status: configSpaceResultStatus(cyclesWithNotices), Noteworthy: cyclesWithNotices, Message: fmt.Sprintf("%d cycle(s) had a device that could not be read", cyclesWithNotices)},
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
