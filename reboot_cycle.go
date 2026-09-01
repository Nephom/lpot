package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
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
	entry := cycleChange{
		Cycle:      currentCycle.Load(),
		Time:       time.Now(),
		Reason:     reason,
		Noteworthy: noteworthy,
	}
	changedCyclesMu.Lock()
	changedCycles = append(changedCycles, entry)
	changedCyclesMu.Unlock()

	// Persist immediately: each reboot cycle is a brand-new process, so the
	// in-memory changedCycles slice above only ever holds this cycle's
	// events by the time the NEXT cycle's process starts. Appending this
	// entry to CHANGE_LOG_FILE is what lets writeAffectedCyclesSection()
	// reconstruct the complete, multi-cycle "Affected Cycles" narrative at
	// the end of a multi-day run. Best-effort: a failure here degrades the
	// final summary's completeness but must never abort the cycle itself.
	if err := appendChangeLogEntry(entry); err != nil {
		logWarn("could not persist change-log entry to %s: %v", CHANGE_LOG_FILE, err)
	}
}

// persistedCycleChange is the on-disk JSON representation of one
// cycleChange event, one per line in CHANGE_LOG_FILE.
type persistedCycleChange struct {
	Cycle      int64  `json:"cycle"`
	Time       string `json:"time"`
	Reason     string `json:"reason"`
	Noteworthy bool   `json:"noteworthy"`
}

// appendChangeLogEntry appends one JSON line to CHANGE_LOG_FILE. Using
// O_APPEND (via openSecureAppend) means a later cycle's write can never
// corrupt or truncate an earlier cycle's already-persisted entries, even if
// the process is killed mid-write on some other line.
func appendChangeLogEntry(entry cycleChange) error {
	fp, err := openSecureAppend(CHANGE_LOG_FILE, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()
	data, err := json.Marshal(persistedCycleChange{
		Cycle:      entry.Cycle,
		Time:       entry.Time.Format(logTimeFormat),
		Reason:     entry.Reason,
		Noteworthy: entry.Noteworthy,
	})
	if err != nil {
		return err
	}
	if _, err := fp.Write(append(data, '\n')); err != nil {
		return err
	}
	return fp.Sync()
}

// loadPersistedCycleChanges reads every event ever recorded across the
// entire run from CHANGE_LOG_FILE. A missing file (fresh run) or a corrupt
// line (best-effort skipped, not fatal) never blocks the caller: this data
// feeds only the human-readable "Affected Cycles" summary, never a
// PASS/FAIL verdict.
func loadPersistedCycleChanges() []cycleChange {
	data, err := os.ReadFile(CHANGE_LOG_FILE)
	if err != nil {
		return nil
	}
	var out []cycleChange
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var p persistedCycleChange
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			continue
		}
		// getCurrentTimestamp() (lifecycle.go) formats with time.Now(),
		// which is always in the host's LOCAL timezone. logTimeFormat
		// itself carries no zone offset, so parsing with a bare
		// time.Parse (which defaults to UTC) would silently reinterpret a
		// local-time string as UTC, corrupting every downstream duration
		// calculation by exactly the host's UTC offset. ParseInLocation
		// with time.Local matches the writer's timezone and keeps this
		// round-trip lossless.
		t, _ := time.ParseInLocation(logTimeFormat, p.Time, time.Local)
		out = append(out, cycleChange{Cycle: p.Cycle, Time: t, Reason: p.Reason, Noteworthy: p.Noteworthy})
	}
	return out
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

// cycleEndStatus is the single source of truth for how a cycle is labelled
// at its end banner ('===== Cycle N END (<status>) ====='). It is also the
// only place that decides whether a cycle counts as "noteworthy" for the -p
// stop-on-difference gate, so the banner text and the -p behaviour can never
// diverge again: a cycle that reads "clean (config noise)" in reboot.log by
// definition does not trigger -p, because both consult this function.
func cycleEndStatus(noteworthy, configNoise bool) string {
	switch {
	case noteworthy:
		return "changes detected"
	case configNoise:
		return "clean (config noise)"
	default:
		return "clean"
	}
}

// cycleRequiresStop reports whether -p should stop and disable the service
// for the current cycle. Only genuinely noteworthy changes (topology, lspci
// capability, or a classification change from writeClassificationReportToLog)
// qualify; benign config-space reboot-noise alone does not, matching the
// banner's "clean (config noise)" label produced by cycleEndStatus above.
func cycleRequiresStop(noteworthy, configNoise bool) bool {
	return noteworthy
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

	// Validate BDF before passing to lspci. The value is sourced from sysfs
	// directory listings so it should always match bdfRegex, but refusing a
	// malformed value here removes an argv-injection vector outright.
	if !bdfRegex.MatchString(bdf) {
		return fmt.Errorf("refusing to invoke lspci with malformed BDF %q", bdf)
	}
	output, err := runExternal(lspciTimeout, lspciPath, "-s", bdf, "-vv")
	if err != nil {
		return err
	}

	return writeFileNoFollow(filename, output, 0644)
}

// vendorDeviceBracketRegex matches the "[XXXX:YYYY]" vendor:device hex ID
// that lspci prints on the device summary line, e.g.:
//
//	03:00.0 Non-Volatile memory controller [0108]: Vendor Corp Device [144d:a80a] (rev 01)
//
// There can be more than one bracketed hex pair on the line (a class-code
// bracket often appears too), so callers should take the last match.
var vendorDeviceBracketRegex = regexp.MustCompile(`\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]`)

// vendorDeviceFromLspciDump extracts the vendor:device hex ID from the first
// line of a saved lspci -vv dump (as written to *_init.txt). It is used to
// best-effort recognise a device that "relocated" (disappeared at one BDF,
// appeared at another) rather than genuinely different hardware, since a
// removed device's sysfs entry is already gone and can't be re-queried.
func vendorDeviceFromLspciDump(path string) (vendor, device uint16, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	firstLine := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		firstLine = data[:i]
	}
	matches := vendorDeviceBracketRegex.FindAllStringSubmatch(string(firstLine), -1)
	if len(matches) == 0 {
		return 0, 0, false
	}
	last := matches[len(matches)-1]
	v, err1 := strconv.ParseUint(last[1], 16, 16)
	d, err2 := strconv.ParseUint(last[2], 16, 16)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uint16(v), uint16(d), true
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

	// Step 1: Generate this cycle's current device snapshot (<bdf>.txt) for
	// every bdf FIRST, before checking for removed devices. This ordering is
	// load-bearing, not cosmetic: cleanupBDFFiles() (called at the end of
	// every cycle in main()) deletes every <bdf>.txt while keeping
	// <bdf>_init.txt, and each reboot cycle runs in a brand-new process. If
	// the "removed device" check below ran BEFORE this snapshot step, it
	// would always find last cycle's already-deleted <bdf>.txt missing and
	// misreport every single device as REMOVED on every cycle after the
	// first — silently disabling the lspci Dev/Lnk comparison entirely
	// (allUnchanged would never be true) and, under -p, stopping the test on
	// the very second cycle. Do not reorder these two steps.
	//
	// snapshotFailedBDFs collects devices whose current-cycle lspci snapshot
	// could not be captured (e.g. a transient link reset or lspci timeout).
	// This is a per-device, non-fatal condition: one flaky device must not
	// abort the whole cycle (and with it, potentially the rest of a 48h run).
	// It is recorded as a plain warning only — it does not affect this
	// cycle's PASS/FAIL verdict, since the device may simply have been mid-
	// reset when queried and could be perfectly stable a moment later.
	var snapshotFailedBDFs []string
	for _, bdf := range bdfs {
		if err := executeLspci(bdf, ".txt"); err != nil {
			snapshotFailedBDFs = append(snapshotFailedBDFs, bdf)
			logWarnFp(logFp, "could not capture this cycle's lspci snapshot for %s (%v); this device is skipped from lspci comparison this cycle only and does not affect the pass/fail result", bdf, err)
		}
	}

	// Step 2: Check for removed devices, now that every reachable bdf's
	// <bdf>.txt has been (re)created above. Removed devices cannot be
	// queried via sysfs (they're gone), so we only emit the BDF; lspci dump
	// for this BDF is already in *_init.txt and is appended to the log by
	// filterLpotscanErrors. A device whose snapshot failed this cycle
	// (snapshotFailedBDFs) is NOT treated as removed: a transient lspci
	// timeout is not evidence the device disappeared from sysfs, and
	// conflating the two would turn a flaky read into a false topology
	// alarm.
	failedThisCycle := make(map[string]bool, len(snapshotFailedBDFs))
	for _, bdf := range snapshotFailedBDFs {
		failedThisCycle[normalizeBDF(bdf)] = true
	}
	for _, initFile := range initFiles {
		filename := filepath.Base(initFile)
		bdf := strings.TrimSuffix(filename, "_init.txt")
		if failedThisCycle[normalizeBDF(bdf)] {
			continue
		}
		currentFile := filepath.Join(TMP_DIR, bdf+".txt")

		if !fileExists(currentFile) {
			removedDevices = append(removedDevices, bdf)
			fmt.Fprintf(logFp, "%s %sREMOVED Device: %s\n", getCurrentTimestamp(), cycleTag(), bdf)
			recordCycleChange(fmt.Sprintf("device removed: %s", bdf))
		}
	}

	// Step 3: Check for new devices. New devices are present in sysfs, so
	// enrich the log line with vendor/device/class to help identify which
	// hardware appeared without requiring a separate lspci. Skip bdfs whose
	// snapshot failed this cycle: without a <bdf>.txt there is nothing to
	// compare, and the device may simply not have been captured rather than
	// genuinely be new.
	for _, bdf := range bdfs {
		if failedThisCycle[normalizeBDF(bdf)] {
			continue
		}
		initFile := filepath.Join(TMP_DIR, bdf+"_init.txt")
		if !fileExists(initFile) {
			newDevices = append(newDevices, bdf)
			fmt.Fprintf(logFp, "%s %sNEW Device: %s\n", getCurrentTimestamp(), cycleTag(), describePCIBDF(bdf))
			recordCycleChange(fmt.Sprintf("device added: %s", bdf))
		}
	}

	allUnchanged := (len(newDevices) == 0 && len(removedDevices) == 0)
	overallSuccess := true

	// Best-effort match a removed BDF with a new BDF that reports the same
	// vendor:device ID, and add one extra clarifying log line. This does not
	// change whether -p stops the service: both BDFs are already recorded as
	// noteworthy changes above (REMOVED Device / NEW Device), so this note is
	// purely a readability aid for the common "device relocated to a
	// different slot/BDF" case.
	if len(removedDevices) > 0 && len(newDevices) > 0 {
		// consumedNewBDF tracks which new BDFs have already been matched to an
		// old BDF, so two removed devices sharing the same vendor:device ID
		// (common on multi-function NICs) cannot both claim the same new BDF
		// and produce duplicate or contradictory relocation notes.
		consumedNewBDF := make(map[string]bool, len(newDevices))
		for _, oldBDF := range removedDevices {
			oldVendor, oldDevice, oldOK := vendorDeviceFromLspciDump(filepath.Join(TMP_DIR, oldBDF+"_init.txt"))
			if !oldOK {
				continue
			}
			for _, newBDF := range newDevices {
				if consumedNewBDF[newBDF] {
					continue
				}
				newInfo, newOK := readPCIDeviceInfo(newBDF)
				if newOK && oldVendor == newInfo.Vendor && oldDevice == newInfo.Device {
					fmt.Fprintf(logFp, "%s %sNOTE: device %04x:%04x may have relocated from %s to %s\n",
						getCurrentTimestamp(), cycleTag(), oldVendor, oldDevice, oldBDF, newBDF)
					consumedNewBDF[newBDF] = true
					break
				}
			}
		}
	}

	// Rebase the lspci-text topology baseline for every REMOVED/NEW device
	// found this cycle, so the SAME disappearance/appearance is not
	// rediscovered and re-reported on every subsequent cycle for the rest
	// of the run. Without this, a device that disappears once would leave
	// its stale <bdf>_init.txt in place forever, so every later cycle's
	// removed-device check (Step 2 above) would find its <bdf>.txt missing
	// again and re-flag it as REMOVED — permanently keeping allUnchanged
	// false and silently disabling the lspci Dev/Lnk comparison
	// (the `if allUnchanged` branch below) for the rest of the run.
	// Symmetrically, a device that appears once would never get an
	// <bdf>_init.txt baseline of its own, so every later cycle would find it
	// still missing and re-flag it as NEW forever.
	for _, bdf := range removedDevices {
		// The device is gone from sysfs; there is nothing to rebase to, so
		// simply retire its stale baseline. os.Remove is used (not a rename)
		// because vendorDeviceFromLspciDump() above has already consumed
		// this file for this cycle's relocation-note best-effort match; nothing
		// downstream needs it again once this cycle's decisions are logged.
		if err := os.Remove(filepath.Join(TMP_DIR, bdf+"_init.txt")); err != nil && !os.IsNotExist(err) {
			logWarnFp(logFp, "could not retire stale topology baseline for removed device %s: %v", bdf, err)
		}
	}
	for _, bdf := range newDevices {
		// The device is now present; adopt this cycle's snapshot as its new
		// baseline so the NEXT cycle compares against "the device as it
		// looked when it first appeared" instead of re-discovering the same
		// appearance forever.
		src := filepath.Join(TMP_DIR, bdf+".txt")
		dst := filepath.Join(TMP_DIR, bdf+"_init.txt")
		data, err := os.ReadFile(src)
		if err != nil {
			logWarnFp(logFp, "could not read snapshot to establish topology baseline for new device %s: %v", bdf, err)
			continue
		}
		if err := writeFileNoFollow(dst, data, 0644); err != nil {
			logWarnFp(logFp, "could not establish topology baseline for new device %s: %v", bdf, err)
		}
	}

	// Track device topology changes. A topology change always interrupts any
	// active "clean streak" summary that may have been aggregating.
	if !allUnchanged {
		flushCleanStreak(logFp)
	}

	if allUnchanged {
		// Load ignore list for lpotscan
		ignoreSet, err := loadIgnoreList(IGNORE_LIST_FILE)
		if err != nil {
			logWarn("could not load ignore list: %v", err)
			ignoreSet = make(map[string]bool)
		}

		// Compare each device using lpotscan logic
		lpotscanFile, err := openSecureAppend(LPOTSCAN_LOG, 0644)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", LPOTSCAN_LOG, err)
		}
		defer lpotscanFile.Close()

		var fieldChanges []DeviceFieldChange
		for _, bdf := range bdfs {
			if ignoreSet[normalizeBDF(bdf)] {
				continue
			}
			initFile := filepath.Join(TMP_DIR, bdf+"_init.txt")
			currentFile := filepath.Join(TMP_DIR, bdf+".txt")

			if !fileExists(initFile) || !fileExists(currentFile) {
				continue
			}

			result := compareDeviceFiles(initFile, currentFile, ignoreSet, lpotscanFile)
			fieldChanges = append(fieldChanges, result.Changes...)
			if result.HasDifferences {
				overallSuccess = false
				// Rebase this device's Dev/Lnk baseline to the value just
				// logged as changed. Without this, a link that trains down
				// once (e.g. x8 -> x4) and then stays stable at x4 would be
				// re-reported as "changed" on every subsequent cycle for
				// the rest of the run, because _init.txt would forever keep
				// comparing against the ORIGINAL x8 value instead of the
				// device's current, stable state. Rebasing after logging
				// the difference means a genuinely new change (e.g. a
				// later x4 -> x2 drop, or recovering back to x8) is still
				// correctly detected and logged exactly once, mirroring
				// the topology baseline rebase for NEW/REMOVED devices
				// above and compareDeviceConfigs()' initial.bin rebase.
				if data, err := os.ReadFile(currentFile); err != nil {
					logWarnFp(logFp, "could not read snapshot to rebase Dev/Lnk baseline for %s: %v", bdf, err)
				} else if err := writeFileNoFollow(initFile, data, 0644); err != nil {
					logWarnFp(logFp, "could not rebase Dev/Lnk baseline for %s: %v", bdf, err)
				}
			}
			if result.Error != nil {
				logWarnFp(logFp, "comparison error for %s: %v", bdf, result.Error)
				if stopService {
					recordDeviceFieldChanges(fieldChanges)
					return result.Error
				}
			}
		}

		// Persist all Dev/Lnk statistics for this cycle in one read-modify-write.
		recordDeviceFieldChanges(fieldChanges)

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
			recordCycleChange("lspci differences detected")
			filterLpotscanErrors(LPOTSCAN_LOG, logFile)
			logFile.Sync()
		} else {
			// "No devices changed" is repeated every cycle; collapse
			// consecutive clean cycles into a single line with a running
			// counter so the log stays readable across 48 h runs.
			noteCleanCycle(logFile, timeStr)
		}
	}

	return nil
}

// cleanCycleStreak tracks how many consecutive cycles reported "No devices
// changed". A single summary line is emitted for long clean runs so reboot.log
// doesn't grow a page per idle cycle.
//
// The counter itself is persisted to CLEAN_STREAK_STATE_FILE (loaded lazily on
// first use, saved after every update) because each reboot cycle runs in a
// brand-new process: systemd re-execs /lpot/reboot.sh after every reboot, so
// an in-memory-only counter would reset on every single cycle and the log's
// own "N cycles clean (Cycle X..Y)" claim of a multi-cycle streak would never
// actually be true (N would always be 1). Persisting to disk lets the streak
// genuinely accumulate across reboots, matching what the log line claims.
var (
	cleanCycleMu     sync.Mutex
	cleanCycleStart  int64
	cleanCycleLast   int64
	cleanCycleCount  int
	cleanCycleHeader bool
	cleanCycleLoaded bool
)

// cleanStreakState is the on-disk representation of the in-progress clean
// streak, persisted so it survives the reboot between cycles.
type cleanStreakState struct {
	Start  int64 `json:"start"`
	Last   int64 `json:"last"`
	Count  int   `json:"count"`
	Active bool  `json:"active"`
}

// loadCleanStreakStateLocked reads CLEAN_STREAK_STATE_FILE into the package
// vars exactly once per process (cleanCycleLoaded guards repeat loads). Must
// be called with cleanCycleMu held. A missing or corrupt file is treated as
// "no streak in progress" rather than an error, since the state file is
// best-effort bookkeeping, not authoritative data.
func loadCleanStreakStateLocked() {
	if cleanCycleLoaded {
		return
	}
	cleanCycleLoaded = true
	data, err := os.ReadFile(CLEAN_STREAK_STATE_FILE)
	if err != nil {
		return
	}
	var state cleanStreakState
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	cleanCycleStart = state.Start
	cleanCycleLast = state.Last
	cleanCycleCount = state.Count
	cleanCycleHeader = state.Active
}

// saveCleanStreakStateLocked persists the current streak state. Must be
// called with cleanCycleMu held. Failures are logged but not fatal: losing
// the persisted streak only degrades a cosmetic "N cycles clean" count, it
// never affects PASS/FAIL correctness.
func saveCleanStreakStateLocked() {
	state := cleanStreakState{Start: cleanCycleStart, Last: cleanCycleLast, Count: cleanCycleCount, Active: cleanCycleHeader}
	data, err := json.Marshal(state)
	if err != nil {
		logWarn("could not encode clean streak state: %v", err)
		return
	}
	if err := writeFileNoFollow(CLEAN_STREAK_STATE_FILE, data, 0644); err != nil {
		logWarn("could not persist clean streak state to %s: %v", CLEAN_STREAK_STATE_FILE, err)
	}
}

// noteCleanCycle emits a single line when a clean streak starts, then updates
// a trailing "... N cycles clean (Cycle X-Y)" status line in persisted state.
// The final flush happens either when a non-clean cycle interrupts the streak
// (handled via flushCleanStreak) or at test end via generateFinalSummary.
func noteCleanCycle(logFile *os.File, timeStr string) {
	cleanCycleMu.Lock()
	defer cleanCycleMu.Unlock()
	loadCleanStreakStateLocked()
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
	saveCleanStreakStateLocked()
}

// flushCleanStreak terminates a clean streak and writes a one-line summary
// to logFile. Called from any path that records a non-clean event, and from
// generateFinalSummary at shutdown.
func flushCleanStreak(logFile *os.File) {
	cleanCycleMu.Lock()
	defer cleanCycleMu.Unlock()
	loadCleanStreakStateLocked()
	if !cleanCycleHeader {
		return
	}
	fmt.Fprintf(logFile, "%s [Cycle %d] Clean streak ended: %d cycles clean (Cycle %d..%d)\n",
		getCurrentTimestamp(), currentCycle.Load(), cleanCycleCount, cleanCycleStart, cleanCycleLast)
	logFile.Sync()
	cleanCycleHeader = false
	cleanCycleCount = 0
	saveCleanStreakStateLocked()
}

// cleanupBDFFiles removes current .txt files but keeps _init.txt files
func cleanupBDFFiles() {
	entries, err := os.ReadDir(TMP_DIR)
	if err != nil {
		logWarn("could not read tmp directory: %v", err)
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".txt") && !strings.HasSuffix(name, "_init.txt") && name != "initial_pci_devices.txt" {
			filepath := filepath.Join(TMP_DIR, name)
			if err := os.Remove(filepath); err != nil {
				logWarn("could not delete %s: %v", filepath, err)
			}
		}
	}
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

// persistedTestStats is the on-disk, whole-run-accumulated representation of
// the statistics that used to live only in the in-memory globals
// cyclesWithConfigChanges, deviceChangeStats, and (indirectly, via
// FieldChanges) mostChangedField. See TEST_STATS_FILE's declaration comment
// in main.go for why this must be a file rather than a package variable.
type persistedTestStats struct {
	CyclesWithConfigChanges int            `json:"cycles_with_config_changes"`
	DeviceChanges           map[string]int `json:"device_changes"`
	FieldChanges            map[string]int `json:"field_changes"`
}

// loadTestStats reads TEST_STATS_FILE. A missing or corrupt file is treated
// as "no stats recorded yet" (a fresh run), matching the zero-value behaviour
// the in-memory globals used to have on first use.
func loadTestStats() persistedTestStats {
	stats := persistedTestStats{DeviceChanges: make(map[string]int), FieldChanges: make(map[string]int)}
	data, err := os.ReadFile(TEST_STATS_FILE)
	if err != nil {
		return stats
	}
	var loaded persistedTestStats
	if err := json.Unmarshal(data, &loaded); err != nil {
		return stats
	}
	if loaded.DeviceChanges != nil {
		stats.DeviceChanges = loaded.DeviceChanges
	}
	if loaded.FieldChanges != nil {
		stats.FieldChanges = loaded.FieldChanges
	}
	stats.CyclesWithConfigChanges = loaded.CyclesWithConfigChanges
	return stats
}

// saveTestStats persists stats to TEST_STATS_FILE atomically. Failures are
// logged but not fatal: losing this file only degrades the final summary's
// "Most affected device" / "Most changed field" / raw-config STABLE-vs-CHANGED
// lines, it never affects any cycle's PASS/FAIL verdict.
func saveTestStats(stats persistedTestStats) {
	data, err := json.Marshal(stats)
	if err != nil {
		logWarn("could not encode test stats: %v", err)
		return
	}
	if err := writeFileAtomicNoFollow(TEST_STATS_FILE, data, 0644); err != nil {
		logWarn("could not persist test stats to %s: %v", TEST_STATS_FILE, err)
	}
}

// recordConfigSpaceChangeCycle increments the persisted count of cycles that
// saw at least one raw config-space byte change. It is the disk-backed
// equivalent of the old `cyclesWithConfigChanges++` in-memory statement,
// which reset to 0 every cycle because each reboot cycle runs in a
// brand-new process.
func recordConfigSpaceChangeCycle() {
	stats := loadTestStats()
	stats.CyclesWithConfigChanges++
	saveTestStats(stats)
}

// recordDeviceFieldChanges adds all lspci Dev/Lnk changes from one cycle to
// the persisted counters in a single read-modify-write. The file is needed
// because each reboot cycle runs in a brand-new process, but rewriting it for
// every field would turn a cycle with N changes into N full-file rewrites.
func recordDeviceFieldChanges(changes []DeviceFieldChange) {
	if len(changes) == 0 {
		return
	}

	stats := loadTestStats()
	for _, change := range changes {
		stats.DeviceChanges[normalizeBDF(change.BDF)]++
		stats.FieldChanges[change.Field]++
	}
	saveTestStats(stats)
}
