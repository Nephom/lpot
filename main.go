package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Path variables. All persistent state lives under LPOT_DIR so behaviour is
// independent of the caller's working directory. These are declared as var
// rather than const for historical reasons only; no code in this repository
// ever reassigns them, so in practice they behave exactly like constants.
var (
	LPOT_DIR            = "/lpot"
	PERSISTENT_BINARY   = "/lpot/lpot"
	SYS_PCI_DEVICES     = "/sys/bus/pci/devices/"
	TIMESTAMP_FILE      = "/lpot/timestamp"
	REBOOTCOUNT_FILE    = "/lpot/rebootcount"
	TM_TARGET_FILE      = "/lpot/tm_target"
	TM_START_COUNT_FILE = "/lpot/tm_start_count"
	INITIAL_PCI_DEVICES = "/lpot/initial_pci_devices.txt"
	REBOOT_LOG          = "/lpot/reboot.log"
	CLASSIFY_STATE_FILE = "/lpot/pci_devices_classify_state.json"
	// CLASSIFY_REPORTED_STATE_FILE tracks the last classification encoding
	// that was actually LOGGED/recordCycleChange'd for each BDF, so a device
	// that deviates from CLASSIFY_STATE_FILE's immutable baseline once and
	// then stays at that same deviated value is reported exactly once, not
	// on every subsequent cycle. It is a report-dedup cache only —
	// CLASSIFY_STATE_FILE itself (the comparison baseline) is never rewritten
	// after its first write, per Issue #21.
	CLASSIFY_REPORTED_STATE_FILE = "/lpot/pci_devices_classify_reported.json"
	COMMAND_USER_LOG             = "/lpot/command_user_custom.log"
	TMP_DIR                      = "/lpot/tmp"
	IGNORE_LIST_FILE             = "/lpot/ignore_list.txt"
	CONFIG_CHANGES_LOG           = "/lpot/pci-config-changes.log"
	RESULT_FILE                  = "/lpot/result.json"
	CLASSIFY_LOG                 = "/lpot/pci_devices_classify.log"
	LPOTSCAN_LOG                 = "/lpot/lpotscan.log"
	PCIE_FILTER_FILE             = "/lpot/pcie_filter.txt"
	CONFIG_DUMP_DIR              = "/lpot/config_dump"
	// TOPOLOGY_STATE_FILE persists which BDFs are currently considered
	// "absent" for each topology-tracking namespace (lspci-text and raw
	// config-space are tracked separately). Its sole purpose is to dedupe
	// repeated REMOVED/REAPPEARED log lines and recordCycleChange calls for a
	// device that stays absent across many cycles, WITHOUT ever deleting or
	// rewriting the immutable per-device baseline files (<bdf>_init.txt,
	// initial.bin). See processPCIDevices() (reboot_cycle.go) and
	// compareDeviceConfigs() (pci_config_scan.go).
	TOPOLOGY_STATE_FILE = "/lpot/topology_state.json"
	// UNAVAILABLE_STATE_FILE persists, per topology-tracking namespace, the
	// first cycle/time a BDF that is still enumerated (present in sysfs /
	// still in the current bdfs list) could not be read (lspci or raw
	// config-space). This is deliberately a different concept and a
	// different file from TOPOLOGY_STATE_FILE: a device can be genuinely
	// ABSENT (gone from sysfs entirely) or merely UNAVAILABLE (still present
	// but transiently unreadable); conflating the two would misreport a
	// flaky read as a topology change or vice versa.
	UNAVAILABLE_STATE_FILE = "/lpot/device_unavailable_state.json"
	// INITIAL_BIN_FILE is the one-time, never-rewritten raw config-space
	// baseline snapshot (compareDeviceConfigs' initialFile). Named/centralised
	// here instead of repeating the "/lpot/initial.bin" string literal at
	// every call site.
	INITIAL_BIN_FILE = "/lpot/initial.bin"
	// CLEAN_STREAK_STATE_FILE persists the in-progress "consecutive clean
	// cycles" counter across reboots. Each reboot cycle runs in a brand-new
	// process (systemd re-execs /lpot/reboot.sh), so an in-memory-only counter
	// would reset to 0/1 every cycle and could never actually reflect a
	// multi-cycle clean streak, contradicting the log line's own "N cycles
	// clean (Cycle X..Y)" wording.
	CLEAN_STREAK_STATE_FILE = "/lpot/clean_streak_state.json"

	// CHANGE_LOG_FILE persists every recordCycleChange/recordCycleNoise entry
	// as one JSON line per event, across the entire multi-day run. Each
	// reboot cycle runs in a brand-new process (systemd re-execs
	// /lpot/reboot.sh), so the in-memory changedCycles slice that
	// appendCycleChange() populates is reset to empty on every single cycle.
	// Without this file, writeAffectedCyclesSection() (the "Affected Cycles"
	// section of the final summary) could only ever see the last cycle's
	// events, silently losing every earlier cycle's topology/lspci/config
	// changes from the final report. Appending one line per event (rather
	// than rewriting a whole-file snapshot like CLEAN_STREAK_STATE_FILE)
	// keeps every writer a simple O(1) append that cannot corrupt earlier
	// cycles' entries if a later cycle crashes mid-write.
	CHANGE_LOG_FILE = "/lpot/change_log.jsonl"

	// TEST_STATS_FILE persists cross-cycle counters and per-device/per-field
	// tallies that used to live only in in-memory globals
	// (cyclesWithConfigChanges, deviceChangeStats, mostAffectedDevice,
	// mostChangedField). Like CHANGE_LOG_FILE and CLEAN_STREAK_STATE_FILE,
	// these must be read-modify-written across the brand-new process each
	// reboot cycle runs in, or the final summary's "Most affected device",
	// "Most changed field", and raw-config STABLE/CHANGED verdict would
	// silently reflect only the very last cycle instead of the whole run.
	TEST_STATS_FILE = "/lpot/test_stats.json"
)

const (
	// Per-command timeouts for external tools. Chosen conservatively so a stuck
	// child process cannot hang the overall test loop.
	lspciTimeout         = 30 * time.Second
	systemctlTimeout     = 15 * time.Second
	configScanLogTimeout = 2 * time.Minute
	rebootCmdTimeout     = 30 * time.Second
	// PCI discovery is retried only during normal cycle startup. The bounded
	// retry handles asynchronous enumeration without allowing boot to hang
	// indefinitely when no link-capable device exists.
	pciDiscoveryRetryAttempts = 5
	pciDiscoveryRetryInterval = 2 * time.Second

	// deviceReadRetryAttempts/deviceReadRetryInterval bound how long a single
	// still-enumerated device is retried when its lspci snapshot or raw
	// config-space read fails this cycle, before it is recorded as
	// UNAVAILABLE for the cycle. This is intentionally short (a few seconds
	// total) since a stuck/absent read must not stall the entire cycle for
	// every other device waiting behind it.
	deviceReadRetryAttempts = 3
	deviceReadRetryInterval = 2 * time.Second

	// logTimeFormat is the single timestamp layout used across every log file
	// (reboot.log, pci-config-changes.log, lpotscan echo). A unified format
	// lets users correlate events by plain text search and by tools like
	// `sort -k1,2` without translation.
	logTimeFormat = "2006-01-02 15:04:05"

	// rebootFixedThreshold is the occurrence-ratio cutoff (fraction of
	// completed reboot cycles) above which a (device, offset) config-space
	// change is classified as benign "reboot-fixed" noise rather than a
	// noteworthy volatile change. It is shared between generateConfigSpaceSummary
	// (summary.go, reboot.log's human-readable table) and buildResultReport
	// (result_helpers.go, result.json's ConfigSpace/ConfigNoise checks) so the
	// two artifacts always agree on which rows are "benign" vs "needs review".
	rebootFixedThreshold = 0.80
	version              = "2.6.16"
	serviceName          = "lpot.service"
	servicePath          = "/etc/systemd/system/" + serviceName
)

var buildTime = "development"

// Global variables
var (
	stopFlag atomic.Bool // set when SIGINT/SIGTERM is received or rootCtx is cancelled

	// rootCtx is cancelled on SIGINT/SIGTERM and is used to bound every external
	// command so the test loop cannot be left waiting on a stuck child process.
	rootCtx    context.Context
	rootCancel context.CancelFunc

	// currentCycle holds the reboot cycle number for the current run. It is
	// written once by main() after updateRebootCount() succeeds and then read
	// by log helpers to tag every event with [Cycle N].
	currentCycle atomic.Int64

	// changedCycles records cycles where any topology / lspci / config-space
	// change was detected, along with a short reason string. It is summarised
	// at the end of the run so users can see exactly which cycles were noisy
	// without grepping the entire reboot.log.
	changedCyclesMu sync.Mutex
	changedCycles   []cycleChange

	// endpointFilterSet, when non-nil, restricts every PCI-touching path
	// (savePCIConfigReportingFailures, compareDeviceConfigs, processPCIDevices)
	// to the set of short BDFs it contains. nil means "no filter" so unit
	// tests and the legacy code path keep working unchanged.
	endpointFilterSet       map[string]bool
	classifiedDevicesGlobal []deviceClassification
)
