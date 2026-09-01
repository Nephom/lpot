package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// This file implements the two small persisted state files that let the
// topology and read-availability tracking in reboot_cycle.go and
// pci_config_scan.go dedupe repeated events across cycles WITHOUT ever
// touching an immutable comparison baseline (<bdf>_init.txt, initial.bin,
// pci_devices_classify_state.json). See Issue #21 (baseline must never be
// rebased to the latest observed state) and Issue #23 (read failures need
// bounded retry, duration tracking, and reliable -p interaction).
//
// Two independent tracking namespaces are used ("lspci" and "rawconfig")
// because the lspci-text comparison path (processPCIDevices) and the raw
// config-space comparison path (compareDeviceConfigs) discover topology
// events independently and on slightly different schedules (one device's
// lspci snapshot can fail while its raw config sample succeeds, or vice
// versa); collapsing them into one namespace would let one path's dedup
// state incorrectly suppress the other path's first-time event.
const (
	topologyNamespaceLspci     = "lspci"
	topologyNamespaceRawConfig = "rawconfig"
	// topologyNamespaceClassify tracks devices whose PCI config-space read
	// failed specifically for link classification (writeClassificationReportToLog,
	// pcie_classify.go). A device can fail this read independently of the
	// lspci-text and raw config-space comparison paths, so it needs its own
	// dedup/duration-tracking namespace in unavailableState, exactly like
	// "lspci" and "rawconfig" already do for their own read paths.
	topologyNamespaceClassify = "classify"
)

// topologyState records, per namespace, the set of BDFs currently believed
// to be ABSENT (i.e. the last cycle that looked found them missing from
// this namespace's live device set). A BDF with no entry is PRESENT. This
// is intentionally the only state carried between cycles for topology
// dedup: the actual comparison baseline lives in <bdf>_init.txt / initial.bin
// and is never modified from here.
type topologyState struct {
	Namespaces map[string]map[string]bool `json:"namespaces"`
}

func loadTopologyState() topologyState {
	state := topologyState{Namespaces: make(map[string]map[string]bool)}
	data, err := os.ReadFile(TOPOLOGY_STATE_FILE)
	if err != nil {
		return state
	}
	var loaded topologyState
	if err := json.Unmarshal(data, &loaded); err != nil {
		return state
	}
	if loaded.Namespaces != nil {
		state.Namespaces = loaded.Namespaces
	}
	return state
}

func saveTopologyState(state topologyState) {
	data, err := json.Marshal(state)
	if err != nil {
		logWarn("could not encode topology state: %v", err)
		return
	}
	if err := writeFileAtomicNoFollow(TOPOLOGY_STATE_FILE, data, 0644); err != nil {
		logWarn("could not persist topology state to %s: %v", TOPOLOGY_STATE_FILE, err)
	}
}

// topologyIsAbsent reports whether bdf (already normalised by the caller) is
// currently recorded as absent in namespace.
func topologyIsAbsent(state topologyState, namespace, bdf string) bool {
	ns := state.Namespaces[namespace]
	if ns == nil {
		return false
	}
	return ns[bdf]
}

// topologyMarkAbsent records bdf as absent in namespace. Callers must persist
// the returned/mutated state via saveTopologyState.
func topologyMarkAbsent(state *topologyState, namespace, bdf string) {
	if state.Namespaces == nil {
		state.Namespaces = make(map[string]map[string]bool)
	}
	if state.Namespaces[namespace] == nil {
		state.Namespaces[namespace] = make(map[string]bool)
	}
	state.Namespaces[namespace][bdf] = true
}

// topologyMarkPresent clears any absent marker for bdf in namespace.
func topologyMarkPresent(state *topologyState, namespace, bdf string) {
	if ns := state.Namespaces[namespace]; ns != nil {
		delete(ns, bdf)
	}
}

// unavailableEntry records when a still-enumerated BDF first became
// unreadable, so later cycles can report how long it has been unavailable.
type unavailableEntry struct {
	FirstCycle int64  `json:"first_cycle"`
	FirstTime  string `json:"first_time"`
}

// unavailableState records, per namespace, every BDF that is currently
// enumerated (present in sysfs / this cycle's device list) but whose
// config-space could not be read this cycle. This is a distinct concept
// from topologyState: a device can be genuinely ABSENT (gone from sysfs)
// or merely UNAVAILABLE (still present but transiently unreadable), and
// conflating the two would misreport a flaky read as a topology change.
type unavailableState struct {
	Namespaces map[string]map[string]unavailableEntry `json:"namespaces"`
}

func loadUnavailableState() unavailableState {
	state := unavailableState{Namespaces: make(map[string]map[string]unavailableEntry)}
	data, err := os.ReadFile(UNAVAILABLE_STATE_FILE)
	if err != nil {
		return state
	}
	var loaded unavailableState
	if err := json.Unmarshal(data, &loaded); err != nil {
		return state
	}
	if loaded.Namespaces != nil {
		state.Namespaces = loaded.Namespaces
	}
	return state
}

func saveUnavailableState(state unavailableState) {
	data, err := json.Marshal(state)
	if err != nil {
		logWarn("could not encode device-unavailable state: %v", err)
		return
	}
	if err := writeFileAtomicNoFollow(UNAVAILABLE_STATE_FILE, data, 0644); err != nil {
		logWarn("could not persist device-unavailable state to %s: %v", UNAVAILABLE_STATE_FILE, err)
	}
}

// unavailableMark records that bdf failed to read this cycle (after bounded
// retry), returning a human-readable description of how long it has been
// unavailable (e.g. "since cycle 5 (1 cycle, ~12s)"). If this is the first
// cycle bdf is seen as unavailable, an entry is created with the current
// cycle/time.
func unavailableMark(state *unavailableState, namespace, bdf string, currentCycleNum int64, now time.Time) string {
	if state.Namespaces == nil {
		state.Namespaces = make(map[string]map[string]unavailableEntry)
	}
	if state.Namespaces[namespace] == nil {
		state.Namespaces[namespace] = make(map[string]unavailableEntry)
	}
	entry, existed := state.Namespaces[namespace][bdf]
	if !existed {
		entry = unavailableEntry{FirstCycle: currentCycleNum, FirstTime: now.Format(logTimeFormat)}
		state.Namespaces[namespace][bdf] = entry
	}
	consecutive := currentCycleNum - entry.FirstCycle + 1
	if consecutive < 1 {
		consecutive = 1
	}
	firstTime, err := time.ParseInLocation(logTimeFormat, entry.FirstTime, time.Local)
	if err != nil {
		return fmt.Sprintf("since cycle %d (%d cycle(s))", entry.FirstCycle, consecutive)
	}
	return fmt.Sprintf("since cycle %d (%d cycle(s), ~%s)", entry.FirstCycle, consecutive, now.Sub(firstTime).Round(time.Second))
}

// unavailableClear removes bdf's unavailable marker from namespace, if
// present, and returns a human-readable recovery description ("" if bdf was
// not previously marked unavailable).
func unavailableClear(state *unavailableState, namespace, bdf string, now time.Time) string {
	ns := state.Namespaces[namespace]
	if ns == nil {
		return ""
	}
	entry, existed := ns[bdf]
	if !existed {
		return ""
	}
	delete(ns, bdf)
	firstTime, err := time.ParseInLocation(logTimeFormat, entry.FirstTime, time.Local)
	if err != nil {
		return fmt.Sprintf("was unavailable since cycle %d", entry.FirstCycle)
	}
	return fmt.Sprintf("was unavailable since cycle %d (~%s)", entry.FirstCycle, now.Sub(firstTime).Round(time.Second))
}

// classifyReportedState is the report-dedup cache for
// writeClassificationReportToLog (pcie_classify.go). See
// CLASSIFY_REPORTED_STATE_FILE's declaration comment (main.go) for why this
// is a separate file from the immutable CLASSIFY_STATE_FILE comparison
// baseline.
type classifyReportedState struct {
	Devices map[string]string `json:"devices"`
	Removed map[string]bool   `json:"removed"`
}

func loadClassifyReportedState() classifyReportedState {
	state := classifyReportedState{Devices: make(map[string]string), Removed: make(map[string]bool)}
	data, err := os.ReadFile(CLASSIFY_REPORTED_STATE_FILE)
	if err != nil {
		return state
	}
	var loaded classifyReportedState
	if err := json.Unmarshal(data, &loaded); err != nil {
		return state
	}
	if loaded.Devices != nil {
		state.Devices = loaded.Devices
	}
	if loaded.Removed != nil {
		state.Removed = loaded.Removed
	}
	return state
}

func saveClassifyReportedState(state classifyReportedState) {
	data, err := json.Marshal(state)
	if err != nil {
		logWarn("could not encode classification report-dedup state: %v", err)
		return
	}
	if err := writeFileAtomicNoFollow(CLASSIFY_REPORTED_STATE_FILE, data, 0644); err != nil {
		logWarn("could not persist classification report-dedup state to %s: %v", CLASSIFY_REPORTED_STATE_FILE, err)
	}
}
