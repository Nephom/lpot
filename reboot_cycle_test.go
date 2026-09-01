package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordDeviceFieldChangesBatchesStats(t *testing.T) {
	root := t.TempDir()
	oldStatsPath := TEST_STATS_FILE
	oldSimulationMode := simulationMode
	defer func() {
		TEST_STATS_FILE = oldStatsPath
		simulationMode = oldSimulationMode
	}()

	TEST_STATS_FILE = filepath.Join(root, "test_stats.json")
	simulationMode = true

	recordDeviceFieldChanges([]DeviceFieldChange{
		{BDF: "0000:21:00.0", Field: "LnkSta"},
		{BDF: "21:00.0", Field: "LnkSta"},
		{BDF: "21:00.0", Field: "DevCtl"},
	})

	stats := loadTestStats()
	if got := stats.DeviceChanges["21:00.0"]; got != 3 {
		t.Fatalf("device change count = %d, want 3", got)
	}
	if got := stats.FieldChanges["LnkSta"]; got != 2 {
		t.Fatalf("LnkSta count = %d, want 2", got)
	}
	if got := stats.FieldChanges["DevCtl"]; got != 1 {
		t.Fatalf("DevCtl count = %d, want 1", got)
	}
}

func TestRecordDeviceFieldChangesSkipsEmptyBatch(t *testing.T) {
	root := t.TempDir()
	oldStatsPath := TEST_STATS_FILE
	oldSimulationMode := simulationMode
	defer func() {
		TEST_STATS_FILE = oldStatsPath
		simulationMode = oldSimulationMode
	}()

	TEST_STATS_FILE = filepath.Join(root, "test_stats.json")
	simulationMode = true

	recordDeviceFieldChanges(nil)
	if _, err := os.Stat(TEST_STATS_FILE); !os.IsNotExist(err) {
		t.Fatalf("empty batch created stats file, stat error = %v", err)
	}
}

func TestSaveTestStatsWritesCompleteJSONAtomically(t *testing.T) {
	root := t.TempDir()
	oldStatsPath := TEST_STATS_FILE
	oldSimulationMode := simulationMode
	defer func() {
		TEST_STATS_FILE = oldStatsPath
		simulationMode = oldSimulationMode
	}()

	TEST_STATS_FILE = filepath.Join(root, "test_stats.json")
	simulationMode = true

	want := persistedTestStats{
		CyclesWithConfigChanges: 4,
		DeviceChanges:           map[string]int{"21:00.0": 2},
		FieldChanges:            map[string]int{"LnkSta": 2},
	}
	saveTestStats(want)

	data, err := os.ReadFile(TEST_STATS_FILE)
	if err != nil {
		t.Fatalf("read saved stats: %v", err)
	}
	var got persistedTestStats
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("saved stats is not complete JSON: %v", err)
	}
	if got.CyclesWithConfigChanges != want.CyclesWithConfigChanges || got.DeviceChanges["21:00.0"] != 2 || got.FieldChanges["LnkSta"] != 2 {
		t.Fatalf("saved stats = %+v, want %+v", got, want)
	}
}
