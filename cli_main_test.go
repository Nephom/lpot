package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func keepDecision(bdf string) deviceClassification {
	return deviceClassification{BDF: bdf, Kept: true, KeptReason: "link-capable"}
}

func TestGenerateFinalSummaryPreservesIncompleteStatus(t *testing.T) {
	root := t.TempDir()
	oldPaths := map[*string]string{
		&REBOOT_LOG:          REBOOT_LOG,
		&RESULT_FILE:         RESULT_FILE,
		&CHANGE_LOG_FILE:     CHANGE_LOG_FILE,
		&TEST_STATS_FILE:     TEST_STATS_FILE,
		&CONFIG_CHANGES_LOG:  CONFIG_CHANGES_LOG,
		&LPOTSCAN_LOG:        LPOTSCAN_LOG,
		&CLASSIFY_STATE_FILE: CLASSIFY_STATE_FILE,
	}
	oldSimulationMode := simulationMode
	defer func() {
		for path, old := range oldPaths {
			*path = old
		}
		simulationMode = oldSimulationMode
	}()

	REBOOT_LOG = filepath.Join(root, "reboot.log")
	RESULT_FILE = filepath.Join(root, "result.json")
	CHANGE_LOG_FILE = filepath.Join(root, "change_log.jsonl")
	TEST_STATS_FILE = filepath.Join(root, "test_stats.json")
	CONFIG_CHANGES_LOG = filepath.Join(root, "pci-config-changes.log")
	LPOTSCAN_LOG = filepath.Join(root, "lpotscan.log")
	CLASSIFY_STATE_FILE = filepath.Join(root, "classification.json")
	simulationMode = true

	if err := os.WriteFile(REBOOT_LOG, []byte("2026-01-01 00:00:00 ===== Cycle 1 START =====\n2026-01-01 00:00:00 #########Start to test#########\n\t\t\tReboot Count: 1\n"), 0644); err != nil {
		t.Fatalf("write reboot log: %v", err)
	}

	generateFinalSummary("INCOMPLETE")

	logData, err := os.ReadFile(REBOOT_LOG)
	if err != nil {
		t.Fatalf("read reboot log: %v", err)
	}
	if !strings.Contains(string(logData), "Test Session Summary") || !strings.Contains(string(logData), "Test Result: INCOMPLETE") {
		t.Fatalf("incomplete summary missing from reboot.log: %s", logData)
	}

	resultData, err := os.ReadFile(RESULT_FILE)
	if err != nil {
		t.Fatalf("read result report: %v", err)
	}
	var report resultReport
	if err := json.Unmarshal(resultData, &report); err != nil {
		t.Fatalf("decode result report: %v", err)
	}
	if report.Status != "INCOMPLETE" {
		t.Fatalf("result status = %q, want INCOMPLETE", report.Status)
	}
}

func TestDiscoverPCIEndpointsWithRetryRefreshesSysfsSnapshot(t *testing.T) {
	calls := 0

	result, err := discoverPCIEndpointsWithRetry(
		func() ([]string, error) {
			calls++
			if calls == 1 {
				return nil, nil
			}
			return []string{"0000:01:00.0"}, nil
		},
		func(bdfs []string) ([]string, []deviceClassification) {
			if len(bdfs) == 0 {
				return nil, nil
			}
			return []string{bdfs[0]}, []deviceClassification{keepDecision(bdfs[0])}
		},
		3, 0, nil,
	)
	if err != nil {
		t.Fatalf("discoverPCIEndpointsWithRetry() returned error: %v", err)
	}
	if calls != 2 || result.attempts != 2 {
		t.Fatalf("expected two discovery attempts, calls=%d attempts=%d", calls, result.attempts)
	}
	if !reflect.DeepEqual(result.kept, []string{"0000:01:00.0"}) {
		t.Fatalf("unexpected kept BDFs: %#v", result.kept)
	}
}

func TestDiscoverPCIEndpointsWithRetryUsesLatestCompleteSet(t *testing.T) {
	calls := 0
	result, err := discoverPCIEndpointsWithRetry(
		func() ([]string, error) {
			calls++
			if calls == 1 {
				return []string{"0000:01:00.0"}, nil
			}
			return []string{"0000:01:00.0", "0000:02:00.0"}, nil
		},
		func(bdfs []string) ([]string, []deviceClassification) {
			if len(bdfs) < 2 {
				return nil, []deviceClassification{keepDecision(bdfs[0])}
			}
			return append([]string(nil), bdfs...), []deviceClassification{keepDecision(bdfs[0]), keepDecision(bdfs[1])}
		},
		2, 0, nil,
	)
	if err != nil {
		t.Fatalf("discoverPCIEndpointsWithRetry() returned error: %v", err)
	}
	if !reflect.DeepEqual(result.kept, []string{"0000:01:00.0", "0000:02:00.0"}) {
		t.Fatalf("expected latest complete BDF set, got %#v", result.kept)
	}
	if result.totalDiscovered != 2 {
		t.Fatalf("expected latest discovery count 2, got %d", result.totalDiscovered)
	}
}

func TestDiscoverPCIEndpointsWithRetryIsBounded(t *testing.T) {
	calls := 0
	result, err := discoverPCIEndpointsWithRetry(
		func() ([]string, error) {
			calls++
			return nil, nil
		},
		func([]string) ([]string, []deviceClassification) { return nil, nil },
		3, 0, nil,
	)
	if err != nil {
		t.Fatalf("empty final discovery should not be an infrastructure error: %v", err)
	}
	if calls != 3 || result.attempts != 3 {
		t.Fatalf("expected exactly three attempts, calls=%d attempts=%d", calls, result.attempts)
	}
	if len(result.kept) != 0 {
		t.Fatalf("expected no kept devices, got %#v", result.kept)
	}
}

func TestDiscoverPCIEndpointsWithRetryRetriesFetchErrors(t *testing.T) {
	calls := 0
	result, err := discoverPCIEndpointsWithRetry(
		func() ([]string, error) {
			calls++
			if calls < 3 {
				return nil, errors.New("sysfs temporarily unavailable")
			}
			return []string{"0000:03:00.0"}, nil
		},
		func(bdfs []string) ([]string, []deviceClassification) {
			return bdfs, []deviceClassification{keepDecision(bdfs[0])}
		},
		3, 0, nil,
	)
	if err != nil {
		t.Fatalf("expected recovery after transient fetch errors: %v", err)
	}
	if result.attempts != 3 || calls != 3 {
		t.Fatalf("expected three attempts, calls=%d attempts=%d", calls, result.attempts)
	}
}

func TestDiscoverPCIEndpointsWithRetryStopsBeforeNextAttempt(t *testing.T) {
	calls := 0
	result, err := discoverPCIEndpointsWithRetry(
		func() ([]string, error) {
			calls++
			return nil, nil
		},
		func([]string) ([]string, []deviceClassification) { return nil, nil },
		5, 0, func() bool { return calls > 0 },
	)
	if err == nil || result.attempts != 0 {
		t.Fatalf("expected cancellation before second attempt, result=%#v err=%v", result, err)
	}
	if calls != 1 {
		t.Fatalf("expected one attempt before cancellation, got %d", calls)
	}
}
