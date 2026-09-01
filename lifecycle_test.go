package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResetClassificationBaselineRemovesAllRunState(t *testing.T) {
	root := t.TempDir()

	oldPaths := struct {
		classify string
		streak   string
		changes  string
		stats    string
		scan     string
	}{
		classify: CLASSIFY_STATE_FILE,
		streak:   CLEAN_STREAK_STATE_FILE,
		changes:  CHANGE_LOG_FILE,
		stats:    TEST_STATS_FILE,
		scan:     LPOTSCAN_LOG,
	}
	defer func() {
		CLASSIFY_STATE_FILE = oldPaths.classify
		CLEAN_STREAK_STATE_FILE = oldPaths.streak
		CHANGE_LOG_FILE = oldPaths.changes
		TEST_STATS_FILE = oldPaths.stats
		LPOTSCAN_LOG = oldPaths.scan
	}()

	CLASSIFY_STATE_FILE = filepath.Join(root, "classification.json")
	CLEAN_STREAK_STATE_FILE = filepath.Join(root, "clean_streak_state.json")
	CHANGE_LOG_FILE = filepath.Join(root, "change_log.jsonl")
	TEST_STATS_FILE = filepath.Join(root, "test_stats.json")
	LPOTSCAN_LOG = filepath.Join(root, "lpotscan.log")

	paths := []string{
		CLASSIFY_STATE_FILE,
		CLEAN_STREAK_STATE_FILE,
		CHANGE_LOG_FILE,
		TEST_STATS_FILE,
		LPOTSCAN_LOG,
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("persisted state"), 0600); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
	}

	if err := resetClassificationBaseline(); err != nil {
		t.Fatalf("resetClassificationBaseline() returned error: %v", err)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed, stat error = %v", path, err)
		}
	}
}
