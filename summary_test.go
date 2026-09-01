package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRebootLogForStatsDeduplicatesLSPCIChangesPerCycle(t *testing.T) {
	root := t.TempDir()
	oldRebootLog := REBOOT_LOG
	defer func() {
		REBOOT_LOG = oldRebootLog
	}()
	REBOOT_LOG = filepath.Join(root, "reboot.log")

	logData := "2026-01-01 00:00:00 ===== Cycle 1 START =====\n" +
		"2026-01-01 00:00:00 #########Start to test#########\n" +
		"2026-01-01 00:00:00 Reboot Count: 1\n" +
		"2026-01-01 00:00:01 Had devices changed\n" +
		"2026-01-01 00:00:02 Had devices changed\n" +
		"2026-01-01 00:00:03 NEW Device: 0000:01:00.0\n" +
		"2026-01-01 00:00:04 NEW Device: 0000:02:00.0\n" +
		"2026-01-01 00:01:00 ===== Cycle 2 START =====\n" +
		"2026-01-01 00:01:00 #########Start to test#########\n" +
		"2026-01-01 00:01:00 Reboot Count: 2\n" +
		"2026-01-01 00:01:01 Had devices changed\n" +
		"2026-01-01 00:01:02 REMOVED Device: 0000:03:00.0\n" +
		"2026-01-01 00:01:03 REMOVED Device: 0000:04:00.0\n"
	if err := os.WriteFile(REBOOT_LOG, []byte(logData), 0644); err != nil {
		t.Fatalf("write reboot log: %v", err)
	}

	_, totalCycles, cyclesWithChanges, topologyChanges, lspciChanges := parseRebootLogForStats()
	if totalCycles != 2 {
		t.Errorf("total cycles = %d, want 2", totalCycles)
	}
	if cyclesWithChanges != 2 {
		t.Errorf("cycles with changes = %d, want 2", cyclesWithChanges)
	}
	if topologyChanges != 2 {
		t.Errorf("topology changes = %d, want 2", topologyChanges)
	}
	if lspciChanges != 2 {
		t.Errorf("lspci changes = %d, want 2", lspciChanges)
	}
}
