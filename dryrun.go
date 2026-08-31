package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// printDryRunFile reports a complete text payload without opening the target
// for writing. It intentionally reads an existing regular file only to make
// the audit output explain whether the normal O_EXCL/write path would create,
// skip, or replace it.
func printDryRunFile(path, action string, mode os.FileMode, content string) {
	state := "WOULD CREATE"
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			state = "WOULD REFUSE (symlink exists)"
		} else {
			state = "WOULD USE EXISTING"
			if action == "replace" {
				state = "WOULD REPLACE"
			}
		}
	} else if !os.IsNotExist(err) {
		state = fmt.Sprintf("WOULD INSPECT (stat failed: %v)", err)
	}

	fmt.Printf("[DRY-RUN] %s %s mode=%#o\n", state, path, mode.Perm())
	fmt.Printf("[DRY-RUN] CONTENT BEGIN %s\n%s[DRY-RUN] CONTENT END %s\n", path, content, path)
}

func printDryRunCommand(name string, args ...string) {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, name)
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	fmt.Printf("[DRY-RUN] WOULD EXEC %s\n", strings.Join(parts, " "))
}

func printDryRunHostPolicyActions() {
	for _, service := range []string{"firewalld", "ufw", "nftables", "iptables", "ip6tables", "SuSEfirewall2", "apparmor"} {
		if systemdUnitExists(service) {
			printDryRunCommand(systemctlPath, "stop", service)
			printDryRunCommand(systemctlPath, "is-enabled", service)
			printDryRunCommand(systemctlPath, "disable", service)
		} else {
			fmt.Printf("[DRY-RUN] READ systemd unit %s: absent (skip)\n", service)
		}
	}
	if ufwPath != "" {
		printDryRunCommand(ufwPath, "disable")
	}
	if setenforcePath != "" {
		printDryRunCommand(setenforcePath, "0")
	}
}

func printDryRunReadCommand(timeout time.Duration, name string, args ...string) []byte {
	printDryRunCommand(name, args...)
	out, err := runExternal(timeout, name, args...)
	if err != nil {
		fmt.Printf("[DRY-RUN] READ COMMAND FAILED: %v\n", err)
		return nil
	}
	fmt.Printf("[DRY-RUN] COMMAND OUTPUT BEGIN %s\n%s[DRY-RUN] COMMAND OUTPUT END %s\n",
		name, string(out), name)
	return out
}

func runDryRunScanAudit() {
	fmt.Println("[DRY-RUN] scan audit mode; no scan result will be written")
	fmt.Printf("[DRY-RUN] WOULD READ %s for PCI configuration samples\n", SYS_PCI_DEVICES)
	fmt.Println("[DRY-RUN] WOULD COLLECT 5 read-only PCI samples at one-second intervals")
	fmt.Printf("[DRY-RUN] WOULD WRITE %s (generated volatile-byte ignore list)\n", IGNORE_LIST_FILE)
	fmt.Printf("[DRY-RUN] WOULD REMOVE temporary sample directory after analysis\n")
	fmt.Println("[DRY-RUN] scan audit complete")
}

func runDryRunClassifyAudit() {
	fmt.Println("[DRY-RUN] classify audit mode; no report or host policy will be written")
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fmt.Printf("[DRY-RUN] READ PCI devices failed: %v\n", err)
		return
	}
	ov, err := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
	if err != nil {
		fmt.Printf("[DRY-RUN] READ %s failed: %v\n", PCIE_FILTER_FILE, err)
		return
	}
	decisions := classifyDevices(bdfs, ov)
	var report bytes.Buffer
	printClassificationReport(&report, decisions)
	fmt.Printf("[DRY-RUN] WOULD WRITE %s\n", CLASSIFY_LOG)
	fmt.Printf("[DRY-RUN] CONTENT BEGIN %s\n%s[DRY-RUN] CONTENT END %s\n", CLASSIFY_LOG, report.String(), CLASSIFY_LOG)
	fmt.Println("[DRY-RUN] classify audit complete")
}

// runDryRunAudit performs the read-only portion of startup and prints every
// planned mutation. It is deliberately separate from the normal execution
// path: a dry run must remain safe even when a future write is added to the
// reboot loop and its author forgets to add another guard.
func runDryRunAudit(args []string, waitHours, standbyTime, waitSeconds int, stopService bool, scanOnly, classify bool) {
	if scanOnly {
		runDryRunScanAudit()
		return
	}
	if classify {
		runDryRunClassifyAudit()
		return
	}
	fmt.Println("[DRY-RUN] audit mode enabled; no filesystem or host-state mutation will occur")
	fmt.Printf("[DRY-RUN] parameters: duration=%dh driver-delay=%ds reboot-delay=%ds stop-on-error=%t\n",
		waitHours, standbyTime, waitSeconds, stopService)

	if info, err := os.Lstat(LPOT_DIR); err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0755\n", LPOT_DIR)
		} else {
			fmt.Printf("[DRY-RUN] READ %s failed: %v\n", LPOT_DIR, err)
		}
	} else {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			LPOT_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}
	if info, err := os.Lstat(TMP_DIR); err != nil && os.IsNotExist(err) {
		fmt.Printf("[DRY-RUN] WOULD MKDIR %s mode=0755\n", TMP_DIR)
	} else if err == nil {
		fmt.Printf("[DRY-RUN] READ %s exists mode=%#o directory=%t symlink=%t\n",
			TMP_DIR, info.Mode().Perm(), info.IsDir(), info.Mode()&os.ModeSymlink != 0)
	}

	printDryRunHostPolicyActions()

	if info, err := os.Lstat(selinuxConfigPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
		if setenforcePath != "" {
			printDryRunCommand(setenforcePath, "0")
		}
		if data, readErr := os.ReadFile(selinuxConfigPath); readErr == nil {
			lines := strings.Split(string(data), "\n")
			found := false
			for i, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") {
					lines[i] = "SELINUX=disabled"
					found = true
				}
			}
			if !found {
				lines = append(lines, "SELINUX=disabled")
			}
			printDryRunFile(selinuxConfigPath, "replace", 0644, strings.Join(lines, "\n"))
		} else {
			fmt.Printf("[DRY-RUN] READ %s failed: %v\n", selinuxConfigPath, readErr)
		}
	} else {
		fmt.Printf("[DRY-RUN] READ %s: absent or symlink (no SELinux config write)\n", selinuxConfigPath)
	}

	script := buildRebootScript(PERSISTENT_BINARY, args[1:], customCommandArgs)
	printDryRunFile(PERSISTENT_BINARY, "replace", 0755, "[binary copied from the invoked executable]\n")
	printDryRunFile(filepath.Join(LPOT_DIR, "reboot.sh"), "replace", 0700, script)

	if info, err := os.Lstat(legacyPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
		printDryRunCommand(systemctlPath, "stop", legacyService)
		printDryRunCommand(systemctlPath, "disable", legacyService)
		fmt.Printf("[DRY-RUN] WOULD REMOVE %s\n", legacyPath)
	}
	target := "multi-user.target"
	if out := printDryRunReadCommand(systemctlTimeout, systemctlPath, "get-default"); strings.TrimSpace(string(out)) == "graphical.target" {
		target = "graphical.target"
	}
	fmt.Printf("[DRY-RUN] selected systemd WantedBy=%s\n", target)
	printDryRunFile(servicePath, "create", 0644, systemdServiceContent(filepath.Join(LPOT_DIR, "reboot.sh"), target))
	printDryRunCommand(systemctlPath, "daemon-reload")
	printDryRunCommand(systemctlPath, "enable", serviceName)

	nextCount := 1
	if data, err := os.ReadFile(REBOOTCOUNT_FILE); err == nil {
		if count, parseErr := strconv.Atoi(strings.TrimSpace(string(data))); parseErr == nil {
			nextCount = count + 1
		}
	}
	printDryRunFile(REBOOTCOUNT_FILE, "replace", 0600, fmt.Sprintf("%d\n", nextCount))
	printDryRunFile(TIMESTAMP_FILE, "replace", 0644,
		fmt.Sprintf("%d\n", time.Now().Add(time.Duration(waitHours)*time.Hour).Unix()))

	fmt.Printf("[DRY-RUN] WOULD READ %s and discover PCI devices\n", SYS_PCI_DEVICES)
	bdfs, err := fetchPCIBDFs()
	if err != nil {
		fmt.Printf("[DRY-RUN] READ PCI devices failed: %v\n", err)
	} else {
		overrides, filterErr := loadPCIeFilterOverrides(PCIE_FILTER_FILE)
		if filterErr != nil {
			overrides = pcieFilterOverrides{Include: map[string]bool{}, Exclude: map[string]bool{}}
			fmt.Printf("[DRY-RUN] READ %s: absent/unreadable, using automatic classification\n", PCIE_FILTER_FILE)
		}
		kept, skipped := filterEndpoints(bdfs, overrides)
		fmt.Printf("[DRY-RUN] PCI classification: kept=%d skipped=%d\n", len(kept), len(skipped))
		initialOutput := printDryRunReadCommand(lspciTimeout, lspciPath, "-vv")
		if len(initialOutput) > 0 {
			printDryRunFile(INITIAL_PCI_DEVICES, "replace", 0644, string(initialOutput))
		}
		for _, bdf := range kept {
			output := printDryRunReadCommand(lspciTimeout, lspciPath, "-s", bdf, "-vv")
			if len(output) > 0 {
				printDryRunFile(filepath.Join(TMP_DIR, bdf+"_init.txt"), "replace", 0644, string(output))
				printDryRunFile(filepath.Join(TMP_DIR, bdf+".txt"), "replace", 0644, string(output))
			} else {
				fmt.Printf("[DRY-RUN] WOULD WRITE %s (content unavailable because read command failed)\n", filepath.Join(TMP_DIR, bdf+"_init.txt"))
				fmt.Printf("[DRY-RUN] WOULD WRITE %s (content unavailable because read command failed)\n", filepath.Join(TMP_DIR, bdf+".txt"))
			}
		}
	}

	for _, path := range []string{
		INITIAL_PCI_DEVICES, IGNORE_LIST_FILE, "/lpot/initial.bin", "/lpot/current.bin",
		CONFIG_CHANGES_LOG, CLASSIFY_LOG, LPOTSCAN_LOG, REBOOT_LOG, RESULT_FILE, COMMAND_USER_LOG,
	} {
		fmt.Printf("[DRY-RUN] WOULD WRITE/UPDATE %s (content generated from read-only PCI scan and comparison)\n", path)
	}
	fmt.Printf("[DRY-RUN] WOULD REMOVE generated temporary snapshots under %s\n", TMP_DIR)
	fmt.Printf("[DRY-RUN] WOULD WAIT %ds before reboot\n", waitSeconds)
	printDryRunCommand(rebootPath)
	fmt.Println("[DRY-RUN] audit complete; reboot command was not executed")
}
