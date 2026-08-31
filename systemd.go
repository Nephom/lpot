package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func setupSystemdService() error {
	scriptPath := filepath.Join(LPOT_DIR, "reboot.sh")
	target, err := systemdDefaultTarget()
	if err != nil {
		logWarn("could not detect the systemd default target: %v; using multi-user.target", err)
		target = "multi-user.target"
	}
	if err := migrateLegacySystemdService(); err != nil {
		return err
	}
	serviceContent := systemdServiceContent(scriptPath, target)
	if err := verifyRootRegularFileIfPresent(servicePath); err != nil {
		return err
	}
	if err := writeFileNoFollow(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write systemd service file %s: %w", servicePath, err)
	}
	if err := os.Chmod(servicePath, 0644); err != nil {
		return fmt.Errorf("set systemd service mode on %s: %w", servicePath, err)
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %v", err)
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "enable", serviceName); err != nil {
		return fmt.Errorf("failed to enable %s: %v", serviceName, err)
	}
	return nil
}

func systemdDefaultTarget() (string, error) {
	out, err := runExternal(systemctlTimeout, systemctlPath, "get-default")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) == "graphical.target" {
		return "graphical.target", nil
	}
	return "multi-user.target", nil
}

func migrateLegacySystemdService() error {
	info, err := os.Lstat(legacyPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect legacy systemd service: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to migrate %s: path is a symlink", legacyPath)
	}
	if err := stopAndDisableUnit(legacyService); err != nil {
		return fmt.Errorf("failed to disable legacy %s: %v", legacyService, err)
	}
	if err := os.Remove(legacyPath); err != nil {
		return fmt.Errorf("failed to remove legacy %s: %v", legacyPath, err)
	}
	return nil
}

func systemdServiceContent(scriptPath, target string) string {
	return fmt.Sprintf(`[Unit]
Description=LPOT PCIe reboot stability test
After=local-fs.target

[Service]
ExecStart=%s
Restart=no
User=root
Group=root
WorkingDirectory=/lpot

[Install]
WantedBy=%s
`, scriptPath, target)
}

var selinuxConfigPath = "/etc/selinux/config"

func disableSELinux() error {
	info, err := os.Lstat(selinuxConfigPath)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to modify %s: path is a symlink", selinuxConfigPath)
	}
	if setenforcePath != "" {
		if _, err := runExternal(systemctlTimeout, setenforcePath, "0"); err != nil {
			logWarn("setenforce 0 failed: %v", err)
		}
	}
	data, err := os.ReadFile(selinuxConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", selinuxConfigPath, err)
	}
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
	if err := writeFileNoFollow(selinuxConfigPath, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to update %s: %w", selinuxConfigPath, err)
	}
	return nil
}

func systemdUnitExists(unit string) bool {
	out, err := runExternal(systemctlTimeout, systemctlPath, "cat", unit)
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

func stopAndDisableUnit(unit string) error {
	if !systemdUnitExists(unit) {
		return nil
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "stop", unit); err != nil {
		return fmt.Errorf("failed to stop %s: %w", unit, err)
	}
	if state, err := runExternal(systemctlTimeout, systemctlPath, "is-enabled", unit); err == nil && strings.TrimSpace(string(state)) == "enabled" {
		if _, err := runExternal(systemctlTimeout, systemctlPath, "disable", unit); err != nil {
			return fmt.Errorf("failed to disable %s: %w", unit, err)
		}
	}
	return nil
}

func disableFirewall() error {
	services := []string{"firewalld", "ufw", "nftables", "iptables", "ip6tables", "SuSEfirewall2"}
	for _, service := range services {
		if err := stopAndDisableUnit(service); err != nil {
			return err
		}
	}
	if ufwPath != "" {
		if _, err := runExternal(systemctlTimeout, ufwPath, "disable"); err != nil {
			return fmt.Errorf("failed to disable ufw: %w", err)
		}
	}
	return nil
}

func disableAppArmor() error { return stopAndDisableUnit("apparmor") }

func prepareHostPolicies() error {
	if err := disableFirewall(); err != nil {
		return fmt.Errorf("disable firewall: %w", err)
	}
	if err := disableAppArmor(); err != nil {
		return fmt.Errorf("disable AppArmor: %w", err)
	}
	if err := disableSELinux(); err != nil {
		return fmt.Errorf("configure SELinux: %w", err)
	}
	return nil
}
