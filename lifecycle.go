package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// runExternal runs an external command with an upper-bound timeout derived
// from rootCtx, so both Ctrl-C and a stuck child will release the caller.
// argv[0] must be an absolute path or be resolvable via exec.LookPath; callers
// are responsible for passing a trusted command name.
func runExternal(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(rootCtx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

// Absolute paths of trusted system binaries, resolved at startup via
// resolveBinaries() against a sanitised PATH. Using absolute paths for every
// subprocess prevents a writable PATH entry from shadowing standard tools.
var (
	lspciPath         string
	systemctlPath     string
	rebootPath        string
	configScanLogPath string
	setenforcePath    string
	ufwPath           string
)

// trustedBinDirs is the allow-list of system directories in which the standard
// tools may live. A resolved path outside these directories is treated as
// evidence of PATH tampering.
var trustedBinDirs = []string{"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"}

// isTrustedBinPath reports whether p lives under one of trustedBinDirs.
func isTrustedBinPath(p string) bool {
	for _, d := range trustedBinDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// resolveBinaries locks down PATH and resolves the external tools the test
// harness will invoke. It must run before setupSystemdService() or any loop
// that shells out.
func resolveBinaries(requireLSPCITools, requireRebootTools bool) error {
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")

	tools := []struct {
		name string
		dst  *string
	}{
		{"lspci", &lspciPath},
	}
	if requireLSPCITools {
		for _, t := range tools {
			p, err := exec.LookPath(t.name)
			if err != nil {
				return fmt.Errorf("required tool %q not found in PATH: %w", t.name, err)
			}
			if !isTrustedBinPath(p) {
				return fmt.Errorf("tool %q resolved to untrusted path %q", t.name, p)
			}
			*t.dst = p
		}
	}
	if requireRebootTools {
		for _, t := range []struct {
			name string
			dst  *string
		}{
			{"systemctl", &systemctlPath},
			{"reboot", &rebootPath},
		} {
			p, err := exec.LookPath(t.name)
			if err != nil {
				return fmt.Errorf("required tool %q not found in PATH: %w", t.name, err)
			}
			if !isTrustedBinPath(p) {
				return fmt.Errorf("tool %q resolved to untrusted path %q", t.name, p)
			}
			*t.dst = p
		}
	}

	// configscan_log.sh is a custom helper shipped alongside the binary. Only
	// accept it from known absolute locations to avoid PATH-based hijacking.
	for _, p := range []string{
		filepath.Join(LPOT_DIR, "configscan_log.sh"),
		"/usr/local/bin/configscan_log.sh",
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			configScanLogPath = p
			break
		}
	}
	// These commands are optional and are handled as best-effort controls for
	// distributions where the corresponding security facility is installed.
	setenforcePath, _ = exec.LookPath("setenforce")
	ufwPath, _ = exec.LookPath("ufw")
	return nil
}

// ensureRoot aborts startup if the process is not running with effective uid 0.
// Every meaningful operation (reading PCI config space, writing to /etc, and
// rebooting the host) requires root, so refusing early is clearer than failing
// later with a partially-initialised state.
func ensureRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "LPOT must be run as root (effective uid 0).")
		os.Exit(1)
	}
}

// secureLpotDir ensures LPOT_DIR exists as a real directory owned by root and
// not reachable through a symlink. The directory is readable/traversable by
// non-root users for operational inspection, while files that control reboot
// execution remain root-owned and non-writable by other users.
func secureLpotDir() error {
	info, err := os.Lstat(LPOT_DIR)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", LPOT_DIR, err)
		}
		if err := os.MkdirAll(LPOT_DIR, 0755); err != nil {
			return fmt.Errorf("create %s: %w", LPOT_DIR, err)
		}
		info, err = os.Lstat(LPOT_DIR)
		if err != nil {
			return fmt.Errorf("stat %s after create: %w", LPOT_DIR, err)
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to run", LPOT_DIR)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", LPOT_DIR)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("%s must be owned by root (uid 0), found uid %d", LPOT_DIR, st.Uid)
	}
	if info.Mode().Perm() != 0755 {
		if err := os.Chmod(LPOT_DIR, 0755); err != nil {
			return fmt.Errorf("chmod %s to 0755: %w", LPOT_DIR, err)
		}
	}
	tmpInfo, err := os.Lstat(TMP_DIR)
	if err == nil {
		if tmpInfo.Mode()&os.ModeSymlink != 0 || !tmpInfo.IsDir() {
			return fmt.Errorf("%s must be a real directory", TMP_DIR)
		}
		if st, ok := tmpInfo.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("%s must be owned by root (uid 0), found uid %d", TMP_DIR, st.Uid)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(TMP_DIR, 0755); err != nil {
			return fmt.Errorf("create %s: %w", TMP_DIR, err)
		}
	} else {
		return fmt.Errorf("stat %s: %w", TMP_DIR, err)
	}
	if err := os.Chmod(TMP_DIR, 0755); err != nil {
		return fmt.Errorf("chmod %s: %w", TMP_DIR, err)
	}
	return nil
}

// sleepInterruptible blocks until d elapses or ctx is cancelled. It returns
// true if the full duration elapsed and false if the context was cancelled
// first. Callers that must not proceed after cancellation should consult the
// return value (or stopFlag) before taking their next action.
func sleepInterruptible(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// setupSignalHandlers installs SIGINT/SIGTERM handling. The first signal
// triggers graceful shutdown: rootCtx is cancelled (aborting in-flight exec
// commands via exec.CommandContext) and stopFlag is latched so in-process
// sleep loops can exit promptly. A second signal falls through to the Go
// runtime's default handler so an unresponsive run can still be forcibly
// killed with a second Ctrl-C.
func setupSignalHandlers() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nReceived interrupt signal. Cleaning up...")
		stopFlag.Store(true)
		rootCancel()
		<-c
		fmt.Println("Second interrupt: forcing exit.")
		signal.Stop(c)
		os.Exit(130)
	}()
}

// fileExists reports only a usable regular file. Permission and I/O errors are
// not silently converted into "exists", because doing so can make the next
// stage skip required initialization and produce misleading comparisons.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && info.Mode().IsRegular()
}

func installPersistentBinary(source string) error {
	if err := verifyRootRegularFileIfPresent(PERSISTENT_BINARY); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("resolve executable %q: %w", source, err)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return fmt.Errorf("read executable %q: %w", resolved, err)
	}
	if target, targetErr := filepath.EvalSymlinks(PERSISTENT_BINARY); targetErr == nil && target == resolved {
		if err := os.Chmod(PERSISTENT_BINARY, 0755); err != nil {
			return fmt.Errorf("set executable mode on %s: %w", PERSISTENT_BINARY, err)
		}
		return nil
	}

	// Install through a closed temporary inode and rename it into place. Directly
	// truncating /lpot/lpot fails with ETXTBSY when the service is already running
	// that same binary.
	tmp, err := os.CreateTemp(LPOT_DIR, ".lpot-install-*")
	if err != nil {
		return fmt.Errorf("create temporary executable in %s: %w", LPOT_DIR, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		return fmt.Errorf("set temporary executable mode: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary executable: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	if err := os.Rename(tmpName, PERSISTENT_BINARY); err != nil {
		return fmt.Errorf("install executable at %s: %w", PERSISTENT_BINARY, err)
	}
	return nil
}

// Get current timestamp string
func getCurrentTimestamp() string {
	return time.Now().Format(logTimeFormat)
}

// Validate input parameters
func validateInputParameters(waitHours, waitSeconds, standbyTime int) bool {
	if waitHours < 1 || waitHours > 8760 {
		fmt.Fprintf(os.Stderr, "Invalid -t value: duration must be between 1 and 8760 hours.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-t 24` or bare `-t` for the 12-hour default.")
		return false
	}
	if waitSeconds < 10 || waitSeconds > 3600 {
		fmt.Fprintf(os.Stderr, "Invalid -s value: reboot wait must be between 10 and 3600 seconds.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-s 600`.")
		return false
	}
	if standbyTime < 10 || standbyTime > 3600 {
		fmt.Fprintf(os.Stderr, "Invalid -d value: driver wait must be between 10 and 3600 seconds.\n")
		fmt.Fprintln(os.Stderr, "Suggestion: use a value such as `-d 300`.")
		return false
	}
	return true
}

// Write timestamp
func writeTimestamp(hours int) error {
	now := time.Now().Add(time.Duration(hours) * time.Hour)
	data := []byte(fmt.Sprintf("%d\n", now.Unix()))
	if err := writeFileNoFollow(TIMESTAMP_FILE, data, 0644); err != nil {
		return fmt.Errorf("failed to write timestamp file: %v", err)
	}
	if err := os.Chmod(TIMESTAMP_FILE, 0644); err != nil {
		return fmt.Errorf("failed to set timestamp file mode: %v", err)
	}
	return nil
}

// Read timestamp
func readTimestamp() (time.Time, error) {
	data, err := os.ReadFile(TIMESTAMP_FILE)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read timestamp file: %v", err)
	}

	timestamp, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %v", err)
	}

	return time.Unix(timestamp, 0), nil
}

// updateRebootCount atomically reads, increments and writes the persisted
// reboot counter under an exclusive advisory lock. The lock protects against a
// stuck-but-respawned systemd unit racing against the next invocation, which
// would otherwise corrupt the counter and silently break the test schedule.
func updateRebootCount() (int, error) {
	if err := verifyRootRegularFileIfPresent(REBOOTCOUNT_FILE); err != nil {
		return 0, err
	}
	fp, err := os.OpenFile(REBOOTCOUNT_FILE, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return 0, fmt.Errorf("failed to open reboot count file: %v", err)
	}
	defer fp.Close()
	if err := fp.Chmod(0600); err != nil {
		return 0, fmt.Errorf("failed to set reboot count mode: %w", err)
	}

	if err := syscall.Flock(int(fp.Fd()), syscall.LOCK_EX); err != nil {
		return 0, fmt.Errorf("failed to lock reboot count file: %v", err)
	}
	defer syscall.Flock(int(fp.Fd()), syscall.LOCK_UN)

	var buf [64]byte
	n, _ := fp.ReadAt(buf[:], 0)
	count := 1
	if n > 0 {
		if c, err := strconv.Atoi(strings.TrimSpace(string(buf[:n]))); err == nil {
			count = c + 1
		}
	}

	if _, err := fp.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("failed to seek reboot count file: %v", err)
	}
	if err := fp.Truncate(0); err != nil {
		return 0, fmt.Errorf("failed to truncate reboot count file: %v", err)
	}
	if _, err := fmt.Fprintf(fp, "%d\n", count); err != nil {
		return 0, fmt.Errorf("failed to write reboot count: %v", err)
	}
	return count, nil
}

func readRebootCount() (int, error) {
	data, err := os.ReadFile(REBOOTCOUNT_FILE)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read reboot count: %w", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse reboot count: %w", err)
	}
	return count, nil
}

func resetClassificationBaseline() error {
	err := os.Remove(CLASSIFY_STATE_FILE)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func prepareTestCycleLimit(limit int) (bool, error) {
	current, err := readRebootCount()
	if err != nil {
		return false, err
	}
	target, targetErr := readOptionalInteger(TM_TARGET_FILE)
	start, startErr := readOptionalInteger(TM_START_COUNT_FILE)
	cycleTarget := cycleTargetForReboots(limit)
	if targetErr != nil || startErr != nil || target <= 0 || start < 0 || current < start || current >= start+target {
		if err := resetClassificationBaseline(); err != nil {
			return false, fmt.Errorf("reset classification baseline: %w", err)
		}
		target = cycleTarget
		start = current
		if err := writeFileNoFollow(TM_TARGET_FILE, []byte(fmt.Sprintf("%d\n", target)), 0600); err != nil {
			return false, fmt.Errorf("write test cycle target: %w", err)
		}
		if err := writeFileNoFollow(TM_START_COUNT_FILE, []byte(fmt.Sprintf("%d\n", start)), 0600); err != nil {
			return false, fmt.Errorf("write test cycle start count: %w", err)
		}
	}
	return current-start >= target, nil
}

func cycleTargetForReboots(reboots int) int {
	return reboots + 1
}

func readOptionalInteger(path string) (int, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return value, nil
}

func fixedCycleLimitReached(current int) (bool, error) {
	target, err := readOptionalInteger(TM_TARGET_FILE)
	if err != nil {
		return false, err
	}
	start, err := readOptionalInteger(TM_START_COUNT_FILE)
	if err != nil {
		return false, err
	}
	return target > 0 && current-start >= target, nil
}

func disableFixedCycleService() {
	if systemctlPath != "" {
		if _, err := runExternal(systemctlTimeout, systemctlPath, "disable", serviceName); err != nil {
			logWarn("could not disable %s after -tm completion: %v", serviceName, err)
		}
	}
	os.Remove(TM_TARGET_FILE)
	os.Remove(TM_START_COUNT_FILE)
}

// Create reboot script
// buildRebootScript renders the reboot.sh contents that re-invoke executablePath
// with args after reboot, optionally launching customCommand in the
// background first. It is the single source of truth used by
// createRebootScript when writing reboot.sh to disk.
func buildRebootScript(executablePath string, args, customCommand []string) string {
	var script strings.Builder
	script.WriteString("#!/bin/bash\n")
	if len(customCommand) > 0 {
		for i, arg := range customCommand {
			if i > 0 {
				script.WriteString(" ")
			}
			script.WriteString(shellQuote(arg))
		}
		script.WriteString(" >> ")
		script.WriteString(shellQuote(COMMAND_USER_LOG))
		script.WriteString(" 2>&1 &\n")
	}
	script.WriteString("exec ")
	script.WriteString(shellQuote(executablePath))
	for _, arg := range args {
		script.WriteString(" ")
		script.WriteString(shellQuote(arg))
	}
	if len(customCommand) > 0 {
		script.WriteString(" -c")
		for _, arg := range customCommand {
			script.WriteString(" ")
			script.WriteString(shellQuote(arg))
		}
	}
	script.WriteByte('\n')
	return script.String()
}

func createRebootScript(args, customCommand []string) error {
	scriptPath := filepath.Join(LPOT_DIR, "reboot.sh")
	if err := verifyRootRegularFileIfPresent(scriptPath); err != nil {
		return err
	}

	// Install the binary under /lpot before writing the script. The original
	// download location may be /root, /tmp, or another transient directory;
	// systemd must have a stable executable path after reboot.
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current executable: %w", err)
	}
	if err := installPersistentBinary(source); err != nil {
		return err
	}

	executablePath := PERSISTENT_BINARY
	_, err = os.Stat(executablePath)
	if err != nil {
		return fmt.Errorf("verify installed executable %s: %w", executablePath, err)
	}

	script := buildRebootScript(executablePath, args[1:], customCommand)
	if err := writeFileNoFollow(scriptPath, []byte(script), 0700); err != nil {
		return fmt.Errorf("write reboot script %s: %w", scriptPath, err)
	}
	if err := os.Chmod(scriptPath, 0700); err != nil {
		return fmt.Errorf("set reboot script mode on %s: %w", scriptPath, err)
	}
	return nil
}

func persistentRebootArgs(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-scan" || strings.HasPrefix(arg, "-scan=") ||
			arg == "-classify" || strings.HasPrefix(arg, "-classify=") {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

// Reset lpot directory
func resetLpotDirectory() error {
	fmt.Println("Resetting /lpot directory...")
	if os.Geteuid() != 0 {
		return fmt.Errorf("reset requires effective uid 0")
	}
	if systemctlPath == "" {
		return fmt.Errorf("systemctl path was not resolved")
	}
	if err := verifyRootRegularFileIfPresent(servicePath); err != nil {
		return err
	}
	if err := stopAndDisableUnit(serviceName); err != nil {
		return fmt.Errorf("failed to stop and disable %s: %w", serviceName, err)
	}
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", servicePath, err)
	}
	if _, err := runExternal(systemctlTimeout, systemctlPath, "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd after removing %s: %w", servicePath, err)
	}

	// Refuse to operate on LPOT_DIR if it is a symlink or not owned by root,
	// to avoid inadvertently deleting files outside of /lpot.
	info, err := os.Lstat(LPOT_DIR)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to reset: %s is a symlink", LPOT_DIR)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return fmt.Errorf("refusing to reset: %s must be owned by root (uid 0), found uid %d", LPOT_DIR, st.Uid)
		}
	}

	if err := os.MkdirAll(LPOT_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", LPOT_DIR, err)
	}

	// Clean all files directly under /lpot. WalkDir does not descend into
	// symlinks by default; os.Remove removes the symlink entry itself rather
	// than following it, so both layers are safe against a symlink-redirected
	// delete.
	if err := filepath.WalkDir(LPOT_DIR, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && path != LPOT_DIR {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to remove runtime files under %s: %w", LPOT_DIR, err)
	}

	fmt.Println("Reset completed. You can now run LPOT with normal parameters.")
	return nil
}
