package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func fatalOperation(operation string, err error, suggestion string) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	if suggestion != "" {
		fmt.Fprintf(os.Stderr, "Suggestion: %s\n", suggestion)
	}
	os.Exit(1)
}

// simulationMode relaxes the root-ownership check in
// verifyRootRegularFileIfPresent for offline simulation runs only. It is
// declared here (defaulting to false) but can only ever be set to true by
// simulate_main.go, which is compiled in only under `go build -tags
// simulate`. The normal, non-simulate binary (the default build, and the
// only one ever installed on a real test host) never references this
// variable's assignment path, so production behaviour — every persisted
// /lpot file must be root-owned — is completely unchanged.
var simulationMode bool

func verifyRootRegularFileIfPresent(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to use %s: expected a regular file", path)
	}
	if simulationMode {
		return nil
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("refusing to use %s: owner must be root, found uid %d", path, st.Uid)
	}
	return nil
}

func openSecureAppend(path string, perm os.FileMode) (*os.File, error) {
	if err := verifyRootRegularFileIfPresent(path); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode().Perm() != perm.Perm() {
		if err := os.Chmod(path, perm); err != nil {
			return nil, fmt.Errorf("set mode on %s: %w", path, err)
		}
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, perm)
}

func writeFileNoFollow(path string, data []byte, perm os.FileMode) error {
	if err := verifyRootRegularFileIfPresent(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		f.Close()
		return werr
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeFileAtomicNoFollow publishes a complete file without exposing a
// truncated or partially-written destination. The temporary file is created
// in the destination directory so Rename remains atomic on the same
// filesystem.
func writeFileAtomicNoFollow(path string, data []byte, perm os.FileMode) error {
	if err := verifyRootRegularFileIfPresent(path); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keep = true

	// Persist the directory entry as well, so the rename survives a sudden
	// reboot as reliably as the file contents.
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := dirFile.Sync(); err != nil {
		_ = dirFile.Close()
		return err
	}
	return dirFile.Close()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
