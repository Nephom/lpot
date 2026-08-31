package main

import (
	"fmt"
	"os"
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

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
