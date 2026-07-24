package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// --- T-A: writeFileNoFollow ---

func TestWriteFileNoFollow_Create(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := writeFileNoFollow(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("perm = %o, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if string(data) != "hello" {
		t.Errorf("content = %q, want %q", string(data), "hello")
	}
}

func TestWriteFileNoFollow_Truncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("old-and-longer"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := writeFileNoFollow(path, []byte("new"), 0600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Errorf("content = %q, want %q (O_TRUNC did not apply)", string(data), "new")
	}
}

func TestWriteFileNoFollow_RejectSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	err := writeFileNoFollow(link, []byte("payload"), 0600)
	if err == nil {
		t.Fatal("expected error writing through symlink, got nil")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("expected ELOOP, got %v", err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "untouched" {
		t.Errorf("target was modified: %q", string(data))
	}
}

// --- T-A extra: disableSELinux on three system profiles ---

func TestDisableSELinux_NoConfig(t *testing.T) {
	dir := t.TempDir()
	restore := swapSELinuxConfig(t, filepath.Join(dir, "does-not-exist"))
	defer restore()
	disableSELinux()
}

func TestDisableSELinux_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "shadow-lookalike")
	link := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte("SENSITIVE\n"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	restore := swapSELinuxConfig(t, link)
	defer restore()
	disableSELinux()
	data, _ := os.ReadFile(target)
	if string(data) != "SENSITIVE\n" {
		t.Errorf("symlink target was modified: %q", string(data))
	}
}

func TestDisableSELinux_RealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	const initial = "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	restore := swapSELinuxConfig(t, path)
	defer restore()
	disableSELinux()
	data, _ := os.ReadFile(path)
	want := "# comment\nSELINUX=disabled\nSELINUXTYPE=targeted\n"
	if string(data) != want {
		t.Errorf("rewrite mismatch:\n got: %q\nwant: %q", string(data), want)
	}
}

// swapSELinuxConfig redirects selinuxConfigPath to path for the duration of a
// test and stubs setenforceRunner to a no-op so we never touch kernel state.
func swapSELinuxConfig(t *testing.T, path string) func() {
	t.Helper()
	origPath := selinuxConfigPath
	origRunner := setenforceRunner
	selinuxConfigPath = path
	setenforceRunner = func() {}
	return func() {
		selinuxConfigPath = origPath
		setenforceRunner = origRunner
	}
}

// --- T-B: sleepInterruptible ---

func TestSleepInterruptible_Completes(t *testing.T) {
	start := time.Now()
	ok := sleepInterruptible(context.Background(), 50*time.Millisecond)
	if !ok {
		t.Error("expected full-duration completion")
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("returned too early after %v", elapsed)
	}
}

func TestSleepInterruptible_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	ok := sleepInterruptible(ctx, 5*time.Second)
	if ok {
		t.Error("expected interruption, got full completion")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("did not cancel promptly, took %v", elapsed)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name string
		input string
		want  string
	}{
		{name: "plain", input: "/usr/bin/lpot", want: "'/usr/bin/lpot'"},
		{name: "spaces", input: "-t 2", want: "'-t 2'"},
		{name: "shell metacharacters", input: "x; rm -rf /", want: "'x; rm -rf /'"},
		{name: "single quote", input: "it's", want: "'it'\\''s'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shellQuote(tt.input); got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
