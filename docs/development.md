# Development Guide

## Repository Layout

- `main.go`: executable and implementation.
- `go.mod`: Go module metadata.
- `docs/`: operational, architectural, function, and development documentation.

Runtime binaries, logs, archives, timestamps, and local tool state are excluded
by `.gitignore`.

## Linux Target Build

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o lpot .
```

The command may be run from the macOS development environment and produces a
Linux `amd64` executable. The supported runtime target is Linux; macOS is not a
runtime target. No full unit-test suite is maintained for this system-level
tool. The required local verification is a successful Linux-target compilation;
GitHub Actions also runs amd64 Linux `go vet`, formatting, and stripped-binary
checks.

Run `go vet ./...` only when a compatible Go static-analysis environment is
available. It is not a substitute for the Linux-target build.

Use `gofmt` on files being modified. The current legacy `main.go` may contain
pre-existing formatting differences; avoid unrelated whole-file formatting
changes unless that is the explicit goal of the change.

## Runtime Validation Boundaries

Validation must not modify PCI state, reboot an unrelated machine, change
SELinux kernel state unexpectedly, or write outside the intended runtime
directories. Use authenticated `-g <hash>` for manual read-only audit checks
before enabling reboot mode.

Before a real reboot run, confirm the endpoint report with `-classify`, review
`/lpot/pcie_filter.txt`, and verify that the target host is safe to reboot.
Run the binary from a stable location with an explicit `-t` value. The first
normal invocation copies it to `/lpot/lpot`, which is the binary used after
reboot.

## Issue Tracking

Behavior changes, security fixes, parser limitations, and future host-manager
or dashboard work belong in GitHub Issues. Keep this directory focused on
stable technical documentation rather than maintaining a second change log.
