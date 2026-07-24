# Development Guide

## Repository Layout

- `main.go`: executable and implementation.
- `go.mod`: Go module metadata.
- `docs/`: operational, architectural, function, and development documentation.
- `.claude/`: project workflow templates and commands.

Runtime binaries, logs, archives, timestamps, and CodeGraph databases are
excluded by `.gitignore`.

## Linux Checks Before a Pull Request

```bash
GOOS=linux GOARCH=amd64 go build -o lpot_integrated .
go vet ./...
git diff --check
```

Run these commands on Linux. The supported target is Linux and the project does
not require or document macOS compilation or testing.

Use `gofmt` on files being modified. The current legacy `main.go` may contain
pre-existing formatting differences; avoid unrelated whole-file formatting
changes unless that is the explicit goal of the change.

## Validation Boundaries

Validation must not modify PCI state, reboot an unrelated machine, change
SELinux kernel state unexpectedly, or write outside the intended runtime
directories. Use `-g` for manual end-to-end checks before enabling reboot mode.

Before a real reboot run, confirm the endpoint report with `-classify`, review
`/lpot/pcie_filter.txt`, and verify that the target host is safe to reboot.

## Issue Tracking

Behavior changes, security fixes, parser limitations, and future host-manager
or dashboard work belong in GitHub Issues. Keep this directory focused on
stable technical documentation rather than maintaining a second change log.
