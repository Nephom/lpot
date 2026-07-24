# Development Guide

## Repository Layout

- `main.go`: executable and implementation.
- `main_test.go`: unit tests for security helpers and interruptible control
  flow.
- `go.mod`: Go module metadata.
- `docs/`: operational, architectural, function, and development documentation.
- `.claude/`: project workflow templates and commands.

Runtime binaries, logs, archives, timestamps, and CodeGraph databases are
excluded by `.gitignore`.

## Checks Before a Pull Request

```bash
```

Use `gofmt` on files being modified. The current legacy `main.go` may contain
pre-existing formatting differences; avoid unrelated whole-file formatting
changes unless that is the explicit goal of the change.

## Testing Boundaries

Unit tests must not modify the host's PCI state, reboot the machine, change
SELinux kernel state, or write outside temporary directories. Use dependency
injection or package-level runners for system commands and use `-g` for manual
end-to-end checks.

Hardware validation is separate from unit tests. Before a real reboot run,
confirm the endpoint report with `-classify`, review `/lpot/pcie_filter.txt`,
and verify that the target host is safe to reboot.

## Issue Tracking

Behavior changes, security fixes, parser limitations, and future host-manager
or dashboard work belong in GitHub Issues. Keep this directory focused on
stable technical documentation rather than maintaining a second change log.
