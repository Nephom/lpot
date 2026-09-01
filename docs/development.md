# Development Guide

## Repository Layout

- `main.go`: constants, global state, and `main()`.
- `bdf.go`, `cli.go`, `lifecycle.go`, `logging.go`: startup, CLI, and
  lifecycle/logging helpers. See `architecture.md` for the full per-file
  breakdown.
- `pcie_classify.go`, `pci_config_scan.go`, `lspci_compare.go`,
  `reboot_cycle.go`, `summary.go`: PCI discovery, classification, scanning,
  comparison, and per-cycle/final reporting.
- `result_types.go`, `result_helpers.go`: structured report model and
  `/lpot/result.json` aggregation/parsing.
- `dashboard.go`: local read-only dashboard server.
- `systemd.go`: systemd and host policy integration.
- `runtime.go`: secure runtime file primitives and operator error reporting.
- `go.mod`: Go module metadata.
- `docs/`: operational, architectural, function, and development documentation.

Every `.go` file above is part of the same `package main`; the split is for
readability only and does not change build, linking, or runtime behavior.

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
GitHub Actions also runs amd64 Linux `go vet`, formatting, and a stripped-binary
check (ELF x86-64 target verification).

Run `go vet ./...` only when a compatible Go static-analysis environment is
available. It is not a substitute for the Linux-target build.

Use `gofmt` on files being modified; the whole tree is currently `gofmt -l`
clean, so unrelated whole-file formatting changes should not be needed.

## Runtime Validation Boundaries

Validation must not modify PCI state, reboot an unrelated machine, change
SELinux kernel state unexpectedly, or write outside the intended runtime
directories.

Before a real reboot run, confirm the endpoint report with `-classify`, review
`/lpot/pcie_filter.txt`, and verify that the target host is safe to reboot.
Run the binary from a stable location with an explicit `-t` value. The first
normal invocation copies it to `/lpot/lpot`, which is the binary used after
reboot.

The result dashboard is intentionally local-only. It reads the atomic
`/lpot/result.json` checkpoint/final report and fixed diagnostic logs; it is not
part of the reboot loop and does not perform live PCI polling.

## Behavioral Contract and Issue Tracking

The test compares every cycle with the immutable first-valid-cycle baseline;
`-tm n` means exactly n cycles and at most n-1 reboots. Baselines must not be
rebased after a detected change. Separate current/previous observation state
may de-duplicate persistent transition messages, but it must not change the
comparison baseline. A device disappearing and later returning are two
separate changes; a BDF change is recorded as removal plus addition.

Without `-p`, an unreadable device is recorded as an incomplete observation
and the reboot cycle continues. With `-p`, the current cycle is recorded and
future reboots stop. Raw config-space changes with unchanged same-BDF lspci
capability fields are NOTICE; topology changes and changes to required lspci
fields are FAIL. The six required fields are `DevCap`, `DevCtl`, `DevSta`,
`LnkCap`, `LnkCtl`, and `LnkSta`; `*2` fields are optional.

Behavior changes, bugs, security fixes, parser limitations, and future
host-manager or dashboard work belong in GitHub Issues. Keep this directory
focused on stable technical documentation rather than maintaining a second
change log.
