# LPOT Integrated

LPOT Integrated is a Go implementation of a Linux PCIe reboot-stability test
tool. It combines the original LPOT, `configscan`, and `lpotscan` workflow into
one executable and is maintained as an integrated version of
[Nephom/lpot](https://github.com/Nephom/lpot).

The tool records PCI topology, `lspci` output, and PCI configuration-space
changes across reboot cycles. It classifies PCIe endpoints so that bridges and
other non-endpoint devices do not create misleading failures, while allowing
explicit per-device overrides.

## Warning

This is a system-level test tool, not a desktop utility. A normal run requires
root on a Linux host and can reboot that host repeatedly. It accesses
`/sys/bus/pci`, writes under `/lpot`, modifies the SELinux configuration when
present, installs a systemd service, and invokes `reboot` unless debug mode is
enabled. Use it only on a disposable or explicitly reserved test system.

## Features

- Repeated reboot testing for a configurable duration.
- PCI device topology and `lspci -vv` comparison between cycles.
- PCI configuration-space scanning with volatile-byte filtering.
- Endpoint classification with an optional `/lpot/pcie_filter.txt` override.
- Interruptible waits and bounded external-command execution.
- Root-owned, permission-restricted runtime directory and symlink-resistant
  writes for persistent files.
- Per-cycle logs and a final summary that separates noteworthy changes from
  recurring configuration noise.

## Requirements

- Linux with root access.
- Go 1.19 or newer for building.
- `lspci` from the `pciutils` package.
- `systemd` for reboot persistence during a normal run.
- A test host whose reboot can be interrupted or observed safely.

The repository is expected to build on other Unix-like systems for development,
but the executable's hardware and service operations are Linux-specific.

## Build and Test

```bash
go test ./...
go vet ./...
go build -o lpot_integrated .
```

Install the resulting binary on a Linux test host as appropriate for your
environment. The default `.gitignore` excludes generated reports and artifacts.

## Usage

Always inspect the help output from the exact binary being tested:

```bash
sudo ./lpot_integrated -h
```

Common commands:

```bash
# Dry-run endpoint classification; does not start a reboot test.
sudo ./lpot_integrated -classify

# Generate the volatile PCI configuration-byte ignore list and exit.
sudo ./lpot_integrated -scan

# Two-hour debug run; debug mode does not invoke reboot.
sudo ./lpot_integrated -g -t 2

# Twenty-four hours, waiting 600 seconds before each reboot.
sudo ./lpot_integrated -t 24 -s 600

# Stop after a detected comparison error.
sudo ./lpot_integrated -p

# Reset the runtime directory. Review the target host before using this.
sudo ./lpot_integrated -r
```

Options:

| Option | Meaning | Default |
| --- | --- | --- |
| `-t hours` | Test duration in hours | `12` |
| `-d seconds` | Driver/device preparation delay | `300` |
| `-s seconds` | Delay before reboot | `300` |
| `-p` | Stop when an error is detected | disabled |
| `-g` | Debug mode; do not reboot | disabled |
| `-r` | Reset `/lpot` runtime state | off |
| `-scan` | Generate volatile-byte ignore data and exit | off |
| `-classify` | Print endpoint classification and exit | off |
| `-h` | Show help | off |

## Endpoint Filter

Create `/lpot/pcie_filter.txt` on the test host when the automatic endpoint
classification needs an exception. Blank lines and lines beginning with `#`
are ignored.

```text
# Force an endpoint to be included
+ 21:00.0

# Force a device to be excluded
- 03:00.0

# A bare BDF is treated as an include override
0000:04:00.0
```

Both short (`21:00.0`) and long (`0000:21:00.0`) BDF forms are accepted.
Exclusions take precedence over inclusions. Run `-classify` first to review
the resulting decisions before starting a reboot test.

## Runtime Files

The program stores persistent state under `/lpot`:

- `reboot.log`: per-cycle events and final summary.
- `rebootcount`: current reboot-cycle counter.
- `timestamp`: test expiration timestamp.
- `initial_pci_devices.txt`: initial `lspci` snapshot.
- `ignore_bits.txt`: configuration bytes treated as volatile.
- `pci-config-changes.log`: configuration-space comparison results.
- `pci_devices_classify.log`: historical `-classify` reports.
- `pcie_filter.txt`: optional endpoint overrides.
- `tmp/`: temporary per-device `lspci` snapshots.

The `logs/` directory in this repository is intentionally ignored because
runtime logs can contain host-specific hardware information.

## Review Notes and Known Limitations

The current implementation passes `go test ./...` and `go vet ./...`. The
source includes tests for secure file writes, SELinux symlink refusal, and
interruptible waits. Before production use, validate the full reboot workflow
on the intended Linux hardware.

Known follow-up items are tracked in `TODO.md`, including a parser edge case in
`splitDevices()` where the first device header in a raw config dump can be
parsed incorrectly. The planned management layer for adding hosts, deploying
the agent, collecting reports, and displaying a dashboard is documented in
`CHANGE.md`; it is not implemented by this repository yet.

## License and Relationship to Upstream

This project retains the upstream repository's GPL-3.0 license. See
[`LICENSE`](LICENSE). It is an integrated and modified version of the LPOT
project, not a drop-in replacement for an upstream release. Changes and
integration-specific behavior should be documented when extending the tool.
