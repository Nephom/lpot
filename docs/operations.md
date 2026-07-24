# Operations Guide

## Safety

LPOT Integrated is a Linux system-level test tool. A normal run requires root,
writes under `/lpot`, installs `lpot_reboot.service`, changes SELinux settings
when present, and invokes `reboot`. Run it only on a reserved test host. Use
`-g` while validating command-line behavior because debug mode never invokes
the reboot command.

## Requirements

- Linux with effective UID 0.
- Go 1.19 or newer for building.
- `lspci` from `pciutils`.
- `systemd` for persistence across reboots.
- A test host where repeated reboots are expected and safe.

## Build and Validation

```bash
```

## Command-Line Modes

```bash
sudo ./lpot_integrated -h
sudo ./lpot_integrated -classify
sudo ./lpot_integrated -scan
sudo ./lpot_integrated -g -t 2
sudo ./lpot_integrated -t 24 -s 600
sudo ./lpot_integrated -p
sudo ./lpot_integrated -r
```

| Option | Description | Default |
| --- | --- | --- |
| `-t hours` | Test duration | `12` |
| `-d seconds` | Driver/device preparation delay | `300` |
| `-s seconds` | Delay before reboot | `300` |
| `-p` | Stop after a comparison error | disabled |
| `-g` | Debug mode; skip reboot | disabled |
| `-r` | Reset `/lpot` state | off |
| `-scan` | Generate volatile-byte ignore data and exit | off |
| `-classify` | Print endpoint classification and exit | off |
| `-h` | Print help | off |

## Endpoint Filter

The optional `/lpot/pcie_filter.txt` file supports blank lines, `#` comments,
short BDFs such as `21:00.0`, and long BDFs such as `0000:21:00.0`.

```text
# Force inclusion
+ 21:00.0

# Force exclusion; exclusion wins over inclusion
- 03:00.0

# Bare BDF means inclusion
0000:04:00.0
```

Use `-classify` before a reboot test to inspect every keep/skip decision.

## Runtime Files

All persistent state is stored under `/lpot`:

- `reboot.log`: per-cycle events and final summary.
- `rebootcount`: reboot-cycle counter.
- `timestamp`: test expiration timestamp.
- `initial_pci_devices.txt`: initial `lspci` snapshot.
- `ignore_bits.txt`: volatile configuration-byte list.
- `pci-config-changes.log`: configuration-space comparison results.
- `pci_devices_classify.log`: classification report history.
- `pcie_filter.txt`: optional endpoint overrides.
- `tmp/`: temporary per-device `lspci` snapshots.

The repository's `logs/` directory is ignored because reports can contain
host-specific hardware information.
