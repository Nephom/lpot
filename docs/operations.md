# Operations Guide

## Safety

LPOT is a Linux system-level test tool. A normal run requires root, writes
under `/lpot`, stops/disables firewall services, stops/disables AppArmor when
present, changes SELinux settings when present, installs `lpot_reboot.service`,
and invokes `reboot`. Run it only on a reserved laboratory host. Use `-g`
while validating command-line behavior because it performs a read-only audit
and never changes the host or invokes the reboot command.

## Requirements

- Linux with effective UID 0.
- Go 1.19 or newer for building.
- `lspci` from `pciutils`.
- `systemd` for persistence across reboots.
- Permission to disable firewall and mandatory access-control services on the
  dedicated test host.
- A test host where repeated reboots are expected and safe.

## Build and Validation

```bash
GOOS=linux GOARCH=amd64 go build -o lpot .
```

The runtime preparation is distribution-aware across RHEL, SLES, and Ubuntu.
Missing optional services are ignored, but a detected service that cannot be
stopped/disabled aborts before the reboot service is created:

- Firewall services: `firewalld`, `ufw`, `nftables`, `iptables`, `ip6tables`,
  and legacy `SuSEfirewall2` are stopped and disabled when present.
- AppArmor: the `apparmor` service is stopped and disabled when present.
- SELinux: `setenforce 0` is attempted immediately, and
  `/etc/selinux/config` is set to `SELINUX=disabled` for the next boot.

An absent service is normal for a given distribution and is not an error.

`-g` is a read-only audit mode. It does not create `/lpot`, write logs or
snapshots, modify service/SELinux state, create temporary files, or reboot. It
does inspect the host and prints planned commands plus complete contents for
known text files such as the reboot script, systemd unit, and SELinux config.
Read-only command output, including `lspci`, is printed between explicit output
delimiters.

## Command-Line Modes

```bash
sudo ./lpot -h
sudo ./lpot -classify
sudo ./lpot -scan
sudo ./lpot -g -t 2 -d 10 -s 10
sudo ./lpot -t 24 -s 600
sudo ./lpot -p
sudo ./lpot -r
```

| Option | Description | Default |
| --- | --- | --- |
| `-t hours` | Test duration | `12` |
| `-d seconds` | Driver/device preparation delay | `300` |
| `-s seconds` | Delay before reboot | `300` |
| `-p` | Stop after a comparison error | disabled |
| `-g` | Read-only dry-run audit; show commands and file contents without mutation | disabled |
| `-r` | Reset `/lpot` state | off |
| `-scan` | Scan USB/bridge/volatile devices into `ignore_list.txt` and exit | off |
| `-classify` | List external PCIe endpoints and write a report | off |
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
- `ignore_list.txt`: whole-device ignores plus volatile configuration offsets.
- `pci-config-changes.log`: configuration-space comparison results.
- `pci_devices_classify.log`: classification report history.
- `lpotscan.log`: lspci comparison log.
- `pcie_filter.txt`: optional endpoint overrides.
- `tmp/`: temporary per-device `lspci` snapshots.

The repository's `logs/` directory is ignored because reports can contain
host-specific hardware information.
