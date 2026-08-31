# Operations Guide

## Safety

LPOT is a Linux system-level test tool. A normal run requires root, writes
under `/lpot`, stops/disables firewall services, stops/disables AppArmor when
present, changes SELinux settings when present, installs `lpot.service`,
and invokes `reboot`. Run it only on a reserved laboratory host. Use `-g`
while validating command-line behavior because it performs a read-only audit
and never changes the host or invokes the reboot command.

An invocation without `-t` only prints help. Use `-t 24` to explicitly start a
reboot test; bare `-t` uses the default duration of 12 hours. `-scan` and
`-classify` may write reports under `/lpot`, but do not disable host security
policies unless normal `-t` mode is selected.

`-ui` starts a read-only dashboard bound to `127.0.0.1`. It can be run as a
non-root user because it only reads `/lpot/result.json` and the allowlisted
reports. It does not run PCI scans, modify host policy, install services, or
reboot.

`-tm n` performs exactly `n` reboots. The initial invocation and the boot after
the final reboot are also recorded as cycles, so `-tm 2` produces three cycle
records and two reboots.

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
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X main.buildTime=${BUILD_TIME}" -o lpot .
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

`-g <hash>` is an authenticated read-only audit mode. Use `./lpot -k` to print
the encrypted root password value accepted by `-g`. It does not create `/lpot`, write logs or
snapshots, modify service/SELinux state, create temporary files, or reboot. It
does inspect the host and prints planned commands plus complete contents for
known text files such as the reboot script, systemd unit, and SELinux config.
Read-only command output, including `lspci`, is printed between explicit output
delimiters. The `-k` and `-g` invocations must use the same binary; a failed
command substitution must not be replaced with an empty authentication value.

## Command-Line Modes

```bash
sudo ./lpot -h
sudo ./lpot -classify
sudo ./lpot -scan
sudo ./lpot -g "$(sudo ./lpot -k)" -t 2 -d 10 -s 10
sudo ./lpot -g "$(sudo ./lpot -k)" -scan
sudo ./lpot -g "$(sudo ./lpot -k)" -classify
./lpot -ui
sudo ./lpot -t 24 -s 600
sudo ./lpot -t 24 -c /usr/bin/ping -t 192.168.1.1
sudo ./lpot -p
sudo ./lpot -r
```

For a first normal run, use a root shell and a stable download location:

```bash
sudo -i
cd /root
./lpot -t 24 -s 600
```

The program copies the invoked binary to `/lpot/lpot` and creates
`/lpot/reboot.sh`. The systemd service runs that fixed path after reboot, so
the original current directory is irrelevant. Do not remove `/lpot/lpot`
until the test is stopped. Run the updated binary with `-t` again when
installing a new version.

| Option | Description | Default |
| --- | --- | --- |
| `-t hours` | Test duration | `12` |
| `-d seconds` | Driver/device preparation delay | `300` |
| `-s seconds` | Delay before reboot | `300` |
| `-tm count` | Exact number of reboots; `count + 1` cycles are recorded | disabled |
| `-p` | Stop after a comparison error | disabled |
| `-c command ...` | Run the command and all following arguments in the background on every boot; append stdout and stderr to `/lpot/command_user_custom.log` | disabled |
| `-g hash` | Hidden authenticated read-only audit; show commands and file contents | disabled |
| `-k` | Show encrypted root password value used to authorize `-g` | off |
| `-r` | Stop and remove `lpot.service`, reload systemd, and reset `/lpot` state; root only | off |
| `-scan` | Scan USB/bridge/volatile devices into `ignore_list.txt` and exit | off |
| `-classify` | List external PCIe endpoints and write a report | off |
| `-ui` | Open the local read-only result dashboard | off |
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

- `lpot`: installed executable used by systemd after reboot.
- `reboot.log`: per-cycle events and final summary.
- `rebootcount`: reboot-cycle counter.
- `timestamp`: test expiration timestamp.
- `initial_pci_devices.txt`: initial `lspci` snapshot.
- `ignore_list.txt`: explicit whole-device ignores for USB controllers plus
  volatile configuration offsets. PCIe capability classification is evidence
  only; decode failures do not remove a device from raw config comparison.
- `config_dump/<bdf>.txt`: current raw PCI configuration bytes for KEEP devices,
  exposed by the dashboard for manual verification of LnkCap and LnkSta decoding.
- `pci-config-changes.log`: configuration-space comparison results.
- `pci_devices_classify.log`: classification report history.
- `lpotscan.log`: lspci comparison log.
- `pcie_filter.txt`: optional endpoint overrides.
- `tmp/`: temporary per-device `lspci` snapshots.
- `result.json`: structured cycle checkpoint and final test report.
- `pci_devices_classify_state.json`: persistent classification snapshot used to
  report only PCIe classification changes after the first cycle.
- `command_user_custom.log`: stdout and stderr from the optional background
  command configured with `-c`.

The repository's `logs/` directory is ignored because reports can contain
host-specific hardware information.

`/lpot` and `/lpot/tmp` are root-owned with mode `0755` for non-root report
inspection. Reboot controls remain root-only: `/lpot/lpot` and
`/lpot/reboot.sh` are mode `0700`.

`result.json` is written once after each completed cycle, before the `-s`
reboot wait begins, and again as the final aggregated report when the test
expires. Writes use a temporary file, `fsync`, and atomic rename so the
dashboard never intentionally reads a partially written JSON document.
Its top-level status is `RUNNING` for a checkpoint, `PASS` when the completed
test has no noteworthy changes, `FAIL` when a noteworthy change is found, and
`INCOMPLETE` when the test is interrupted or reboot fails.
