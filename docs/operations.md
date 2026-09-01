# Operations Guide

## Safety

LPOT is a Linux system-level test tool. A normal run requires root, writes
under `/lpot`, stops/disables firewall services, stops/disables AppArmor when
present, changes SELinux settings when present, installs `lpot.service`,
and invokes `reboot`. Run it only on a reserved laboratory host.

An invocation without `-t` only prints help. Use `-t 24` to explicitly start a
reboot test; bare `-t` uses the default duration of 12 hours. `-scan` and
`-classify` may write reports under `/lpot`, but do not disable host security
policies unless normal `-t` mode is selected.

`-ui` starts a read-only dashboard bound to `127.0.0.1`. It can be run as a
non-root user because it only reads `/lpot/result.json` and the allowlisted
reports. It does not run PCI scans, modify host policy, install services, or
reboot.

`-tm n` performs exactly `n` cycles. The initial invocation is the first cycle,
so at most `n - 1` reboots are started; `-tm 2` produces two cycle records and
one reboot. `-t` continues while its time window remains active; after a reboot,
it runs another cycle only when the time window has not expired.

## Requirements

- Linux with effective UID 0.
- Go 1.19 or newer for building.
- `lspci` from `pciutils`.
- `systemd` for persistence across reboots.
- PCI discovery is performed after the `-d` driver-ready delay. If no
  link-capable endpoint is visible, LPOT re-reads sysfs and reclassifies the
  current device set a bounded number of times before reporting a failure.
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

## Command-Line Modes

```bash
sudo ./lpot -h
sudo ./lpot -classify
sudo ./lpot -scan
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
the original current directory is irrelevant. After boot, LPOT waits for the
configured `-d` driver/device delay before taking its PCI snapshot. If PCI
enumeration is still in progress and no link-capable endpoint is found, LPOT
performs bounded fresh sysfs discovery retries rather than reusing the initial
device list. Do not remove `/lpot/lpot` until the test is stopped. Run the
updated binary with `-t` again when installing a new version.

| Option | Description | Default |
| --- | --- | --- |
| `-t hours` | Test duration | `12` |
| `-d seconds` | Driver/device preparation delay | `300` |
| `-s seconds` | Delay before reboot | `300` |
| `-tm count` | Exact number of cycles; at most `count - 1` reboots are started | disabled |
| `-p` | Stop after a comparison error | disabled |
| `-c command ...` | Run the command and all following arguments in the background on every boot; append stdout and stderr to `/lpot/command_user_custom.log` | disabled |
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
- `tm_target` / `tm_start_count`: `-tm` cycle target and start counter,
  written for fixed-cycle runs and removed when the limit completes.
- `initial_pci_devices.txt`: initial `lspci` snapshot.
- `ignore_list.txt`: explicit whole-device ignores for USB controllers plus
  volatile configuration offsets. PCIe capability classification is evidence
  only; decode failures do not remove a device from raw config comparison.
- `config_dump/<bdf>_baseline.txt`: the first-cycle raw PCI configuration
  bytes for each KEEP device, captured once and never overwritten.
- `config_dump/<bdf>_latest.txt`: the current cycle's raw PCI configuration
  bytes for each KEEP device, refreshed every cycle. The dashboard exposes
  both via `/api/config?bdf=..&which=baseline|latest` for manual verification
  and comparison of LnkCap/LnkSta decoding over time.
- `pci-config-changes.log`: configuration-space comparison results, always
  diffed against the immutable first-valid-cycle `/lpot/initial.bin` baseline.
  Event de-duplication uses separate current/previous observation state; the
  original baseline is never rewritten during a test.
- `pci_devices_classify.log`: classification report history.
- `lpotscan.log`: lspci comparison log, one compact `<BDF> | <field> changed |
  before: ... | after: ...` line per changed Dev/Lnk capability field,
  accumulated for the entire run (like `pci-config-changes.log`, it is not
  truncated between cycles; every line is tagged with `[Cycle N]`).
- `pcie_filter.txt`: optional endpoint overrides.
- `tmp/`: temporary per-device `lspci` snapshots. `<bdf>_init.txt` is the
  immutable first-valid-cycle Dev/Lnk baseline. Separate observation state
  prevents repeated transition messages without changing the original
  comparison baseline.
- `result.json`: structured cycle checkpoint and final test report.
- `pci_devices_classify_state.json`: first-valid-cycle classification baseline;
  it is not rewritten when a classification changes. Separate observation
  state records present/absent and classification transitions.
- `change_log.jsonl`: one JSON line per recorded topology/lspci/config-space
  change event, accumulated for the entire run. Because each reboot cycle
  runs in a brand-new process, this file (not an in-memory list) is what lets
  the final summary's "Affected Cycles" section cover every cycle of a
  multi-day run instead of only the last one.
- `test_stats.json`: persisted whole-run counters ("Most affected device",
  "Most changed field", and whether any raw config-space change occurred),
  for the same brand-new-process-per-cycle reason as `change_log.jsonl`.
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
Its top-level status is `RUNNING` for a checkpoint, `PASS` only when the
completed test has no changes, `NOTICE` when raw config-space changed but the
same-BDF lspci capability fields did not, `FAIL` when topology or required
lspci capability fields changed, and `INCOMPLETE` when the planned run is
stopped before completion. A read failure is recorded as an incomplete
observation; without `-p` the next reboot cycle still proceeds, while `-p`
stops future reboots after the current cycle is recorded. Every interrupted,
stop-requested, or failed-reboot exit also appends a final `Test Session Summary`
to `reboot.log`; the summary is marked `INCOMPLETE` and contains all statistics
available from the cycles recorded before the interruption.
