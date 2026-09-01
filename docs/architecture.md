# Architecture

## Scope

The executable remains a single Go package (`package main`) with no third-party
Go dependencies, split across responsibility-focused files. It coordinates
Linux sysfs, `lspci`, PCI configuration files, systemd, and reboot persistence.

Current file boundaries are:

- `main.go`: path variables, other constants, and package-level global state.
- `cli_main.go`: `func main()`, the single process entry point: flag parsing,
  mode dispatch, and the top-level startup/cycle/reboot-wait sequence.
- `bdf.go`: BDF regular expressions and `normalizeBDF()`.
- `cli.go`: `-c` argument splitting and `-h` help text.
- `lifecycle.go`: root/tool-path resolution, `/lpot` directory safety,
  persistent binary and reboot-script installation, systemd bookkeeping
  helpers, and reboot-count/timestamp/cycle-limit persistence.
- `logging.go`: shared `logWarn`/`logWarnFp` helpers so warning output shares
  one prefix and format.
- `pcie_classify.go`: PCIe endpoint classification (KEEP/SKIP), link-capability
  decoding, the classification report/baseline, and per-device UNAVAILABLE
  tracking for devices whose config-space read fails during classification.
- `pci_config_scan.go`: raw PCI configuration-space sampling, volatile-byte
  detection, and `-scan`/config-space comparison against a fixed baseline.
- `lspci_compare.go`: per-device `lspci -vv` text parsing and Dev/Lnk
  capability-field comparison (union of whichever of the 11 known fields
  either snapshot actually contains) against a fixed baseline.
- `device_state.go`: small persisted JSON state files (`topologyState`,
  `unavailableState`, `classifyReportedState`) that dedupe repeated
  present/absent and read-failure log lines across many cycles WITHOUT ever
  touching an immutable comparison baseline.
- `reboot_cycle.go`: per-cycle orchestration (`processPCIDevices`), event
  transition bookkeeping, three-tier cycle change/notice/noise bookkeeping,
  and clean-streak log compaction. Bookkeeping is persisted to
  `change_log.jsonl` and `test_stats.json` so a multi-cycle summary survives
  the brand-new process each reboot cycle runs in.
- `summary.go`: the final test summary and PCI config-space summary sections
  appended to `reboot.log`.
- `result_types.go` / `result_helpers.go`: structured result data model and
  the `/lpot/result.json` aggregation/parsing helpers.
- `dashboard.go`: loopback HTTP server, fixed artifact allowlist, and browser
  launcher.
- `systemd.go`: systemd service, host policy preparation, and SELinux
  handling.
- `runtime.go`: root-owned runtime file checks, safe writes, shell quoting,
  and the `fatalOperation()` fatal-error helper.

Every file is compiled into the same `package main`; the split only groups
related declarations for readability, so cross-file calls behave exactly as
if everything were still in one file. See [`call-graph.md`](call-graph.md)
for the complete, generated function-level caller/callee index and flow
diagrams.

## Startup Flow

1. Flags are parsed before root and Linux-tool checks. An invocation without
   `-t` or `-tm` only prints help, except for explicit `-r`, `-scan`, `-classify`,
   or `-ui` modes. `-t` and `-tm` are mutually exclusive run modes (hour-based
   duration vs. a fixed cycle count); supplying both is rejected before any
   host mutation begins. `-tm n` records exactly n cycles and starts at most
   n-1 reboots.
2. `main()` requires root for operational modes and creates a cancellable root
   context.
3. Signal handlers cancel external commands and interrupt waits.
4. `resolveBinaries()` sanitizes `PATH` and resolves trusted system binaries.
5. `secureLpotDir()` verifies that `/lpot` is a root-owned, non-symlink
   directory with mode `0755`; `/lpot/tmp` has the same owner and mode.
6. `-scan` and `-classify` write their reports under `/lpot`, but
   do not change firewall, AppArmor, or SELinux policy.
7. Normal `-t` mode stops/disables common firewall services and AppArmor when
   present, sets SELinux permissive for the current boot and disabled for the
   next boot, then prepares the reboot script and systemd service.
8. The cycle state is recorded under `/lpot`.
9. After each completed cycle, result aggregation writes an atomic
    `/lpot/result.json` checkpoint before the reboot wait starts. On expiration,
    the same report is finalized with `PASS` or `FAIL`. If the run is
    interrupted, explicitly stopped, or reboot fails, the finalization pipeline
    still writes the complete `reboot.log` summary and atomically publishes
    `result.json` with `INCOMPLETE`.

## Reboot Cycle

Each cycle waits for the configured driver-ready delay, then fetches PCI BDFs
and applies endpoint classification and filter overrides. Because PCI
enumeration can remain asynchronous after service startup, an empty
link-capable result causes a bounded sequence of fresh sysfs discovery and
classification attempts. The cycle proceeds only with the latest successful
KEEP set; after the retry limit, an empty set is reported as a startup failure.
It then samples volatile bytes when needed and compares:

- PCI device topology.
- The 11 known PCIe `Dev/Lnk` capability fields (`DevCap`, `DevCtl`, `DevSta`,
  `LnkCap`, `LnkCtl`, `LnkSta`, and the optional `*2`/Gen4+ variants
  `DevCap2`, `DevCtl2`, `LnkCap2`, `LnkCtl2`, `LnkSta2`) from per-device
  `lspci -vv` output. Whichever of these a specific device's output actually
  contains is compared (a union of both snapshots); none of them is required
  to be present, since which fields lspci prints depends entirely on what
  capabilities that specific device advertises.
- PCI configuration-space snapshots with ignored volatile offsets.

The cycle writes a completion banner before the interruptible reboot delay. A
cancelled context or stop signal is checked again immediately before invoking
`reboot`, preventing a requested stop from causing an unexpected reboot.
During the `-s` reboot wait, the program only performs an interruptible delay.
It does not compare full lspci text during the wait; PCI changes are evaluated
by the explicit raw config-space and selected Dev/Lnk comparisons before the
wait.

`-p` stops and disables the service when any of the following happens in a
cycle: a Dev/Lnk field or raw config-space byte differs, a BDF disappears, or
a new BDF appears. A device that changes its own BDF (moves to a different
slot) is detected as one disappearance plus one appearance, so it already
triggers `-p` through the same two checks. `processPCIDevices` additionally
best-effort matches a disappeared BDF to a new BDF with the same vendor:device
ID and appends a single `NOTE: device ... may have relocated from ... to ...`
line; this is a readability aid only and never changes whether `-p` stops the
service.

## Baseline and Observation State

Every test compares the current cycle with the **immutable first-valid-cycle
baseline**. The baseline must never be replaced by a changed or missing state:
otherwise a later cycle would compare against the previous error instead of
answering whether reboot preserved the original state.

The three baseline classes are:

- `<bdf>_init.txt`: first-valid-cycle `lspci` Dev/Lnk fields.
- `initial.bin`: first-valid-cycle raw PCI configuration bytes.
- `CLASSIFY_STATE_FILE`: first-valid-cycle classification and device presence.

Event de-duplication is separate from comparison. A persisted current/previous
observation state may suppress a repeated `present -> absent` event while the
device remains absent, but it must not alter the immutable baseline or hide the
fact that the current cycle still differs from it. A later `absent -> present`
transition is a separate event. A BDF change is recorded as the old BDF
removed and the new BDF added, even if their vendor/device IDs match.

The 11 known `lspci` Dev/Lnk fields are `DevCap`, `DevCtl`, `DevSta`, `LnkCap`,
`LnkCtl`, `LnkSta`, and the optional `*2`/Gen4+ variants `DevCap2`, `DevCtl2`,
`LnkCap2`, `LnkCtl2`, `LnkSta2`. None of them is required to be present on any
given device; whichever fields a device's `lspci -vv` output actually contains
are compared (a union of both snapshots), and a field absent from BOTH
snapshots is simply skipped.

When a device cannot be read during a cycle, LPOT distinguishes two cases
rather than treating them the same:

- **UNAVAILABLE**: the device is still enumerated (present in sysfs / this
  cycle's PCI device list, or still selected by this cycle's link
  classification) but its lspci snapshot, raw config-space sample, or
  classification read failed after a bounded number of retries. This is
  NOTICE severity, tracked in `unavailableState` (`device_state.go`) with a
  first-seen cycle/time so later log lines can report how long it has been
  unavailable.
- **REMOVED**: the device has genuinely left sysfs entirely (checked directly
  via `pciDeviceEnumeratedInSysfs`, an `os.Stat` on its sysfs directory — not
  by this cycle's link classification result, which can exclude a
  still-present device for one bad cycle without it actually being gone).
  This is FAIL severity.

Without `-p`, the cycle sequence continues to the next reboot cycle after
recording either kind of event. With `-p`, the current cycle is recorded and
future reboots are stopped after either a FAIL or a NOTICE event.

## Persistence Across Reboots

`createRebootScript()` installs the current binary at `/lpot/lpot` and writes
`/lpot/reboot.sh`. The script re-executes that fixed binary with individually
shell-quoted arguments, independent of the directory from which the first run
was started. The systemd unit at
`/etc/systemd/system/lpot.service` starts that script as root after the next
boot. `systemctl get-default` selects `graphical.target` only when it is the
default; all other systems use `multi-user.target`. Writes use
`O_NOFOLLOW`; pre-existing symlinks are rejected and existing root-owned
regular files are refreshed so changed arguments and binaries take effect.

## Data Safety Boundaries

- External tools run through `exec.CommandContext` with bounded timeouts.
- Tool paths are resolved only from trusted system directories.
- Persistent writes use `O_NOFOLLOW` where truncation or replacement is
  possible.
- Runtime state is outside the repository, so test reports are not source
  files and should not be committed.
- Fatal startup and cycle errors include an operation, the underlying cause,
  and an operator suggestion in stderr.
- `-ui` serves the structured result and fixed report allowlist on
  `127.0.0.1` only; it has no mutation endpoints.

## Known Limitations

The executable assumes `lspci`, systemd, and the Linux PCI sysfs interface are
available. Optional distro components may be absent, but an installed firewall
or mandatory-access-control service that cannot be stopped causes startup to
abort. A remote host manager, report collector, and dashboard are not part of
this executable.
