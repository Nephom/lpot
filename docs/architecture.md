# Architecture

## Scope

The executable remains a single Go package (`package main`) with no third-party
Go dependencies, split across responsibility-focused files. It coordinates
Linux sysfs, `lspci`, PCI configuration files, systemd, and reboot persistence.

Current file boundaries are:

- `main.go`: path variables (redirectable only by `simulate_main.go`, see
  below), other constants, and package-level global state shared by every
  build variant.
- `cli_main.go`: `func main()` for the normal production binary (build tag
  `!simulate`, the default): flag parsing, mode dispatch, and the top-level
  startup/cycle/reboot-wait sequence.
- `simulate_main.go`: `func main()` for an offline, root-free 10-cycle
  simulation binary (build tag `simulate`, built with
  `go build -tags simulate`). It exercises the same production comparison
  and reporting functions used by `cli_main.go` (`classifyDevices`,
  `runConfigScan`, `processPCIDevices`, `generateFinalSummary`,
  `writeResultReport`) against a synthetic PCI device model and a fake
  `lspci` script, entirely under a throwaway `./test` directory. It is a
  verification/review tool only and is never installed on a real host.
- `bdf.go`: BDF regular expressions and `normalizeBDF()`.
- `cli.go`: `-c` argument splitting and `-h` help text.
- `lifecycle.go`: root/tool-path resolution, `/lpot` directory safety,
  persistent binary and reboot-script installation, systemd bookkeeping
  helpers, and reboot-count/timestamp/cycle-limit persistence.
- `logging.go`: shared `logWarn`/`logWarnFp`/`warnIncompleteReport`
  helpers so warning output shares one prefix and format.
- `pcie_classify.go`: PCIe endpoint classification (KEEP/SKIP/UNVERIFIED),
  link-capability decoding, and the classification report/baseline (rebased
  in place on every classification change so a change is reported exactly
  once, not every subsequent cycle).
- `pci_config_scan.go`: raw PCI configuration-space sampling, volatile-byte
  detection, and `-scan`/config-space comparison, including the
  `initial.bin` NEW/REMOVED-device baseline rebase.
- `lspci_compare.go`: per-device `lspci -vv` text parsing and the selected
  Dev/Lnk capability-field comparison.
- `reboot_cycle.go`: per-cycle orchestration (`processPCIDevices`, including
  its `<bdf>_init.txt` topology/Dev-Lnk baseline rebase), cycle
  change/noise bookkeeping (persisted to `change_log.jsonl` and
  `test_stats.json` so a multi-cycle summary survives the brand-new
  process each reboot cycle runs in), and clean-streak log compaction.
- `summary.go`: the final test summary and PCI config-space summary sections
  appended to `reboot.log`.
- `result_types.go` / `result_helpers.go`: structured result data model and
  the `/lpot/result.json` aggregation/parsing helpers.
- `dashboard.go`: loopback HTTP server, fixed artifact allowlist, and browser
  launcher.
- `systemd.go`: systemd service, host policy preparation, and SELinux
  handling.
- `runtime.go`: root-owned runtime file checks, safe writes, shell quoting,
  and the `fatalOperation()` fatal-error helper. `simulationMode` (default
  `false`, settable only from `simulate_main.go`) relaxes the root-ownership
  check for offline simulation runs only; the default (non-simulate) build
  never sets it, so production behaviour is unchanged.

Every file is compiled into the same `package main`; the split only groups
related declarations for readability, so cross-file calls behave exactly as
if everything were still in one file (aside from `cli_main.go` and
`simulate_main.go`, which are mutually exclusive build-tag-gated entry
points and are never compiled together).

## Startup Flow

1. Flags are parsed before root and Linux-tool checks. An invocation without
   `-t` only prints help, except for explicit `-r`, `-scan`, `-classify`,
   or `-ui` modes. `-t` and `-tm` are mutually exclusive run modes (hour-based
   duration vs. a fixed reboot count); supplying both is rejected before any
   host mutation begins.
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
    the same report is finalized with `PASS`, `FAIL`, or `INCOMPLETE`.

## Reboot Cycle

Each cycle fetches PCI BDFs, applies endpoint classification and filter
overrides, waits for drivers, samples volatile bytes when needed, and compares:

- PCI device topology.
- The eleven selected PCIe `Dev/Lnk` capability fields (`DevCap`, `DevCtl`,
  `DevSta`, `LnkCap`, `LnkCtl`, `LnkSta`, `DevCap2`, `DevCtl2`, `LnkCap2`,
  `LnkCtl2`, `LnkSta2`) from per-device `lspci -vv` output.
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

## Baseline Rebasing

Every comparison baseline that tracks device *presence* or a *discrete
capability value* (as opposed to a raw config-space byte's occurrence
ratio; see below) is rebased in place to the just-logged new state the
moment a change is reported:

- `processPCIDevices()` rewrites a device's `<bdf>_init.txt` to its current
  `<bdf>.txt` snapshot whenever a Dev/Lnk field change is logged, and
  removes/creates `<bdf>_init.txt` whenever a REMOVED/NEW topology event is
  logged.
- `compareDeviceConfigs()` folds a NEW device into its in-memory
  `initialDevices` map (later rewritten to `initial.bin`) and drops a
  REMOVED device from that same map.
- `writeClassificationReportToLog()` rewrites `CLASSIFY_STATE_FILE` to the
  current cycle's classification snapshot whenever any change/removal is
  logged.

This is required, not cosmetic: without it, a device that disappears (or a
Dev/Lnk field that changes) exactly once would be permanently absent from
(or different from) its comparison baseline for the rest of the run, so
every subsequent cycle would rediscover the SAME disappearance/change and
re-log it, permanently keeping `allUnchanged` false (silently disabling the
lspci Dev/Lnk comparison for the rest of the run) and pinning the
cycle-end banner to "changes detected" long after the underlying state had
actually stabilised.

The one deliberate exception is `compareAndLogDeviceChanges()`'s raw
config-space BYTE-level diff, which stays anchored to the original
one-time `initial.bin` for the entire run by design:
`classifyConfigChangeRatio` (shared by `summary.go` and
`result_helpers.go`) classifies a `(device, offset)` row as benign
"reboot-fixed" noise specifically because it recurs in
`>= rebootFixedThreshold` (80%) of ALL completed cycles when compared
against that fixed baseline — rebasing after the first detected change
would make that register look "clean" from the very next cycle onward,
permanently hiding the classic every-boot-reset pattern this ratio-based
classification exists to surface.

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
