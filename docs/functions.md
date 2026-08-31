# Function Reference

This is a focused guide to the functions that define the program's behavior.
It is not generated API documentation; the source remains the authoritative
reference.

The implementation is intentionally still `package main`; the files are split
by responsibility first so behavior can be verified before introducing
`internal/` packages.

## Lifecycle and Signals

- `main`: validates the host, parses flags, initializes state, executes one
  reboot cycle, and schedules the next cycle through systemd.
- `setupSignalHandlers`: turns SIGINT/SIGTERM into `stopFlag` and context
  cancellation.
- `sleepInterruptible`: waits for a duration while responding to context
  cancellation.
- `updateRebootCount`: updates the reboot counter using an exclusive file lock.

## Security and External Commands

- `ensureRoot`: refuses to run without effective UID 0.
- `resolveBinaries`: sanitizes `PATH` and accepts only trusted system binary
  locations.
- `secureLpotDir`: validates ownership, type, `0755` permissions, and symlink
  status of `/lpot` and `/lpot/tmp`.
- `writeFileNoFollow`: writes with `O_NOFOLLOW` to prevent path redirection.
- `openSecureAppend`: safely appends to an existing or newly created log.
- `isTrustedBinPath`: shared check for whether a resolved tool path lives
  under an allow-listed system directory.
- `shellQuote`: encodes one command-line argument as a POSIX shell word.
- `runExternal`: applies the root context and command-specific timeout.
- `installPersistentBinary`: copies the invoked binary to `/lpot/lpot` so
  systemd does not depend on the original download directory.
- `buildRebootScript`: renders the `reboot.sh` contents written by
  `createRebootScript`.
- `createRebootScript`: refreshes the persistent reboot script, rejects unsafe
  existing files, and quotes every argument independently.
- `setupSystemdService`: refreshes the systemd unit and rejects unsafe existing
  files at the service path.
- `sleepInterruptible`: waits for the reboot delay while still responding to
  cancellation; reboot-wait does not perform a full-output lspci poll.
- `disableSELinux`: best-effort SELinux configuration update with symlink refusal.
- `disableFirewall`: stops/disables common RHEL, SLES, and Ubuntu firewall
  services and invokes `ufw disable` when available.
- `disableAppArmor`: stops/disables the Ubuntu AppArmor service when present.

## Logging

- `logWarn`: writes a single `Warning: ...` line to stderr with a consistent
  prefix and trailing newline; the target for every ad hoc warning print.
- `logWarnFp`: writes the same warning to stderr and, with a timestamp and
  cycle tag, to an open cycle log file. Used for warnings that happen during
  a reboot cycle and should also be visible in `reboot.log`.
- `warnIncompleteReport`: the single call site for "could not save the
  incomplete test report" on every early-exit path in `main()`.
- `fatalOperation` (in `runtime.go`): prints an operation, the underlying
  error, and an optional operator suggestion, then exits with status 1. Every
  fatal startup/mode error in `main()` funnels through this helper.

## PCI Discovery and Filtering

- `fetchPCIBDFs`: discovers PCI devices from sysfs.
- `readPCIDeviceInfo`: reads vendor, class, header, and capability metadata.
- `classifyDevices`: applies endpoint rules and user overrides.
- `filterEndpoints`: returns devices to compare and records skipped devices.
- `normalizeBDF`: unifies `0000:` and short BDF forms on single-domain hosts.
- `printClassificationReport`: renders deterministic classification output.

## Scanning and Comparison

- `scanAndGenerateIgnoreBits`: detects recurring volatile configuration bytes.
- `savePCIConfig` / `compareDeviceConfigs`: persist and compare binary PCI
  configuration snapshots.
- `executeLspci`: captures one device's `lspci -vv` output.
- `processPCIDevices`: compares topology and per-device text snapshots; opens
  `lpotscan.log` once per cycle and passes it to `compareDeviceFiles`/
  `compareDevices` instead of reopening it per device.
- `isComparedLspciField`: the eleven `Dev`/`Lnk` capability field names that
  are compared (`DevCap`, `DevCtl`, `DevSta`, `LnkCap`, `LnkCtl`, `LnkSta`,
  `DevCap2`, `DevCtl2`, `LnkCap2`, `LnkCtl2`, `LnkSta2`).
- `compareDeviceFiles` / `compareDevices`: apply the ignore list and diff the
  selected `lspci` text fields between an `_init.txt` baseline and the current
  snapshot; each difference is written as one compact `<BDF> | <field>
  changed | before: ... | after: ...` line (see `isCompactLpotscanChange` /
  `lspciChangeParts` for the shared parser both `filterLpotscanErrors` and
  `buildResultReport` rely on).
- `persistClassificationConfigDumps`: writes each KEEP device's raw
  config-space bytes to `config_dump/<bdf>_latest.txt` every cycle, and to
  `config_dump/<bdf>_baseline.txt` exactly once (first cycle that device is
  KEEP and readable); the latter is never overwritten again.
- `vendorDeviceFromLspciDump`: best-effort extracts the `[vendor:device]` hex
  ID from a saved `_init.txt` dump so `processPCIDevices` can recognise a
  device that disappeared at one BDF and reappeared at another (see
  `architecture.md`).
- `cleanupBDFFiles`: removes current snapshots while keeping initial baselines.

## Reporting

- `recordCycleChange` / `recordCycleNoise`: classify cycle observations.
- `noteCleanCycle` / `flushCleanStreak`: compact repeated clean-cycle output.
- `generateFinalSummary`: writes aggregate results and affected-cycle details.
- `parseRebootLogForStats`: derives summary counters from the persisted log.
- `buildResultReport`: aggregates the current test session into structured
  status, checks, cycles, problems, and artifact paths; cross-references
  `parseConfigResultChanges` output onto each classification device
  (`config_changed`/`config_change_count`) and, via `parseLspciResultChanges`,
  turns every lspci Dev/Lnk field change into a per-BDF problem with
  before/after values, matching the fidelity config-space changes already
  had.
- `writeResultReport`: writes a checkpoint or final `/lpot/result.json` using
  fsync and atomic rename.
- `startDashboard`: serves the read-only local result dashboard and fixed log
  allowlist on loopback.
