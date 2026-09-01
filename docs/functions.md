# Function Reference

This is a focused guide to the functions that define the program's behavior.
It is not generated API documentation; the source remains the authoritative
reference. For the complete, generated, per-function caller/callee index and
flow diagrams, see [`call-graph.md`](call-graph.md).

The implementation is intentionally still `package main`; the files are split
by responsibility first so behavior can be verified before introducing
`internal/` packages.

## Lifecycle and Signals

- `main` (`cli_main.go`): validates the host, parses flags — rejecting
  `-t`/`-tm` used together and invalid `-tm` counts — initializes state,
  executes one cycle, and schedules the next cycle through systemd. `-tm n`
  means n cycles and at most n-1 reboots.
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
- `fatalOperation` (in `runtime.go`): prints an operation, the underlying
  error, and an optional operator suggestion, then exits with status 1. Every
  fatal startup/mode error in `main()` funnels through this helper.

## PCI Discovery and Filtering

- `fetchPCIBDFs`: discovers PCI devices from sysfs.
- `readPCIDeviceInfo`: reads vendor, class, header, and capability metadata.
- `classifyDevices`: applies endpoint rules and user overrides.
- `filterClassifiedEndpoints`: partitions an already-classified device list
  into the KEEP set (returned) and the SKIP set (recorded for the report),
  from an existing classification report rather than reclassifying.
- `normalizeBDF`: unifies `0000:` and short BDF forms on single-domain hosts.
- `printClassificationReport`: renders deterministic classification output.

## Scanning and Comparison

- `scanAndGenerateIgnoreBits`: detects recurring volatile configuration bytes.
- `savePCIConfigReportingFailures` / `compareDeviceConfigs`: persist and
  compare binary PCI configuration snapshots. A baselined BDF that is still
  enumerated in sysfs (`pciDeviceEnumeratedInSysfs`) but has no stable sample
  this cycle is reported as UNAVAILABLE (NOTICE); one that has genuinely left
  sysfs is reported as REMOVED (FAIL). Neither ever rewrites `initial.bin`.
- `executeLspci`: captures one device's `lspci -vv` output.
- `processPCIDevices`: compares topology and per-device text snapshots against
  immutable first-valid-cycle baselines; opens `lpotscan.log` once per cycle
  and passes it to `compareDeviceFiles`/`compareDevices`. Separate observation
  state de-duplicates persistent transitions without changing the baseline.
  The same UNAVAILABLE-vs-REMOVED distinction `compareDeviceConfigs` makes
  applies here too, via the same `pciDeviceEnumeratedInSysfs` sysfs check.
- `isComparedLspciField`: the 11 known `Dev`/`Lnk` capability fields (`DevCap`,
  `DevCtl`, `DevSta`, `LnkCap`, `LnkCtl`, `LnkSta`, and the optional
  `*2`/Gen4+ variants). Whichever of these a specific device's `lspci -vv`
  output actually contains is compared (a union of both snapshots); a field
  absent from BOTH snapshots is simply skipped, since not every device
  advertises every field.
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
- `cleanupBDFFiles`: removes current snapshots while keeping immutable initial
  baselines and persisted observation state.

## Reporting

- `recordCycleChange` / `recordCycleNotice` / `recordCycleNoise`: classify
  cycle observations into one of three severities — FAIL (topology/lspci
  changes, always), NOTICE (unconfirmed config-space changes, unreadable
  devices), or INFO (confirmed recurring benign config-space noise) — and
  persist each one as a JSON line to `change_log.jsonl`
  (`appendChangeLogEntry`) so the whole-run "Affected Cycles" summary
  survives the brand-new process each reboot cycle runs in. `cycleChangeKind`/
  `cycleEndStatus`/`cycleRequiresStop` (`reboot_cycle.go`) are the single
  shared classifiers both the cycle-end banner and the `-p` stop condition
  consult, so the two can never disagree.
- `loadPersistedCycleChanges`: reads every event ever recorded across the
  run from `change_log.jsonl`; the sole data source for
  `writeAffectedCyclesSection`.
- `recordConfigSpaceChangeCycle` / `recordDeviceFieldChanges`: persist
  whole-run counters (cycles with config-space changes; per-device and
  per-field lspci change tallies) to `test_stats.json`
  (`loadTestStats`/`saveTestStats`), for the same brand-new-process-per-cycle
  reason as `change_log.jsonl`.
- `topologyState` / `unavailableState` / `classifyReportedState`
  (`device_state.go`): small persisted JSON files that dedupe repeated
  present/absent and read-failure log lines across many cycles WITHOUT ever
  touching the immutable comparison baselines (`<bdf>_init.txt`,
  `initial.bin`, the classification baseline). See `call-graph.md`'s Flow
  Diagrams for exactly where each one is consulted.
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
