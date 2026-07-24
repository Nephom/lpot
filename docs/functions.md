# Function Reference

This is a focused guide to the functions that define the program's behavior.
It is not generated API documentation; the source remains the authoritative
reference.

## Lifecycle and Signals

- `main`: validates the host, parses flags, initializes state, executes one
  reboot cycle, and schedules the next cycle through systemd.
- `runDryRunAudit`: authenticates a hidden `-g <hash>` request and performs
  read-only host inspection, printing all planned commands, mutations, and
  known file contents without writing anything.
- `setupSignalHandlers`: turns SIGINT/SIGTERM into `stopFlag` and context
  cancellation.
- `sleepInterruptible`: waits for a duration while responding to context
  cancellation.
- `updateRebootCount`: updates the reboot counter using an exclusive file lock.

## Security and External Commands

- `ensureRoot`: refuses to run without effective UID 0.
- `resolveBinaries`: sanitizes `PATH` and accepts only trusted system binary
  locations.
- `secureLpotDir`: validates ownership, type, permissions, and symlink status
  of `/lpot`.
- `writeFileNoFollow`: writes with `O_NOFOLLOW` to prevent path redirection.
- `openSecureAppend`: safely appends to an existing or newly created log.
- `openSecureCreateExcl`: creates a file once without a Stat/Create race.
- `shellQuote`: encodes one command-line argument as a POSIX shell word.
- `runExternal`: applies the root context and command-specific timeout.
- `createRebootScript`: creates the reboot script once, rejects symlinks, and
  quotes every executable/argument independently.
- `setupSystemdService`: creates the systemd unit once and rejects a symlink at
   the service path.
- `monitorRebootWait`: compares `/lpot/tmp/<BDF>_init.txt` baselines with
  in-memory polling snapshots during the reboot wait.
- `disableSELinux`: best-effort SELinux configuration update with symlink refusal.
- `disableFirewall`: stops/disables common RHEL, SLES, and Ubuntu firewall
  services and invokes `ufw disable` when available.
- `disableAppArmor`: stops/disables the Ubuntu AppArmor service when present.

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
- `processPCIDevices`: compares topology and per-device text snapshots.
- `compareDeviceFiles`: applies the ignore list to `lspci` text differences.
- `cleanupBDFFiles`: removes current snapshots while keeping initial baselines.

## Reporting

- `recordCycleChange` / `recordCycleNoise`: classify cycle observations.
- `noteCleanCycle` / `flushCleanStreak`: compact repeated clean-cycle output.
- `generateFinalSummary`: writes aggregate results and affected-cycle details.
- `parseRebootLogForStats`: derives summary counters from the persisted log.
