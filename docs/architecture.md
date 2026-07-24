# Architecture

## Scope

The executable is a single Go package (`package main`) with no third-party Go
dependencies. It coordinates Linux sysfs, `lspci`, PCI configuration files,
systemd, and reboot persistence.

## Startup Flow

1. `main()` requires root and creates a cancellable root context.
2. Signal handlers cancel external commands and interrupt waits.
3. `resolveBinaries()` sanitizes `PATH` and resolves trusted system binaries.
4. `secureLpotDir()` verifies that `/lpot` is a root-owned, non-symlink
   directory with mode `0700`.
5. Flags are parsed and special modes (`-h`, `-r`, `-scan`, `-classify`) exit
   before the reboot loop.
6. Normal mode prepares the reboot script and systemd service, then records the
   cycle state under `/lpot`.

## Reboot Cycle

Each cycle fetches PCI BDFs, applies endpoint classification and filter
overrides, waits for drivers, samples volatile bytes when needed, and compares:

- PCI device topology.
- Per-device `lspci -vv` output.
- PCI configuration-space snapshots with ignored volatile offsets.

The cycle writes a completion banner before the interruptible reboot delay. A
cancelled context or stop signal is checked again immediately before invoking
`reboot`, preventing a requested stop from causing an unexpected reboot.

## Persistence Across Reboots

`createRebootScript()` writes `/lpot/reboot.sh`. The script re-executes the
current binary with individually shell-quoted arguments. The systemd unit at
`/etc/systemd/system/lpot_reboot.service` starts that script as root after the
next boot. Creation uses `O_EXCL|O_NOFOLLOW`; pre-existing symlinks are rejected.

## Data Safety Boundaries

- External tools run through `exec.CommandContext` with bounded timeouts.
- Tool paths are resolved only from trusted system directories.
- Persistent writes use `O_NOFOLLOW` where truncation or replacement is
  possible.
- Runtime state is outside the repository, so test reports are not source
  files and should not be committed.

## Known Limitations

The raw configuration parser has a known first-device-header edge case in
`splitDevices()`. A future parser should process headers line by line rather
than relying on the current byte separator. A remote host manager, report
collector, and dashboard are also planned but are not part of this executable.
