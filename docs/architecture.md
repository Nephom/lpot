# Architecture

## Scope

The executable is a single Go package (`package main`) with no third-party Go
dependencies. It coordinates Linux sysfs, `lspci`, PCI configuration files,
systemd, and reboot persistence.

## Startup Flow

1. `main()` requires root and creates a cancellable root context.
2. Signal handlers cancel external commands and interrupt waits.
3. `resolveBinaries()` sanitizes `PATH` and resolves trusted system binaries.
4. Flags are parsed before runtime initialization so `-g` can be a true
   no-write audit mode.
5. `secureLpotDir()` verifies that `/lpot` is a root-owned, non-symlink
   directory with mode `0700`.
6. Special modes (`-h`, `-r`, `-scan`, `-classify`) exit
   before the reboot loop.
7. `-g <hash>` authenticates against root's `/etc/shadow` hash and runs a
   read-only audit. With `-scan` or `-classify`, only that mode is audited;
   otherwise the complete normal-run plan is printed without creating `/lpot`
   or changing the host.
8. Normal mode stops/disables common firewall services and AppArmor when
   present, sets SELinux permissive for the current boot and disabled for the
   next boot, then prepares the reboot script and systemd service.
9. The cycle state is recorded under `/lpot`.

## Reboot Cycle

Each cycle fetches PCI BDFs, applies endpoint classification and filter
overrides, waits for drivers, samples volatile bytes when needed, and compares:

- PCI device topology.
- Per-device `lspci -vv` output.
- PCI configuration-space snapshots with ignored volatile offsets.

The cycle writes a completion banner before the interruptible reboot delay. A
cancelled context or stop signal is checked again immediately before invoking
`reboot`, preventing a requested stop from causing an unexpected reboot.
During the `-s` reboot wait, `monitorRebootWait()` polls PCI topology and
`lspci -vv` output. It uses retained `/lpot/tmp/<BDF>_init.txt` files as the
immutable baseline and keeps later observations in memory. Changes are logged;
`-p` cancels reboot while the default behavior continues the countdown.

## Persistence Across Reboots

`createRebootScript()` writes `/lpot/reboot.sh`. The script re-executes the
current binary with individually shell-quoted arguments. The systemd unit at
`/etc/systemd/system/lpot.service` starts that script as root after the next
boot. `systemctl get-default` selects `graphical.target` only when it is the
default; all other systems use `multi-user.target`. Creation uses
`O_EXCL|O_NOFOLLOW`; pre-existing symlinks are rejected. A legacy
`lpot_reboot.service` is stopped, disabled, and removed before installation.

## Data Safety Boundaries

- External tools run through `exec.CommandContext` with bounded timeouts.
- Tool paths are resolved only from trusted system directories.
- Persistent writes use `O_NOFOLLOW` where truncation or replacement is
  possible.
- Runtime state is outside the repository, so test reports are not source
  files and should not be committed.

## Known Limitations

The executable assumes `lspci`, systemd, and the Linux PCI sysfs interface are
available. Optional distro components may be absent, but an installed firewall
or mandatory-access-control service that cannot be stopped causes startup to
abort. A remote host manager, report collector, and dashboard are not part of
this executable.
