# Deployment

One static binary and one `systemd` unit. Linux only: the process protections in
`internal/platform/hardening` have no equivalent on macOS, so the server refuses to start there
unless `MARSEC_ALLOW_UNPROTECTED_MEMORY=true` is set for local development.

## Install

```sh
make build
sudo sh deploy/systemd/install.sh bin/marsec
```

The script creates a system user, installs the binary to `/usr/local/bin/marsec`, creates
`/etc/marstack-secrets` (`0750`) and `/var/lib/marstack-secrets` (`0700`), and installs the unit.
It does not overwrite an existing environment file.

Put a certificate and key where the environment file points, then:

```sh
sudo systemctl enable --now marstack-secrets
```

## What the unit provides

| Directive | Why |
|---|---|
| `AmbientCapabilities=CAP_IPC_LOCK` | Without it `mlockall` fails and the server refuses to start |
| `LimitMEMLOCK=infinity` | The capability alone is not enough; the resource limit is checked too |
| `LimitCORE=0` | A core dump of this process is a copy of the root key |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other users cannot see the process in `/proc` at all |
| `ProtectSystem=strict`, `ReadWritePaths=` | Only the data directory is writable |
| `MemoryDenyWriteExecute=yes` | No page is ever both writable and executable |
| `RestrictAddressFamilies=AF_INET AF_INET6` | No unix sockets, no netlink, no raw sockets |
| `CapabilityBoundingSet=CAP_IPC_LOCK` | The process cannot gain any other capability, ever |
| `UMask=0077` | Files it creates are unreadable by anyone else |

`SystemCallFilter=@system-service` is used without a deny list. Denying `@resources` is tempting and
wrong here: `setrlimit` lives in that set, and the process calls it to disable core dumps.

`Type=exec` rather than `notify`: the binary does not speak `sd_notify`, and `Type=notify` would
leave systemd waiting for a readiness message that never arrives.

## Verifying a running instance

```sh
PID=$(systemctl show -p MainPID --value marstack-secrets)

sudo grep -E 'VmLck|VmRSS' /proc/$PID/status
sudo grep -E 'Max locked memory|Max core file' /proc/$PID/limits
sudo grep -E 'CapAmb|CapBnd' /proc/$PID/status
sudo ls -l /proc/$PID/mem
systemd-analyze security marstack-secrets
```

What to expect:

| Check | Expected |
|---|---|
| `VmLck` | Non-zero. It reports locked address space, not resident memory |
| `Max locked memory` | `unlimited` |
| `Max core file size` | `0` |
| `CapAmb` and `CapBnd` | `0000000000004000`, which is `CAP_IPC_LOCK` and nothing else |
| Owner of `/proc/$PID/mem` | `root`, not the service user |
| `systemd-analyze security` | Exposure around 1.6 |

The owner of `/proc/$PID/mem` is the check worth understanding. `PR_SET_DUMPABLE=0` hands those
entries to root, so anything else running as `marstack-secrets` cannot read the process memory.
Without it they would belong to the service user, and a second process under that account could read
the root key straight out of memory.

`VmLck` will read far larger than the memory actually in use, because Go reserves a large address
space that `mlockall` marks as locked. On a fresh instance `VmLck` around 1.2 GB alongside a `VmRSS`
of about 88 MB is normal. Size the host by `VmRSS`.

## Host hardening

The unit cannot do these; they belong to the machine:

```sh
swapoff -a
sed -i '/\sswap\s/d' /etc/fstab
sysctl -w vm.swappiness=0
```

Swap is the second line after `mlock`. If locking ever fails or is relaxed, an active swap file means
key material can reach the disk.

Keep the clock synchronised. Lease lifetimes and, from M3, token expiry all depend on it.

## Testing on macOS

`lima/marsec-dev.yaml` provisions an Ubuntu 24.04 VM with the matching Go toolchain, `gitleaks`, and
swap disabled.

```sh
make vm-up
make vm-test
make vm-shell
```

The VM mounts this repository, so a build inside it uses the working tree directly.
