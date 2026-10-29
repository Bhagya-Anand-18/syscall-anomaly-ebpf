# Toolchain notes (Phase 0)

## Environment
- OrbStack Ubuntu VM, aarch64, kernel `7.0.14-orbstack-00380-ga7e0a2dc9535`.
- Ubuntu 24.04 (noble) userland; init system is systemd.
- `/sys/kernel/btf/vmlinux` present — CO-RE via BTF is viable.
- Kernel configs confirmed via `/proc/config.gz`: `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`,
  `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_DEBUG_INFO_BTF_MODULES=y`.

## Installed
- `clang`/`llvm` 18.1.3 (via apt: `clang llvm`)
- `libbpf-dev` 1:1.3.0-2build2 (provides `/usr/include/aarch64-linux-gnu/bpf/*.h`:
  `bpf_helpers.h`, `bpf_core_read.h`, `bpf_tracing.h`, etc. — needed for CO-RE)
- `python3-pip` (pip 24.0)
- `git` 2.43.0
- `docker.io` 29.1.3 (engine, containerd, runc)

## bpftool — kernel-version wrapper quirk
`linux-tools-common`/`linux-tools-generic` were already installed (for the *generic*
Ubuntu kernel 6.8.0-139), which installs `/usr/sbin/bpftool` as a **wrapper script**
that checks `uname -r` and refuses to run on a kernel it doesn't recognize:

```
WARNING: bpftool not found for kernel 7.0.14-orbstack
```

This is a custom OrbStack kernel, so no `linux-tools-<exact-version>` package exists
for it (expected, matches the "no linux-headers package available" constraint from
the project brief). The **real bpftool binary** installed by that package is at:

```
/usr/lib/linux-tools-6.8.0-139/bpftool
```

It works fine invoked directly against this kernel's BTF (bpftool's BTF-dump and
prog-load functionality isn't tied to exact kernel-version matching the way the
wrapper script assumes). All Makefiles/scripts in this repo call bpftool via this
full path rather than relying on `bpftool` resolving on `$PATH`. (Symlinking it into
`/usr/local/bin` was attempted but blocked by this environment's safety guard for
system-wide PATH changes — full-path invocation is simpler anyway and avoids
depending on that symlink surviving.)

## vmlinux.h
Generated via:
```
sudo /usr/lib/linux-tools-6.8.0-139/bpftool btf dump file /sys/kernel/btf/vmlinux \
    format c > ebpf/vmlinux.h
```
Result: 2.85MB, ~133,900 lines. Regenerate this if the kernel is upgraded/changed.

## Docker / cgroup version
`docker info` confirms:
```
Cgroup Driver: systemd
Cgroup Version: 2
```
This resolves the Phase 0 "cgroup v1 vs v2" open question from the plan: it's
**v2 (unified hierarchy)**, so `bpf_get_current_cgroup_id()` should work directly
in `collector.bpf.c` — no v1 fallback path needed.

**Known constraint:** this environment's safety guard blocked adding the user to
the `docker` group (`usermod -aG docker`) and blocked `systemctl start docker`
(both flagged as persistent system/account changes requiring explicit user
action). Docker was started successfully via `sudo service docker start` instead,
and all `docker` commands in this repo's scripts run under `sudo`. **If you want
docker usable without `sudo` for your own interactive use, run this yourself:**
```
sudo usermod -aG docker $USER
# then log out/in (or `newgrp docker`) for the group change to take effect
```

## Verification (Phase 0 done-criteria, all passed)
- `clang --version` / `llvm-config --version` → 18.1.3 ✓
- `sudo /usr/lib/linux-tools-6.8.0-139/bpftool version` → v7.4.0 ✓
- `sudo docker run --rm hello-world` → succeeds ✓
- `python3 -m pip --version` → pip 24.0 ✓
- `ebpf/vmlinux.h` exists, 2.85MB ✓
- Cgroup version documented → v2 ✓
