"""Resolve a running Docker container's name/ID to the cgroup ID the eBPF
collector tags its events with, so captured events can be attributed back to
a container by name. Validation/debugging use only -- not part of the
production inference path.

Docker on this host uses the systemd cgroup driver with cgroup v2, so each
container's cgroup lives at /sys/fs/cgroup/system.slice/docker-<full-id>.scope.
The cgroup ID bpf_get_current_cgroup_id() returns in the kernel is that
directory's inode number.

Self-elevates its own `docker inspect` call via sudo: the docker CLI needs
root here since this user isn't in the `docker` group (see
ebpf/README-toolchain.md). Callers don't need to run the whole process as
root just to use this function.
"""

import subprocess
import os

CGROUP_ROOT = "/sys/fs/cgroup/system.slice"


def container_full_id(name_or_id: str) -> str:
    out = subprocess.run(
        ["sudo", "docker", "inspect", "--format", "{{.Id}}", name_or_id],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def cgroup_id_for_container(name_or_id: str) -> int:
    full_id = container_full_id(name_or_id)
    scope_path = os.path.join(CGROUP_ROOT, f"docker-{full_id}.scope")
    return os.stat(scope_path).st_ino


if __name__ == "__main__":
    import sys

    for name in sys.argv[1:]:
        print(f"{name}: cgroup_id={cgroup_id_for_container(name)}")
