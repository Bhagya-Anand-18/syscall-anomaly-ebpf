"""Phase 3 placeholder only: proves the collector -> pipeline -> model
interface end-to-end. Not a real detector -- flags any syscall name outside a
small hardcoded seed set. Replaced by the real autoencoder in Phase 5.
"""

SEED_NORMAL = {
    "read", "write", "openat", "close", "mmap", "munmap", "brk", "fstat",
    "lseek", "ioctl", "rt_sigaction", "rt_sigprocmask", "clone", "execve",
    "exit", "exit_group", "futex", "nanosleep", "getdents64", "epoll_wait",
    "epoll_ctl", "accept4", "connect", "sendto", "recvfrom", "socket",
    "wait4", "pipe2", "dup3", "fcntl", "statx", "newfstatat", "prctl",
}


class DummyModel:
    def is_anomalous(self, event) -> bool:
        return event.syscall_name not in SEED_NORMAL
