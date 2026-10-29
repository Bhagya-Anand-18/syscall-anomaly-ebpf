#ifndef SYSCALL_ANOMALY_COMMON_H
#define SYSCALL_ANOMALY_COMMON_H

/*
 * Plain built-in types only (no <stdint.h>/<linux/types.h>): this header is
 * included by both the BPF object (clang -target bpf, freestanding, no libc
 * sysroot) and the userspace loader, and pulling in libc headers from the
 * bpf-target compile fails to resolve the host's multiarch include path.
 */
#define TASK_COMM_LEN 16

struct event {
	unsigned long long timestamp_ns;
	unsigned long long cgroup_id;
	int pid;
	int syscall_nr;
	char comm[TASK_COMM_LEN];
};

#endif
