#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * raw_syscalls:sys_enter fires for every syscall on the host, unfiltered --
 * empirically this is several million events per second on this VM. Without
 * an opt-in cgroup allowlist, sustained multi-minute captures for training
 * data are not tractable. filter_enabled defaults to 0 (unset map entries
 * read as zero), so the collector captures everything unless the loader
 * explicitly turns filtering on.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, unsigned long long);
	__type(value, unsigned char);
} watched_cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, unsigned char);
} filter_enabled SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	unsigned long long cgroup_id = bpf_get_current_cgroup_id();
	unsigned int zero = 0;
	unsigned char *filter_on = bpf_map_lookup_elem(&filter_enabled, &zero);
	struct event *e;

	if (filter_on && *filter_on) {
		if (!bpf_map_lookup_elem(&watched_cgroups, &cgroup_id))
			return 0;
	}

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->cgroup_id = cgroup_id;
	e->pid = (int)(bpf_get_current_pid_tgid() >> 32);
	e->syscall_nr = (int)ctx->id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
