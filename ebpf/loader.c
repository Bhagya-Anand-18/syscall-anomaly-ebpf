#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include "collector.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	(void)level;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;
	const struct event *e = data;

	/* Newline-delimited JSON on stdout: the IPC contract with pipeline/consumer.py */
	printf("{\"ts_ns\":%llu,\"cgroup_id\":%llu,\"pid\":%d,\"syscall_nr\":%d,\"comm\":\"%.*s\"}\n",
	       (unsigned long long)e->timestamp_ns, (unsigned long long)e->cgroup_id,
	       e->pid, e->syscall_nr, TASK_COMM_LEN, e->comm);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct collector_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err = 0;

	libbpf_set_print(libbpf_print_fn);

	skel = collector_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load BPF skeleton\n");
		return 1;
	}

	/* Optional argv: a list of cgroup IDs to filter to. With none given,
	 * the collector captures every syscall on the host (Phase 1/2 mode). */
	if (argc > 1) {
		int watch_fd = bpf_map__fd(skel->maps.watched_cgroups);
		int filter_fd = bpf_map__fd(skel->maps.filter_enabled);
		unsigned char one = 1;
		unsigned int zero_key = 0;
		int i;

		for (i = 1; i < argc; i++) {
			unsigned long long cg = strtoull(argv[i], NULL, 10);

			bpf_map_update_elem(watch_fd, &cg, &one, BPF_ANY);
		}
		bpf_map_update_elem(filter_fd, &zero_key, &one, BPF_ANY);
		fprintf(stderr, "cgroup filter enabled for %d id(s)\n", argc - 1);
	}

	err = collector_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF program: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		err = -1;
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	fprintf(stderr, "collector attached, streaming JSON-lines events to stdout...\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring buffer poll error: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	collector_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
