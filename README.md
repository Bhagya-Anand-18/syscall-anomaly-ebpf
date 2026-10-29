# Syscall Anomaly Detection for Docker Containers (eBPF + Autoencoder)

Operating Systems course project, Vellore Institute of Technology.
Bhagya Anand (24BDS0074), Raghav Bhargav (24BCI0058).

An eBPF program records every system call made inside chosen Docker
containers. User-space code turns each container's calls into windows of 64
syscall names and scores them with a dense autoencoder trained only on benign
traffic. A window whose reconstruction error is above the 95th percentile of
benign scores raises an alert. No attack data is used for training.

## How it works

```
KERNEL   containers -> raw_syscalls:sys_enter -> eBPF program (cgroup allowlist) -> ring buffer
USER     C loader (JSON lines) -> name vocabulary + 64-call windows -> autoencoder -> score > p95 -> alert
OFFLINE  benign captures or LID-DS normal recordings -> train (Adam, 20 epochs) -> weights + threshold
```

- `ebpf/`: CO-RE eBPF collector (`collector.bpf.c`) and libbpf loader (`loader.c`).
  The collector drops events from cgroups that are not on the allowlist before
  they reach the ring buffer.
- `pipeline/`: event schema, cgroup to container mapping, syscall name
  vocabulary (319 entries, so x86_64 and aarch64 traces share one encoding),
  windowing, benign data collection, live scoring.
- `model/`: dense autoencoder (embedding 16, MLP 128-32-128, 2.78 M parameters),
  training, threshold calibration, LID-DS evaluation.
- `data/lid_ds/`: loader for the LID-DS 2019 data set.
- `docker/`: benign workloads and the CVE-2012-2122 live exploit demo.
- `reports/eval_report.md`: full evaluation write-up.

## Results

| Setting | Result |
|---|---|
| Held-out benign windows (our containers) | median score 0.002, p95 threshold 0.605 |
| Synthetic window of never-seen syscalls | score 12.15 |
| LID-DS, model trained on unrelated containers | ROC-AUC 0.52 (does not transfer across applications) |
| LID-DS CVE-2017-7529, same-application model | 148 of 164 attack recordings flagged (90.2%) |
| Live CVE-2012-2122 exploit on `vulhub/mysql:5.5.23` | window rate up 54x, mean score up 2.2x while the exploit ran |
| Same run, threshold from the container's own idle traffic | 8.1% idle windows flagged, 67.8% attack windows flagged |

The recalibrated threshold in the last row was computed from only 15 idle
windows and applied to the same run, so those two rates are optimistic. CPU and
memory overhead have not been measured yet. See `reports/eval_report.md`.

## Requirements

- Linux with cgroup v2 and kernel BTF (`/sys/kernel/btf/vmlinux`)
- clang/LLVM, libbpf-dev, bpftool, Docker with the Compose v2 plugin
- Python 3 with the packages in `requirements.txt`
- Root access (loading eBPF programs)

Developed on an aarch64 Ubuntu VM (OrbStack). `ebpf/README-toolchain.md` lists
the environment-specific fixes.

## Running

```bash
# 1. Build the collector
cd ebpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
make            # edit BPFTOOL and ARCH_DEFINE in the Makefile for your machine
cd ..
pip install -r requirements.txt

# 2. Collect benign data and train
sudo python3 -m pipeline.collect_benign --seconds 300
sudo python3 -m pipeline.collect_benign --seconds 100 --outdir data/live/benign_holdout
python3 -m model.train "data/live/benign/*.jsonl"
python3 -m model.evaluate "data/live/benign_holdout/*.jsonl"   # writes the p95 threshold

# 3. Score a running container live
sudo python3 -m pipeline.live_score <cgroup_id> --tag v1

# 4. Evaluate on LID-DS 2019 (data set not included; extract to data/lid_ds/raw/)
python3 -m data.lid_ds.export_benign CVE-2017-7529 --limit 200 --outdir data/lid_ds/exports/CVE-2017-7529_benign
python3 -m data.lid_ds.export_benign CVE-2017-7529 --limit 100 --offset 200 --outdir data/lid_ds/exports/CVE-2017-7529_holdout
python3 -m model.train --tag lidds_cve-2017-7529 "data/lid_ds/exports/CVE-2017-7529_benign/*.jsonl"
python3 -m model.evaluate --tag lidds_cve-2017-7529 "data/lid_ds/exports/CVE-2017-7529_holdout/*.jsonl"
python3 -m model.eval_lidds --tag lidds_cve-2017-7529 CVE-2017-7529
```

The live exploit demo is described step by step in `docker/exploit-runner/README.md`.
It starts a deliberately vulnerable MySQL image, so run it only on an isolated
test machine.

Captured data, the LID-DS archives, and trained checkpoints are not in the
repository because of their size.
