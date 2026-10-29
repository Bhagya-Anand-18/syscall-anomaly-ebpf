#!/usr/bin/env python3
"""Phase 5: bring up the benign-workload containers, capture N seconds of
their syscalls (cgroup-filtered, per Phase 2/3's collector), write to
data/live/benign/, and tear the containers down.

Usage (from repo root):
    python3 -m pipeline.collect_benign --seconds 300
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from pipeline.cgroup_map import cgroup_id_for_container
from pipeline.consumer import parse_lines

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "docker" / "benign-workloads" / "docker-compose.yml"
LOADER_BIN = REPO_ROOT / "ebpf" / "loader"
BENIGN_DIR = REPO_ROOT / "data" / "live" / "benign"

CONTAINER_NAMES = ["benign_web", "benign_batch", "benign_shell"]


def compose_up():
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"], check=True)


def compose_down():
    subprocess.run(["sudo", "docker", "compose", "-f", str(COMPOSE_FILE), "down"], check=True)


def stop_loader():
    subprocess.run(["sudo", "pkill", "-9", "-x", "loader"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=300.0)
    parser.add_argument("--outdir", type=str, default=str(BENIGN_DIR))
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    output_path = outdir / f"benign_{int(time.time())}.jsonl"

    print("starting benign workload containers...", file=sys.stderr)
    compose_up()
    time.sleep(3)  # let containers settle into their loops

    cgroup_ids = []
    for name in CONTAINER_NAMES:
        cg = cgroup_id_for_container(name)
        cgroup_ids.append(str(cg))
        print(f"  {name}: cgroup_id={cg}", file=sys.stderr)

    proc = subprocess.Popen(
        ["sudo", str(LOADER_BIN), *cgroup_ids],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    start = time.monotonic()
    count = 0
    try:
        with open(output_path, "w") as out:
            for record in parse_lines(proc.stdout):
                out.write(json.dumps(record.to_dict()) + "\n")
                count += 1
                if time.monotonic() - start >= args.seconds:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop_loader()
        proc.wait(timeout=5)
        compose_down()

    elapsed = time.monotonic() - start
    print(f"wrote {count} records in {elapsed:.1f}s to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
