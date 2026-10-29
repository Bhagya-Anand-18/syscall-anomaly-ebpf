#!/usr/bin/env python3
"""Phase 3 thin end-to-end skeleton: loader -> consumer -> dummy model.

Usage (run from the repo root):
    python3 -m pipeline.run_demo <cgroup_id> [<cgroup_id> ...] [--seconds N]

At least one cgroup ID should be given (see pipeline/cgroup_map.py) --
running with none floods the pipeline with every syscall on the host (see
ebpf/README-toolchain.md). Requires the loader binary to be built
(cd ebpf && make) and sudo available, since loading/attaching the BPF
program needs elevated privileges.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from pipeline.consumer import parse_lines, default_output_path
from model.dummy_model import DummyModel

LOADER_BIN = Path(__file__).resolve().parent.parent / "ebpf" / "loader"


def stop_loader():
    """sudo pkill by exact name, not proc.terminate()/SIGTERM through sudo --
    the latter has been observed to not reach the loader child process
    reliably (see ebpf/README-toolchain.md)."""
    subprocess.run(["sudo", "pkill", "-9", "-x", "loader"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cgroup_ids", nargs="+")
    parser.add_argument("--seconds", type=float, default=None,
                         help="stop automatically after this many seconds (default: run until Ctrl-C)")
    args = parser.parse_args()

    if not LOADER_BIN.exists():
        print(f"loader binary not found at {LOADER_BIN} -- run 'make' in ebpf/ first", file=sys.stderr)
        sys.exit(1)

    output_path = default_output_path()
    model = DummyModel()
    proc = subprocess.Popen(
        ["sudo", str(LOADER_BIN), *args.cgroup_ids],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    print(f"writing normalized events to {output_path}", file=sys.stderr)
    start = time.monotonic()
    count = 0
    anomalies = 0
    try:
        with open(output_path, "w") as out:
            for record in parse_lines(proc.stdout):
                out.write(json.dumps(record.to_dict()) + "\n")
                count += 1
                if model.is_anomalous(record):
                    anomalies += 1
                    print(f"[FLAG] pid={record.pid} cgroup={record.cgroup_id} "
                          f"syscall={record.syscall_name}", file=sys.stderr)
                if args.seconds is not None and time.monotonic() - start >= args.seconds:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        stop_loader()
        proc.wait(timeout=5)
        err = proc.stderr.read() if proc.stderr else ""
        if err:
            print("--- loader stderr ---", file=sys.stderr)
            print(err, file=sys.stderr)

    elapsed = time.monotonic() - start
    print(f"wrote {count} records ({anomalies} flagged) in {elapsed:.1f}s to {output_path}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
