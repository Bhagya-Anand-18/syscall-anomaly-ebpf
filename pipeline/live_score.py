#!/usr/bin/env python3
"""Live reconstruction-error scoring against a trained autoencoder, so you
can watch the score cross the threshold in real time during a demo (e.g.
the Phase 7 exploit-runner). Unlike pipeline.run_demo (which uses the Phase
3 placeholder DummyModel), this loads a real checkpoint + threshold.

Usage (from repo root):
    python3 -m pipeline.live_score <cgroup_id> [<cgroup_id> ...] [--tag v1]
"""

import argparse
import json
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

import torch

from pipeline.consumer import parse_lines
from pipeline.vocab import index_for
from model.evaluate import load_model, threshold_path
from model.autoencoder import reconstruction_error

REPO_ROOT = Path(__file__).resolve().parent.parent
LOADER_BIN = REPO_ROOT / "ebpf" / "loader"


def stop_loader():
    subprocess.run(["sudo", "pkill", "-9", "-x", "loader"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cgroup_ids", nargs="+")
    parser.add_argument("--tag", default="v1", help="checkpoint/threshold tag from training")
    parser.add_argument("--stride", type=int, default=1,
                         help="score every Nth new event (default: every event, for a responsive live demo)")
    args = parser.parse_args()

    if not LOADER_BIN.exists():
        print(f"loader binary not found at {LOADER_BIN} -- run 'make' in ebpf/ first", file=sys.stderr)
        sys.exit(1)

    model, window_size = load_model(args.tag)
    threshold = json.load(open(threshold_path(args.tag)))["threshold"]
    print(f"tag={args.tag} window_size={window_size} threshold={threshold:.4f}", file=sys.stderr)
    print("waiting for events...", file=sys.stderr)

    proc = subprocess.Popen(
        ["sudo", str(LOADER_BIN), *args.cgroup_ids],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
    )

    buf = deque(maxlen=window_size)
    seen = 0
    try:
        for record in parse_lines(proc.stdout):
            buf.append(index_for(record.syscall_name))
            seen += 1
            if len(buf) < window_size or seen % args.stride != 0:
                continue
            x = torch.tensor([list(buf)], dtype=torch.long)
            with torch.no_grad():
                err = reconstruction_error(model(x), x).item()
            flag = "  <-- ANOMALY" if err > threshold else ""
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] recon_error={err:.4f}{flag}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        stop_loader()
        proc.wait(timeout=5)
        err_out = proc.stderr.read() if proc.stderr else ""
        if err_out:
            print("--- loader stderr ---", file=sys.stderr)
            print(err_out, file=sys.stderr)


if __name__ == "__main__":
    main()
