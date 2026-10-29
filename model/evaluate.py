#!/usr/bin/env python3
"""Phase 5: reconstruction-error distribution over held-out benign data --
establishes the anomaly threshold baseline (fixed percentile, per
IMPLEMENTATION_PLAN.md's recommended default over a learned threshold).

Usage:
    python3 -m model.evaluate "data/live/benign_holdout/*.jsonl"
    python3 -m model.evaluate --tag lidds_cve-2017-7529 "data/lid_ds/exports/CVE-2017-7529_holdout/*.jsonl"
"""

import argparse
import glob
import json
import sys
from pathlib import Path

import torch
import yaml
from torch.utils.data import DataLoader

from pipeline.dataset import SyscallWindowDataset
from model.autoencoder import DenseAutoencoder, reconstruction_error

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKPOINT_DIR = REPO_ROOT / "model" / "checkpoints"


def checkpoint_path(tag: str) -> Path:
    return CHECKPOINT_DIR / f"autoencoder_{tag}.pt"


def threshold_path(tag: str) -> Path:
    return CHECKPOINT_DIR / f"threshold_{tag}.json"


def load_model(tag: str = "v1"):
    ckpt = torch.load(checkpoint_path(tag), map_location="cpu")
    model = DenseAutoencoder(
        vocab_size=ckpt["vocab_size"],
        window_size=ckpt["window_size"],
        embed_dim=ckpt["embed_dim"],
        hidden_dim=ckpt["hidden_dim"],
        bottleneck_dim=ckpt["bottleneck_dim"],
    )
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model, ckpt["window_size"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--percentile", type=float, default=95.0)
    parser.add_argument("--tag", default="v1", help="matches the --tag used at training time")
    args = parser.parse_args()

    files = []
    for pattern in args.paths:
        files.extend(sorted(glob.glob(pattern)))
    if not files:
        print("no input files matched", file=sys.stderr)
        sys.exit(1)

    model, window_size = load_model(args.tag)
    pipeline_cfg = yaml.safe_load(open(REPO_ROOT / "config" / "pipeline.yaml"))
    dataset = SyscallWindowDataset(files, window_size, pipeline_cfg["stride"])
    loader = DataLoader(dataset, batch_size=64)

    errors = []
    with torch.no_grad():
        for batch in loader:
            errors.extend(reconstruction_error(model(batch), batch).tolist())

    if not errors:
        print("no windows produced from held-out data", file=sys.stderr)
        sys.exit(1)

    errors_t = torch.tensor(errors)
    threshold = torch.quantile(errors_t, args.percentile / 100.0).item()

    print(f"n_windows={len(errors)}")
    print(f"mean={errors_t.mean():.4f}  std={errors_t.std():.4f}")
    for p in (50, 90, 95, 99):
        print(f"p{p}={torch.quantile(errors_t, p / 100.0):.4f}")
    print(f"threshold (p{args.percentile})={threshold:.4f}")

    out_path = threshold_path(args.tag)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"percentile": args.percentile, "threshold": threshold}, f)
    print(f"saved threshold to {out_path}")


if __name__ == "__main__":
    main()
