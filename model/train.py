#!/usr/bin/env python3
"""Phase 5: train the dense autoencoder on benign-only windowed sequences.

Usage (from repo root):
    python3 -m model.train "data/live/benign/*.jsonl"
    python3 -m model.train --tag lidds_cve-2017-7529 "data/lid_ds/exports/CVE-2017-7529_benign/*.jsonl"
"""

import argparse
import glob
import sys
from pathlib import Path

import torch
import yaml
from torch.utils.data import DataLoader, random_split

from pipeline.dataset import SyscallWindowDataset
from pipeline.vocab import VOCAB_SIZE
from model.autoencoder import DenseAutoencoder, reconstruction_error

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKPOINT_DIR = REPO_ROOT / "model" / "checkpoints"


def load_config():
    pipeline_cfg = yaml.safe_load(open(REPO_ROOT / "config" / "pipeline.yaml"))
    model_cfg = yaml.safe_load(open(REPO_ROOT / "config" / "model.yaml"))
    return pipeline_cfg, model_cfg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", help="glob patterns for benign JSONL files")
    parser.add_argument("--tag", default="v1", help="checkpoint name suffix, e.g. autoencoder_<tag>.pt")
    args = parser.parse_args()

    files = []
    for pattern in args.paths:
        files.extend(sorted(glob.glob(pattern)))
    if not files:
        print("no input files matched", file=sys.stderr)
        sys.exit(1)

    pipeline_cfg, model_cfg = load_config()
    dataset = SyscallWindowDataset(files, pipeline_cfg["window_size"], pipeline_cfg["stride"])
    if len(dataset) < 10:
        print(f"only {len(dataset)} windows available -- need more benign data", file=sys.stderr)
        sys.exit(1)

    val_size = max(1, int(0.1 * len(dataset)))
    train_size = len(dataset) - val_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_ds, batch_size=model_cfg["batch_size"], shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=model_cfg["batch_size"])

    model = DenseAutoencoder(
        vocab_size=VOCAB_SIZE,
        window_size=pipeline_cfg["window_size"],
        embed_dim=model_cfg["embed_dim"],
        hidden_dim=model_cfg["hidden_dim"],
        bottleneck_dim=model_cfg["bottleneck_dim"],
    )
    optimizer = torch.optim.Adam(model.parameters(), lr=model_cfg["learning_rate"])

    for epoch in range(model_cfg["epochs"]):
        model.train()
        train_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            logits = model(batch)
            loss = reconstruction_error(logits, batch).mean()
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch.size(0)
        train_loss /= train_size

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch in val_loader:
                val_loss += reconstruction_error(model(batch), batch).mean().item() * batch.size(0)
        val_loss /= val_size

        print(f"epoch {epoch + 1}/{model_cfg['epochs']}  "
              f"train_loss={train_loss:.4f}  val_loss={val_loss:.4f}")

    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    ckpt_path = CHECKPOINT_DIR / f"autoencoder_{args.tag}.pt"
    torch.save({
        "state_dict": model.state_dict(),
        "vocab_size": VOCAB_SIZE,
        "window_size": pipeline_cfg["window_size"],
        "embed_dim": model_cfg["embed_dim"],
        "hidden_dim": model_cfg["hidden_dim"],
        "bottleneck_dim": model_cfg["bottleneck_dim"],
    }, ckpt_path)
    print(f"saved checkpoint to {ckpt_path}")


if __name__ == "__main__":
    main()
