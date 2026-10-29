#!/usr/bin/env python3
"""Phase 7: evaluate the benign-trained autoencoder against LID-DS 2019
ground truth -- does it flag real CVE exploits as anomalous while trained
on nothing but benign container traffic?

Usage (from repo root):
    python3 -m model.eval_lidds CVE-2017-7529 CVE-2012-2122 CVE-2014-0160
    python3 -m model.eval_lidds --tag lidds_cve-2017-7529 CVE-2017-7529
"""

import argparse
import json
import sys
from pathlib import Path

import torch
import yaml

from data.lid_ds.loader import load_scenario
from pipeline.features import group_by_container, events_to_sequence
from pipeline.metrics import per_window_metrics, per_attack_instance_recall
from model.evaluate import load_model, threshold_path
from model.autoencoder import reconstruction_error

REPO_ROOT = Path(__file__).resolve().parent.parent


def make_labeled_windows(events, window_size, stride):
    """Mirrors pipeline.windowing.make_windows' slicing exactly, but also
    carries a per-window label (True if any event in the window falls in
    the attack phase) -- kept here rather than in pipeline/windowing.py
    since Phase 4's windowing has no concept of labels."""
    seq = events_to_sequence(events)
    labels = [bool(e.is_attack) for e in events]
    windows, window_labels = [], []
    for start in range(0, len(seq) - window_size + 1, stride):
        windows.append(seq[start:start + window_size])
        window_labels.append(any(labels[start:start + window_size]))
    return windows, window_labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenarios", nargs="+")
    parser.add_argument("--tag", default="v1", help="matches the --tag used at training time")
    args = parser.parse_args()

    model, window_size = load_model(args.tag)
    pipeline_cfg = yaml.safe_load(open(REPO_ROOT / "config" / "pipeline.yaml"))
    stride = pipeline_cfg["stride"]
    threshold = json.load(open(threshold_path(args.tag)))["threshold"]

    print(f"threshold={threshold:.4f}  window_size={window_size}  stride={stride}")

    all_y_true, all_y_pred, all_scores = [], [], []
    all_recordings = []

    for scenario in args.scenarios:
        events = load_scenario(scenario)
        groups = group_by_container(events)
        print(f"{scenario}: {len(groups)} recordings, {len(events)} events", file=sys.stderr)

        for cgroup_id, group in groups.items():
            windows, window_labels = make_labeled_windows(group, window_size, stride)
            if not windows:
                continue

            batch = torch.tensor(windows, dtype=torch.long)
            with torch.no_grad():
                errors = reconstruction_error(model(batch), batch).tolist()
            preds = [e > threshold for e in errors]

            all_y_true.extend(window_labels)
            all_y_pred.extend(preds)
            all_scores.extend(errors)

            attack_windows_flagged = any(
                lbl and pred for lbl, pred in zip(window_labels, preds)
            )
            is_attack_recording = any(window_labels)
            all_recordings.append({
                "is_attack_recording": is_attack_recording,
                "any_attack_window_flagged": attack_windows_flagged,
            })

    print()
    print("=== per-window metrics ===")
    print(f"n_windows={len(all_y_true)}  n_positive={sum(all_y_true)}")
    print(per_window_metrics(all_y_true, all_y_pred, all_scores))

    print()
    print("=== per-attack-instance recall ===")
    print(per_attack_instance_recall(all_recordings))


if __name__ == "__main__":
    main()
