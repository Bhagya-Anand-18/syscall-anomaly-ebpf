#!/usr/bin/env python3
"""Exports a LID-DS scenario's normal-behavior (non-exploit) recordings to
JSONL matching pipeline.schema.EventRecord, so the existing model/train.py
(built for the live collector's JSONL output) can train on LID-DS data
unchanged. Per the dataset's own README: "we recommend to use the first 200
recordings of normal behaviour of each scenario as training data for reasons
of comparability."

Usage (from repo root):
    python3 -m data.lid_ds.export_benign CVE-2017-7529 --limit 200 \\
        --outdir data/lid_ds/exports/CVE-2017-7529_benign
"""

import argparse
import json
from pathlib import Path

from data.lid_ds.loader import _read_runs_csv, LID_DS_ROOT, load_scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--offset", type=int, default=0,
                         help="skip this many normal recordings first (e.g. 200 to get a held-out set disjoint from training)")
    parser.add_argument("--outdir", type=str, required=True)
    args = parser.parse_args()

    scenario_dir = LID_DS_ROOT / args.scenario
    runs = _read_runs_csv(scenario_dir)
    normal_names = [
        name for name, row in runs.items() if row["is_executing_exploit"].strip() == "False"
    ][args.offset:args.offset + args.limit]

    events = load_scenario(args.scenario, limit=None)
    normal_set = set(normal_names)
    events = [e for e in events if e.container_name in normal_set]

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / f"{args.scenario}_benign.jsonl"
    with open(out_path, "w") as f:
        for e in events:
            f.write(json.dumps(e.to_dict()) + "\n")

    print(f"wrote {len(events)} events from {len(normal_names)} recordings to {out_path}")


if __name__ == "__main__":
    main()
