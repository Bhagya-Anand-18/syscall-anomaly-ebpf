"""Consumes newline-delimited JSON events from the eBPF loader's stdout and
normalizes them into EventRecord. Container-name resolution is optional and
best-effort (see pipeline/cgroup_map.py) -- not required for the pipeline to
function, only for human-readable debugging.
"""

import json
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional, Dict

from pipeline.schema import EventRecord, from_loader_json

LIVE_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "live"


def parse_lines(
    lines: Iterable[str], cgroup_names: Optional[Dict[int, str]] = None
) -> Iterator[EventRecord]:
    cgroup_names = cgroup_names or {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield from_loader_json(raw, container_name=cgroup_names.get(raw.get("cgroup_id")))


def default_output_path() -> Path:
    LIVE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return LIVE_DATA_DIR / f"events_{int(time.time())}.jsonl"
