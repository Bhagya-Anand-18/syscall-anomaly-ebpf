"""LID-DS 2019 loader.

Confirmed structure (inspected the CVE-2017-7529 archive, the smallest of
the 9 scenarios): each scenario archive extracts to data/lid_ds/raw/<scenario>/
containing ~1000 per-recording .txt files (named after the recording's
Docker container's random name, e.g. "mammoth_bhaskara_4207.txt") plus one
runs.csv mapping each recording to its label.

runs.csv columns: image_name, scenario_name, is_executing_exploit,
warmup_time, recording_time, exploit_start_time. All times in seconds;
exploit_start_time is -1 for non-attack recordings, otherwise the elapsed
time (since the recording's first captured event) at which the exploit began.

Each .txt line: "event_number event_time cpu user_uid process_name
thread_id event_direction event_type event_arguments", where
event_direction is '>' (enter) or '<' (exit) and event_arguments is a
free-form blob that may itself contain spaces, or be absent entirely.
event_time is wall-clock "HH:MM:SS.nanoseconds" with no date -- elapsed
seconds since the recording's own first event line is used as a proxy for
"seconds since recording start", to compare against exploit_start_time.

Only '>' (enter) events are kept, to match this project's live collector,
which only hooks raw_syscalls:sys_enter -- keeping both directions would
double-count every syscall relative to the live-collector's semantics.

LID-DS has no cgroup ID (it's captured host-side via sysdig watching the
container, not via eBPF cgroup tagging like this project's own collector),
so EventRecord.cgroup_id is repurposed here as a stable per-recording
grouping key (crc32 of the recording name) -- not a real cgroup ID, just
enough for pipeline.features.group_by_container to keep recordings separate.
"""

import csv
import zlib
from pathlib import Path
from typing import List, Optional

from pipeline.schema import EventRecord

LID_DS_ROOT = Path(__file__).resolve().parent / "raw"


def _parse_clock(ts: str) -> float:
    """'HH:MM:SS.nnnnnnnnn' -> seconds since midnight, as a float."""
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def _read_runs_csv(scenario_dir: Path) -> dict:
    runs = {}
    with open(scenario_dir / "runs.csv") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        for row in reader:
            runs[row["scenario_name"]] = row
    return runs


def _cgroup_id_for_recording(recording_name: str) -> int:
    return zlib.crc32(recording_name.encode())


def list_available_scenarios() -> List[str]:
    if not LID_DS_ROOT.is_dir():
        return []
    return sorted(p.name for p in LID_DS_ROOT.iterdir() if p.is_dir())


def load_scenario(name: str, limit: Optional[int] = None) -> List[EventRecord]:
    """limit caps the number of recordings loaded (each recording is a
    separate container run) -- useful since a scenario can have ~1000."""
    scenario_dir = LID_DS_ROOT / name
    runs = _read_runs_csv(scenario_dir)

    recording_names = list(runs.keys())
    if limit is not None:
        recording_names = recording_names[:limit]

    events: List[EventRecord] = []
    for recording_name in recording_names:
        run = runs[recording_name]
        is_attack_recording = run["is_executing_exploit"].strip() == "True"
        exploit_start = float(run["exploit_start_time"])
        cgroup_id = _cgroup_id_for_recording(recording_name)

        path = scenario_dir / f"{recording_name}.txt"
        if not path.exists():
            continue

        first_ts = None
        with open(path, errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(None, 8)
                if len(parts) < 8:
                    continue
                (_event_number, event_time, _cpu, _uid,
                 process_name, thread_id, direction, event_type) = parts[:8]
                if direction != ">":
                    continue

                ts = _parse_clock(event_time)
                if first_ts is None:
                    first_ts = ts
                elapsed = ts - first_ts

                is_attack = is_attack_recording and exploit_start >= 0 and elapsed >= exploit_start

                events.append(EventRecord(
                    ts_ns=int(elapsed * 1e9),
                    cgroup_id=cgroup_id,
                    pid=int(thread_id) if thread_id.isdigit() else -1,
                    syscall_nr=-1,
                    syscall_name=event_type,
                    comm=process_name,
                    container_name=recording_name,
                    is_attack=is_attack,
                ))

    return events
