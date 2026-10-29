"""Canonical event record shape, shared by the live eBPF collector and (from
Phase 6 onward) LID-DS-derived data, so pipeline/features.py and
pipeline/dataset.py don't need to know which source an event came from.
"""

from dataclasses import dataclass, asdict
from typing import Optional

from pipeline.syscall_table import syscall_name


@dataclass
class EventRecord:
    ts_ns: int
    cgroup_id: int
    pid: int
    syscall_nr: int
    syscall_name: str
    comm: str
    container_name: Optional[str] = None
    # Ground-truth label, only ever set for LID-DS-derived records (Phase 6+
    # eval). Always None for the live collector, which has no ground truth.
    is_attack: Optional[bool] = None

    def to_dict(self) -> dict:
        return asdict(self)


def from_loader_json(raw: dict, container_name: Optional[str] = None) -> EventRecord:
    """Build an EventRecord from one JSON object emitted by ebpf/loader.c."""
    return EventRecord(
        ts_ns=raw["ts_ns"],
        cgroup_id=raw["cgroup_id"],
        pid=raw["pid"],
        syscall_nr=raw["syscall_nr"],
        syscall_name=syscall_name(raw["syscall_nr"]),
        comm=raw.get("comm", ""),
        container_name=container_name,
    )
