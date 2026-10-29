"""Converts an ordered per-container syscall event sequence into the raw
syscall-ID (vocab-index) representation chosen for Phase 4 -- see
IMPLEMENTATION_PLAN.md's "feature representation" decision. Decoupled from
data source: works the same whether events came from the live collector or
(from Phase 6) LID-DS.
"""

from typing import List, Iterable

from pipeline.schema import EventRecord
from pipeline.vocab import index_for


def group_by_container(events: Iterable[EventRecord]) -> dict:
    """Group events by cgroup_id and sort each group by timestamp.
    cgroup_id is used as the grouping key (not container_name) since it's
    always present; container_name may be unresolved."""
    groups: dict = {}
    for e in events:
        groups.setdefault(e.cgroup_id, []).append(e)
    for cgroup_id, group in groups.items():
        group.sort(key=lambda e: e.ts_ns)
    return groups


def events_to_sequence(events: List[EventRecord]) -> List[int]:
    """events must already be ordered by timestamp (see group_by_container)."""
    return [index_for(e.syscall_name) for e in events]
