"""PyTorch Dataset over windowed syscall-ID sequences, reading from one or
more normalized JSONL files (from the live collector today; LID-DS-derived
files from Phase 6 onward -- same schema, same loader, per the Phase 4
decoupling goal in IMPLEMENTATION_PLAN.md).
"""

import json
from pathlib import Path
from typing import List, Union

import torch
from torch.utils.data import Dataset

from pipeline.schema import EventRecord
from pipeline.features import group_by_container, events_to_sequence
from pipeline.windowing import make_windows


def load_jsonl(path: Union[str, Path]) -> List[EventRecord]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            events.append(EventRecord(**raw))
    return events


def windows_from_files(paths: List[Union[str, Path]], window_size: int, stride: int) -> List[List[int]]:
    all_windows: List[List[int]] = []
    for path in paths:
        events = load_jsonl(path)
        for _, group in group_by_container(events).items():
            sequence = events_to_sequence(group)
            all_windows.extend(make_windows(sequence, window_size, stride))
    return all_windows


class SyscallWindowDataset(Dataset):
    def __init__(self, paths: List[Union[str, Path]], window_size: int, stride: int):
        self.windows = windows_from_files(paths, window_size, stride)

    def __len__(self) -> int:
        return len(self.windows)

    def __getitem__(self, idx: int) -> torch.Tensor:
        return torch.tensor(self.windows[idx], dtype=torch.long)
