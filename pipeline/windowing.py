"""Chunks a per-container integer syscall sequence into fixed-size windows.

window_size/stride are empirical (see IMPLEMENTATION_PLAN.md) -- defaults in
config/pipeline.yaml are a starting point, not a validated choice. A trailing
partial window (shorter than window_size) is dropped rather than padded, to
avoid teaching the autoencoder to reconstruct padding tokens.
"""

from typing import List


def make_windows(sequence: List[int], window_size: int, stride: int) -> List[List[int]]:
    if window_size <= 0 or stride <= 0:
        raise ValueError("window_size and stride must be positive")

    windows = []
    for start in range(0, len(sequence) - window_size + 1, stride):
        windows.append(sequence[start:start + window_size])
    return windows
