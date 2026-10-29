"""Fixed syscall-name vocabulary for feature encoding.

Built from the same aarch64 syscall table as pipeline/syscall_table.py, so
indices are stable across runs/files regardless of which syscalls actually
appear in a given capture. Per pipeline/syscall_table.py's cross-arch note,
this is keyed on syscall NAME (not raw number) so it's the shared vocabulary
LID-DS (Phase 6, likely x86_64) can be mapped into as well -- a name not in
this table (e.g. an x86_64-only syscall) falls back to UNK rather than
breaking encoding.
"""

from pipeline.syscall_table import SYSCALL_NAME_BY_NR

PAD = "<PAD>"
UNK = "<UNK>"

_names = sorted(set(SYSCALL_NAME_BY_NR.values()))
NAME_TO_INDEX = {PAD: 0, UNK: 1}
for _name in _names:
    NAME_TO_INDEX[_name] = len(NAME_TO_INDEX)

VOCAB_SIZE = len(NAME_TO_INDEX)
PAD_INDEX = NAME_TO_INDEX[PAD]
UNK_INDEX = NAME_TO_INDEX[UNK]


def index_for(syscall_name: str) -> int:
    return NAME_TO_INDEX.get(syscall_name, UNK_INDEX)
