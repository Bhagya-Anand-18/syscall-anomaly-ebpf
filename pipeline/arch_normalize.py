"""Reconciles syscall records captured on different architectures (this
project's live collector runs on aarch64; LID-DS 2019 was very likely
captured on x86_64, which has entirely different syscall numbers for the
same syscall). pipeline.schema.EventRecord already carries syscall_name
(resolved per-source, see pipeline/syscall_table.py and
data/lid_ds/loader.py), so cross-source code should match on
EventRecord.syscall_name and never on EventRecord.syscall_nr, which is only
meaningful within its own source.
"""
