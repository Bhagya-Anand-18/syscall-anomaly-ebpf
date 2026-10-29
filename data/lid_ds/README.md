# LID-DS 2019 integration (Phase 6 -- blocked)

The dataset is still downloading as of this writing. Its internal directory
layout, per-scenario benign/attack split convention, and syscall-log format
(text? CSV? binary?) are all **unknown** -- do not guess them.

## First task once the download is confirmed complete

1. Run `find`/`tree` on the extracted dataset root to inventory its layout.
2. Identify how benign vs. attack phases are distinguished per scenario
   (separate directories? a labels file? timestamps relative to a
   documented exploit-start time?).
3. Identify the raw syscall-log format for one scenario and how to parse it.
4. Only then implement `loader.py`'s `load_scenario()`/`list_available_scenarios()`
   for real, producing `pipeline.schema.EventRecord`s.

## Known cross-source concern

LID-DS 2019 was very likely captured on x86_64, while this project's live
collector runs on aarch64 (different syscall numbering for the same syscall).
Reconcile via syscall **name**, not raw number -- see `pipeline/arch_normalize.py`
and `pipeline/syscall_table.py`'s docstring.

## Which scenarios to use

LID-DS 2019 covers multiple CVE-based attack scenarios. Picking 2-3 for scope
(rather than the full set) is recommended, but which ones is a call to make
once the layout is visible -- pick whichever are best-documented/most
tractable to parse correctly under time pressure.
