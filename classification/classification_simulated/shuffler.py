"""
Simulation Data Shuffler  (true full shuffle)
==============================================

Pre-shuffles the large simulation CSV files from  data/simul/  and saves
them to  temp/simul/  with the **same filenames**.

This is a one-time (or occasional) preparation step.  The shuffled
files are then used by  simulation_source.py  which streams them
sequentially — no random-offset tricks needed because the data is
already randomly ordered.

Usage:
    python -m classification.classification_simulated.shuffler

    Or from the project root:
        python classification/classification_simulated/shuffler.py

Algorithm:
    1. Read all data rows as raw byte lines (one file at a time).
    2. random.shuffle() — true granular row-level shuffle.
    3. Write header + shuffled rows to temp/simul/.

Requires enough RAM to hold one CSV in memory (~15-20 GB for 8.7 M rows).
Run this on the VM with high RAM.
"""

import os
import sys
import time
import random

# ── path setup ──────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_SIMUL_SOURCE_DIR,
    CLASSIFICATION_SIMUL_TEMP_DIR,
    CLASSIFICATION_SIMUL_FILES,
    COLOR_CYAN, COLOR_CYAN_BOLD, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_RESET,
)


def shuffle_file(source_path: str, dest_path: str, seed: int) -> int:
    """
    Load all rows, true shuffle, write out.

    Args:
        source_path: path to the original CSV in  data/simul/.
        dest_path:   path to write the shuffled CSV in  temp/simul/.
        seed:        random seed for reproducibility.

    Returns:
        Number of data rows written.
    """
    basename = os.path.basename(source_path)
    size_mb = os.path.getsize(source_path) / (1024 * 1024)

    print(f"\n{COLOR_CYAN}{'─' * 70}{COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}  Shuffling: {basename}  ({size_mb:,.1f} MB){COLOR_RESET}")
    print(f"{COLOR_CYAN}{'─' * 70}{COLOR_RESET}")

    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # ── 1. Load ──────────────────────────────────────────────────
    t0 = time.time()
    print(f"{COLOR_CYAN}  [1/3] Loading rows...{COLOR_RESET}", end="", flush=True)

    with open(source_path, "rb") as f:
        header = f.readline()       # first line = column names
        rows = f.readlines()        # every other line as raw bytes

    t_load = time.time() - t0
    print(f"  {len(rows):,} rows in {t_load:.1f}s")

    # ── 2. Shuffle ───────────────────────────────────────────────
    t1 = time.time()
    print(f"{COLOR_CYAN}  [2/3] Shuffling (seed={seed})...{COLOR_RESET}", end="", flush=True)

    random.seed(seed)
    random.shuffle(rows)

    t_shuf = time.time() - t1
    print(f"  done in {t_shuf:.1f}s")

    # ── 3. Write ─────────────────────────────────────────────────
    t2 = time.time()
    print(f"{COLOR_CYAN}  [3/3] Writing...{COLOR_RESET}", end="", flush=True)

    with open(dest_path, "wb") as f:
        f.write(header)
        f.writelines(rows)

    t_write = time.time() - t2
    total = time.time() - t0
    dest_mb = os.path.getsize(dest_path) / (1024 * 1024)
    total_rows = len(rows)

    del rows  # free memory before next file

    print(f"  {dest_mb:,.1f} MB in {t_write:.1f}s")
    print(f"{COLOR_GREEN}  ✓ Done  {total_rows:,} rows  ({total:.1f}s total){COLOR_RESET}")

    return total_rows


def main():
    """Shuffle all 4 simulation CSV files."""
    print(f"\n{COLOR_CYAN_BOLD}{'=' * 70}{COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}  SIMULATION DATA SHUFFLER  (true full shuffle){COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}{'=' * 70}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  Source : {CLASSIFICATION_SIMUL_SOURCE_DIR}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  Dest   : {CLASSIFICATION_SIMUL_TEMP_DIR}{COLOR_RESET}")

    # Check source dir exists
    if not os.path.isdir(CLASSIFICATION_SIMUL_SOURCE_DIR):
        print(f"\n{COLOR_RED}  ERROR: Source directory not found: "
              f"{CLASSIFICATION_SIMUL_SOURCE_DIR}{COLOR_RESET}")
        sys.exit(1)

    # Collect files to shuffle
    files_to_shuffle = []
    for (model, labeled), filename in sorted(CLASSIFICATION_SIMUL_FILES.items()):
        source_path = os.path.join(CLASSIFICATION_SIMUL_SOURCE_DIR, filename)
        dest_path = os.path.join(CLASSIFICATION_SIMUL_TEMP_DIR, filename)

        if not os.path.isfile(source_path):
            print(f"\n{COLOR_YELLOW}  SKIP: {filename}  (not found in source dir){COLOR_RESET}")
            continue

        label_tag = "labeled" if labeled else "unlabeled"
        files_to_shuffle.append((source_path, dest_path, model, label_tag, filename))

    if not files_to_shuffle:
        print(f"\n{COLOR_RED}  No CSV files found to shuffle.{COLOR_RESET}")
        sys.exit(1)

    print(f"\n{COLOR_CYAN}  Files to shuffle: {len(files_to_shuffle)}{COLOR_RESET}")
    for _, _, model, label_tag, fname in files_to_shuffle:
        print(f"    • {fname}  (model={model}, {label_tag})")

    # Use a single time-based seed for the entire run
    seed = int(time.time() * 1000) % (2**32)
    print(f"\n{COLOR_CYAN}  Random seed: {seed}{COLOR_RESET}")

    # Shuffle each file
    overall_start = time.time()
    total_rows = 0

    for source_path, dest_path, model, label_tag, fname in files_to_shuffle:
        rows = shuffle_file(source_path, dest_path, seed)
        total_rows += rows

    overall_time = time.time() - overall_start

    # Summary
    print(f"\n{COLOR_GREEN}{'=' * 70}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  ALL DONE{COLOR_RESET}")
    print(f"{COLOR_GREEN}{'=' * 70}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Files shuffled:  {len(files_to_shuffle)}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Total rows:      {total_rows:,}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Total time:      {overall_time:.1f}s{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Output dir:      {CLASSIFICATION_SIMUL_TEMP_DIR}{COLOR_RESET}")
    print(f"{COLOR_GREEN}{'=' * 70}{COLOR_RESET}\n")

    # List output files
    print(f"{COLOR_CYAN}  Shuffled files in {CLASSIFICATION_SIMUL_TEMP_DIR}:{COLOR_RESET}")
    for _, dest_path, _, _, fname in files_to_shuffle:
        if os.path.isfile(dest_path):
            sz = os.path.getsize(dest_path) / (1024 * 1024)
            print(f"    ✓ {fname}  ({sz:,.1f} MB)")
    print()


if __name__ == "__main__":
    main()
