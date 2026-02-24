"""
Fix Extra Columns in CICIDS2018 Tuesday CSV
=============================================

The file 'Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv' (the largest one, ~3.5 GB)
has EXTRA COLUMNS that the other 9 CSV files don't have.

This script:
  1. Reads column headers from a reference file (any of the other 9)
  2. Loads the Tuesday file
  3. Keeps only the 80 common columns, drops the extras
  4. Overwrites the file

Run from project root with venv activated:
    python setup/setup_full/fix_tuesday_csv.py
"""

import os
import sys
import pandas as pd

# Project root = two levels up from setup/setup_full/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")

TUESDAY_FILE = "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"


def get_reference_file():
    """Find any CSV that is NOT the Tuesday file to use as column reference."""
    for f in sorted(os.listdir(RAW_DIR)):
        if f.endswith(".csv") and f != TUESDAY_FILE:
            return f
    return None


def main():
    tuesday_path = os.path.join(RAW_DIR, TUESDAY_FILE)

    if not os.path.exists(tuesday_path):
        print(f"ERROR: {TUESDAY_FILE} not found in {RAW_DIR}")
        print("Make sure you downloaded all 10 CICIDS2018 CSVs into data/raw/")
        sys.exit(1)

    # Get reference columns
    ref_file = get_reference_file()
    if ref_file is None:
        print("ERROR: No other CSV files found in data/raw/ to use as reference.")
        print("Need at least one other CICIDS2018 CSV besides the Tuesday file.")
        sys.exit(1)

    ref_path = os.path.join(RAW_DIR, ref_file)
    ref_cols = pd.read_csv(ref_path, nrows=0).columns.tolist()
    print(f"Reference file: {ref_file} ({len(ref_cols)} columns)")

    # Check Tuesday file
    tuesday_cols = pd.read_csv(tuesday_path, nrows=0).columns.tolist()
    print(f"Tuesday file:   {TUESDAY_FILE} ({len(tuesday_cols)} columns)")

    extra_cols = [c for c in tuesday_cols if c not in ref_cols]

    if not extra_cols:
        print("\nNo extra columns found — file is already fine. Nothing to do.")
        return

    print(f"\nExtra columns found ({len(extra_cols)}): {extra_cols}")
    print(f"\nLoading {TUESDAY_FILE} (~3.5 GB, this may take a minute)...")

    df = pd.read_csv(tuesday_path, low_memory=False)
    print(f"  Loaded: {len(df)} rows, {len(df.columns)} columns")

    # Keep only the common columns
    df = df[ref_cols]
    print(f"  After fix: {len(df.columns)} columns")

    # Save
    print(f"  Saving back to {tuesday_path}...")
    df.to_csv(tuesday_path, index=False)
    print("  Done! File fixed and saved.")


if __name__ == "__main__":
    main()
