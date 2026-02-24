"""
Verify CICIDS2018 Raw CSV Files
================================

Checks that all 10 CSV files exist in data/raw/ and all have the same column count (80).

Run from project root with venv activated:
    python setup/setup_full/verify_csv_files.py
"""

import os
import sys

# Project root = two levels up from setup/setup_full/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")

EXPECTED_FILES = [
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
]

EXPECTED_COLUMNS = 80


def main():
    print("=" * 70)
    print("CICIDS2018 Raw CSV Verification")
    print("=" * 70)
    print(f"\nChecking: {RAW_DIR}\n")

    if not os.path.exists(RAW_DIR):
        print("ERROR: data/raw/ folder does not exist!")
        print("Create it and place the 10 CICIDS2018 CSV files there.")
        sys.exit(1)

    all_ok = True

    # Check each expected file
    for fname in EXPECTED_FILES:
        fpath = os.path.join(RAW_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  MISSING: {fname}")
            all_ok = False
            continue

        # Count columns from header
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            header = f.readline()
        col_count = len(header.split(","))
        size_mb = os.path.getsize(fpath) / (1024 * 1024)

        if col_count == EXPECTED_COLUMNS:
            print(f"  OK:      {fname} ({col_count} cols, {size_mb:.0f} MB)")
        else:
            print(f"  BAD:     {fname} ({col_count} cols, expected {EXPECTED_COLUMNS})")
            all_ok = False

    # Check for unexpected files
    actual_files = [f for f in os.listdir(RAW_DIR) if f.endswith(".csv")]
    unexpected = [f for f in actual_files if f not in EXPECTED_FILES]
    if unexpected:
        print(f"\n  WARNING: Unexpected files in data/raw/: {unexpected}")

    # Summary
    print()
    if all_ok:
        print("ALL CHECKS PASSED — data/raw/ is ready for the ML pipeline.")
    else:
        print("ISSUES FOUND — fix them before running the ML pipeline.")
        print("If a file has wrong column count, run: python setup/setup_full/fix_tuesday_csv.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
