"""
Batch Utilities
Helper functions for batch file discovery and model selection.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_BATCH_DEFAULT_DIR, CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR,
    CLASSIFICATION_BATCH_ALL_DIR, CLASSIFICATION_BATCH_ALL_LABELED_DIR,
    COLOR_CYAN, COLOR_CYAN_BOLD, COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_DARK_GRAY, COLOR_RESET
)

# All four batch folders with metadata
BATCH_FOLDERS = [
    {
        "path": CLASSIFICATION_BATCH_DEFAULT_DIR,
        "label": "Default — Unlabeled",
        "model": "default",
        "has_label": False,
        "use_all_classes": False,
    },
    {
        "path": CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR,
        "label": "Default — Labeled",
        "model": "default",
        "has_label": True,
        "use_all_classes": False,
    },
    {
        "path": CLASSIFICATION_BATCH_ALL_DIR,
        "label": "All — Unlabeled",
        "model": "all",
        "has_label": False,
        "use_all_classes": True,
    },
    {
        "path": CLASSIFICATION_BATCH_ALL_LABELED_DIR,
        "label": "All — Labeled",
        "model": "all",
        "has_label": True,
        "use_all_classes": True,
    },
]


def discover_batch_files():
    """
    Scan all four batch folders and collect CSV files.

    Returns:
        list of dicts with keys:
            name, path, size, folder_label, model, has_label, use_all_classes
    """
    all_files = []

    for folder in BATCH_FOLDERS:
        folder_path = folder["path"]
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, exist_ok=True)
            continue

        for fname in sorted(os.listdir(folder_path)):
            if fname.lower().endswith(".csv"):
                fpath = os.path.join(folder_path, fname)
                if os.path.isfile(fpath):
                    all_files.append({
                        "name": fname,
                        "path": fpath,
                        "size": os.path.getsize(fpath),
                        "folder_label": folder["label"],
                        "model": folder["model"],
                        "has_label": folder["has_label"],
                        "use_all_classes": folder["use_all_classes"],
                    })

    return all_files


def _row_count(path):
    """Count data rows in a CSV (subtract header)."""
    try:
        with open(path, "r") as f:
            return sum(1 for _ in f) - 1
    except Exception:
        return -1


def select_batch_file():
    """
    Interactive file selection from all four batch folders.
    Auto-determines model variant (default / all) based on folder.

    Returns:
        tuple: (file_path, has_label, use_all_classes) or (None, None, None)
    """
    print(f"\n{COLOR_CYAN_BOLD}Batch File Selection{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}")

    all_files = discover_batch_files()

    if not all_files:
        print(f"\n{COLOR_RED}No CSV files found in any batch folder.{COLOR_RESET}")
        print(f"{COLOR_YELLOW}Expected folders:{COLOR_RESET}")
        for folder in BATCH_FOLDERS:
            print(f"  {folder['path']}")
        return None, None, None

    # Group into 4 clear sections
    default_unlabeled = [f for f in all_files if not f["use_all_classes"] and not f["has_label"]]
    default_labeled   = [f for f in all_files if not f["use_all_classes"] and f["has_label"]]
    all_unlabeled     = [f for f in all_files if f["use_all_classes"] and not f["has_label"]]
    all_labeled       = [f for f in all_files if f["use_all_classes"] and f["has_label"]]

    print(f"\n{COLOR_CYAN}Available Batch Files:{COLOR_RESET}\n")

    idx = 1
    sections = [
        ("Default — Unlabeled",  "data/default/batch/",         default_unlabeled),
        ("Default — Labeled",    "data/default/batch_labeled/", default_labeled),
        ("All — Unlabeled",      "data/all/batch/",             all_unlabeled),
        ("All — Labeled",        "data/all/batch_labeled/",     all_labeled),
    ]

    for section_label, folder_hint, file_list in sections:
        if not file_list:
            continue
        if idx > 1:
            print()
        print(f"  {COLOR_CYAN_BOLD}{section_label}{COLOR_RESET}  {COLOR_DARK_GRAY}({folder_hint}){COLOR_RESET}")
        for bf in file_list:
            size_mb = bf["size"] / (1024 * 1024)
            rows = _row_count(bf["path"])
            bf["_idx"] = idx
            print(f"    [{idx}] {bf['name']}  ({size_mb:.2f} MB, {rows:,} rows)")
            idx += 1

    print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")

    while True:
        try:
            choice = input(
                f"\n{COLOR_CYAN_BOLD}Enter file number (1-{len(all_files)}){COLOR_RESET}: "
            ).strip()
            choice_idx = int(choice) - 1

            if 0 <= choice_idx < len(all_files):
                selected = all_files[choice_idx]
                model_tag = "all" if selected["use_all_classes"] else "default"
                label_tag = "labeled" if selected["has_label"] else "unlabeled"
                print(f"\n{COLOR_GREEN}Selected: {selected['name']} "
                      f"({model_tag}, {label_tag}){COLOR_RESET}\n")
                return selected["path"], selected["has_label"], selected["use_all_classes"]
            else:
                print(f"{COLOR_RED}Invalid choice. Enter 1-{len(all_files)}.{COLOR_RESET}")
        except ValueError:
            print(f"{COLOR_RED}Invalid input. Enter a number.{COLOR_RESET}")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{COLOR_RED}No file selected. Exiting.{COLOR_RESET}")
            sys.exit(1)


def detect_model_from_path(file_path):
    """
    Auto-detect model variant from a file path.

    Returns:
        tuple: (has_label, use_all_classes)
    """
    norm = os.path.normpath(file_path).lower()

    use_all_classes = os.sep + "all" + os.sep in norm
    has_label = "batch_labeled" in norm

    return has_label, use_all_classes
