"""
Batch Classification Pipeline - Main Orchestrator
==================================================

Fast vectorized batch classification using the same preprocessing
as classification/ but with tester.py-level speed.

Pipeline:
    BatchSource → BatchPreprocessor → BatchClassifier → BatchReportGenerator

Usage:
    python -m classification_batch.batch_classify <csv_file>
    python -m classification_batch.batch_classify <csv_file> --model all
    python -m classification_batch.batch_classify <csv_file> --labeled
"""

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import COLOR_CYAN, COLOR_CYAN_BOLD, COLOR_GREEN, COLOR_RED, COLOR_RESET

from classification_batch.batch_source import BatchSource
from classification_batch.batch_preprocessor import BatchPreprocessor
from classification_batch.batch_classifier import BatchClassifier
from classification_batch.batch_report import BatchReportGenerator


def run_batch_classification(csv_path, use_all_classes=False, has_label=False,
                             report_dir=None):
    """
    Run the full batch classification pipeline.

    Args:
        csv_path:         Path to the batch CSV file.
        use_all_classes:  If True, use 'all' model (trained_model_all/).
        has_label:        If True, CSV has a Label column for accuracy tracking.
        report_dir:       Override reports directory.

    Returns:
        dict with keys:
            'report_path':  Path to the generated report folder
            'stats':        Classification statistics dict
            'report_generator': The BatchReportGenerator instance
            'total_flows':  Number of flows processed
            'elapsed':      Total elapsed time in seconds
    """
    model_label = "all" if use_all_classes else "default"
    model_display = "All (with Infilteration)" if use_all_classes else "Default"
    batch_filename = os.path.basename(csv_path)

    print(f"\n{COLOR_CYAN_BOLD}{'='*80}{COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}  BATCH CLASSIFICATION PIPELINE{COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}{'='*80}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  File:     {batch_filename}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  Model:    {model_display}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  Labeled:  {has_label}{COLOR_RESET}")
    print(f"{COLOR_CYAN_BOLD}{'='*80}{COLOR_RESET}\n")

    pipeline_start = time.time()

    # 1. Load CSV
    source = BatchSource(csv_path, has_label=has_label)
    features_df, identifiers_df, labels = source.load()

    # 2. Preprocess (vectorized)
    preprocessor = BatchPreprocessor(use_all_classes=use_all_classes)
    X_ready = preprocessor.preprocess(features_df)

    # 3. Classify (vectorized)
    classifier = BatchClassifier(use_all_classes=use_all_classes)
    results, classify_stats = classifier.classify(X_ready, identifiers_df, labels)

    # 4. Generate reports
    reporter = BatchReportGenerator(
        model_name=model_label,
        batch_filename=batch_filename,
        has_label=has_label,
        report_dir=report_dir,
    )
    reporter.generate(results, classify_stats)

    pipeline_elapsed = time.time() - pipeline_start

    print(f"\n{COLOR_GREEN}{'='*80}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  BATCH COMPLETE{COLOR_RESET}")
    print(f"{COLOR_GREEN}{'='*80}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Flows:    {source.total_rows:,}{COLOR_RESET}")
    print(f"{COLOR_GREEN}  Time:     {pipeline_elapsed:.2f}s "
          f"({source.total_rows / pipeline_elapsed:,.0f} flows/s total){COLOR_RESET}")
    print(f"{COLOR_GREEN}  Reports:  {reporter.report_path}{COLOR_RESET}")
    if has_label and "accuracy" in reporter.stats:
        print(f"{COLOR_GREEN}  Accuracy: {reporter.stats['accuracy']:.2f}%{COLOR_RESET}")
    print(f"{COLOR_GREEN}{'='*80}{COLOR_RESET}\n")

    return {
        "report_path": reporter.report_path,
        "stats": reporter.stats,
        "report_generator": reporter,
        "total_flows": source.total_rows,
        "elapsed": pipeline_elapsed,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NIDS Batch Classification")
    parser.add_argument("csv_file", help="Path to the batch CSV file")
    parser.add_argument(
        "--model", choices=["default", "all"], default="default",
        help="Model variant: 'default' or 'all' (with Infilteration)"
    )
    parser.add_argument(
        "--labeled", action="store_true",
        help="CSV has a Label column for accuracy tracking"
    )
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"{COLOR_RED}File not found: {args.csv_file}{COLOR_RESET}")
        sys.exit(1)

    run_batch_classification(
        csv_path=args.csv_file,
        use_all_classes=(args.model == "all"),
        has_label=args.labeled,
    )
