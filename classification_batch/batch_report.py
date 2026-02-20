"""
Batch Report Generator
Generates batch_results.txt and batch_summary.txt from classification results.
Reuses the same report format as classification/report_generator.py batch mode.
"""

import os
import sys
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_REPORTS_DIR,
    CLASSIFICATION_BENIGN_CLASS, CLASSIFICATION_SUSPICIOUS_THRESHOLD,
    CLASSIFICATION_REPORT_TABLE_WIDTH, CLASSIFICATION_REPORT_TABLE_COLUMNS,
    CLASSIFICATION_TIMESTAMP_FORMAT,
    COLOR_CYAN, COLOR_GREEN, COLOR_RESET
)


class BatchReportGenerator:
    """
    Generates structured report files for batch classification results.

    Output files:
        batch_results.txt  - Detailed table of all classified flows
        batch_summary.txt  - Summary statistics and accuracy (if labeled)
    """

    def __init__(self, mode="batch", model_name="default", batch_filename="unknown",
                 has_label=False, report_dir=None):
        """
        Args:
            mode:           Always 'batch' for this module.
            model_name:     'default' or 'all'.
            batch_filename: Name of the input CSV file.
            has_label:      True if batch has actual labels.
            report_dir:     Root reports directory (default: reports/).
        """
        self.mode = mode
        self.model_name = model_name
        self.batch_filename = batch_filename
        self.has_label = has_label

        if report_dir is None:
            report_dir = CLASSIFICATION_REPORTS_DIR

        # Create session folder
        self.session_start = datetime.now()
        session_ts = self.session_start.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_folder_name = f"batch_{model_name}_{session_ts}"
        self.session_folder = os.path.join(report_dir, self.session_folder_name)
        os.makedirs(self.session_folder, exist_ok=True)

        self.report_path = self.session_folder
        self.report_count = 0

        # Stats
        self.stats = {
            "total": 0,
            "threats": 0,
            "suspicious": 0,
            "clean": 0,
            "by_class": {},
        }
        if self.has_label:
            self.stats["correct_predictions"] = 0
            self.stats["accuracy"] = 0.0
            self.stats["by_class_accuracy"] = {}

    def _classify_threat_level(self, result):
        """Determine threat level: 'threat', 'suspicious', or 'clean'."""
        top3 = result["top3"]
        predicted = top3[0][0]
        if predicted != CLASSIFICATION_BENIGN_CLASS:
            return "threat"
        if (len(top3) >= 2
                and top3[1][0] != CLASSIFICATION_BENIGN_CLASS
                and top3[1][1] >= CLASSIFICATION_SUSPICIOUS_THRESHOLD):
            return "suspicious"
        return "clean"

    def _update_stats(self, result):
        """Update session-level stats for a single result."""
        predicted = result["predicted_class"]
        level = self._classify_threat_level(result)

        self.stats["total"] += 1
        if level == "threat":
            self.stats["threats"] += 1
        elif level == "suspicious":
            self.stats["suspicious"] += 1
        else:
            self.stats["clean"] += 1

        self.stats["by_class"][predicted] = self.stats["by_class"].get(predicted, 0) + 1

        # Accuracy tracking
        if self.has_label:
            actual = result.get("actual_label")
            if actual is not None:
                if predicted == actual:
                    self.stats["correct_predictions"] += 1
                if predicted not in self.stats["by_class_accuracy"]:
                    self.stats["by_class_accuracy"][predicted] = {"correct": 0, "total": 0}
                self.stats["by_class_accuracy"][predicted]["total"] += 1
                if predicted == actual:
                    self.stats["by_class_accuracy"][predicted]["correct"] += 1
                if self.stats["total"] > 0:
                    self.stats["accuracy"] = (
                        self.stats["correct_predictions"] / self.stats["total"]
                    ) * 100

    def _build_table_header(self):
        """Build the table header row."""
        cols = list(CLASSIFICATION_REPORT_TABLE_COLUMNS)
        if self.has_label:
            cols.append(("Actual Label", 14))
        header = " | ".join(name.ljust(width) for name, width in cols)
        separator = "-+-".join("-" * width for _, width in cols)
        return header, separator

    def _format_row(self, result):
        """Format a classification result as a table row."""
        ids = result["identifiers"]
        top3 = list(result["top3"])
        ts = result["timestamp"]

        while len(top3) < 3:
            top3.append(("-", 0.0))

        cols = [
            (ts, 19),
            (str(ids.get("Src IP", "?")), 18),
            (str(ids.get("Src Port", "?")), 8),
            (str(ids.get("Dst IP", "?")), 18),
            (str(ids.get("Dst Port", "?")), 8),
            (str(ids.get("Protocol", "?")), 8),
            (top3[0][0], 14),
            (f"{top3[0][1]*100:.1f}%", 8),
            (top3[1][0], 14),
            (f"{top3[1][1]*100:.1f}%", 8),
            (top3[2][0], 14),
            (f"{top3[2][1]*100:.1f}%", 8),
        ]
        if self.has_label:
            cols.append((str(result.get("actual_label", "?")), 14))

        return " | ".join(str(val).ljust(width) for val, width in cols)

    def generate(self, results, classify_stats):
        """
        Generate batch_results.txt and batch_summary.txt.

        Args:
            results:         List of result dicts from BatchClassifier.
            classify_stats:  Dict with total_flows, elapsed_seconds, flows_per_second.
        """
        print(f"{COLOR_CYAN}[BATCH-REPORT] Generating reports in: {self.session_folder}{COLOR_RESET}")

        # Update stats for every result
        for r in results:
            self._update_stats(r)
            self.report_count += 1

        session_end = datetime.now()
        model_display = (
            "All (with Infilteration)" if self.model_name == "all"
            else "Default"
        )

        # ---- batch_results.txt ----
        results_path = os.path.join(self.session_folder, "batch_results.txt")
        with open(results_path, "w", encoding="utf-8") as f:
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write("  NIDS CLASSIFICATION - BATCH RESULTS\n")
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write(f"  Session Mode:      BATCH\n")
            f.write(f"  Model:             {model_display}\n")
            f.write(f"  Batch File:        {self.batch_filename}\n")
            f.write(f"  Session Started:   {self.session_start.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            f.write(f"  Session Ended:     {session_end.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            elapsed = (session_end - self.session_start).total_seconds()
            f.write(f"  Processing Time:   {elapsed:.1f}s\n")
            f.write(f"  Classification:    {classify_stats['elapsed_seconds']:.2f}s "
                    f"({classify_stats['flows_per_second']:,.0f} flows/s)\n")
            f.write(f"  Total Flows:       {self.stats['total']}\n")
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n\n")

            header, separator = self._build_table_header()
            f.write(header + "\n")
            f.write(separator + "\n")

            for r in results:
                f.write(self._format_row(r) + "\n")

            f.write("\n" + "-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write(f"  Total Flows:    {self.stats['total']}")
            f.write(f"  |  Threats: {self.stats['threats']}")
            f.write(f"  |  Suspicious: {self.stats['suspicious']}")
            f.write(f"  |  Clean: {self.stats['clean']}\n")
            if self.stats["by_class"]:
                breakdown = ", ".join(
                    f"{cls}: {cnt}"
                    for cls, cnt in sorted(self.stats["by_class"].items(), key=lambda x: -x[1])
                )
                f.write(f"  Breakdown: {breakdown}\n")
            f.write("-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")

        # ---- batch_summary.txt ----
        summary_path = os.path.join(self.session_folder, "batch_summary.txt")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  NIDS CLASSIFICATION - BATCH SUMMARY\n")
            f.write("=" * 100 + "\n\n")
            f.write(f"  Session Mode:      BATCH\n")
            f.write(f"  Model:             {model_display}\n")
            f.write(f"  Batch File:        {self.batch_filename}\n")
            f.write(f"  Session Started:   {self.session_start.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            f.write(f"  Session Ended:     {session_end.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            elapsed = (session_end - self.session_start).total_seconds()
            f.write(f"  Processing Time:   {elapsed:.1f}s\n")
            f.write(f"  Classification:    {classify_stats['elapsed_seconds']:.2f}s "
                    f"({classify_stats['flows_per_second']:,.0f} flows/s)\n")
            f.write(f"  Report Folder:     {self.session_folder_name}\n")
            f.write(f"  Report Files:      batch_results.txt, batch_summary.txt\n")
            f.write("\n" + "=" * 100 + "\n\n")

            f.write("  CLASSIFICATION STATISTICS\n")
            f.write("  " + "-" * 96 + "\n\n")
            f.write(f"  Total Flows Classified: {self.stats['total']}\n")

            if self.has_label and "accuracy" in self.stats:
                f.write(f"  Accuracy:               {self.stats['accuracy']:.2f}% "
                        f"({self.stats['correct_predictions']}/{self.stats['total']})\n\n")
            else:
                for key, label in [("threats", "Threats Detected"),
                                   ("suspicious", "Suspicious Flows"),
                                   ("clean", "Clean Flows")]:
                    val = self.stats[key]
                    pct = (val / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
                    f.write(f"  {label:25s} {val} ({pct:.1f}%)\n")
                f.write("\n")

            if self.stats["by_class"]:
                if self.has_label and "by_class_accuracy" in self.stats:
                    f.write("  Per-Class Precision (of predicted, how many correct):\n")
                    for cls in sorted(self.stats["by_class"].keys()):
                        count = self.stats["by_class"].get(cls, 0)
                        if cls in self.stats["by_class_accuracy"]:
                            acc = self.stats["by_class_accuracy"][cls]
                            pct = (acc["correct"] / acc["total"] * 100) if acc["total"] > 0 else 0
                            f.write(f"    {cls:20s}: {pct:6.2f}% "
                                    f"({acc['correct']}/{acc['total']})  |  Predicted: {count:6d}\n")
                        else:
                            f.write(f"    {cls:20s}: N/A  |  Predicted: {count:6d}\n")
                else:
                    f.write("  Classification Breakdown:\n")
                    for cls, count in sorted(self.stats["by_class"].items(), key=lambda x: -x[1]):
                        pct = (count / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
                        f.write(f"    {cls:20s}: {count:6d} ({pct:5.1f}%)\n")

            f.write("\n" + "=" * 100 + "\n")

        print(f"{COLOR_GREEN}[BATCH-REPORT] Reports written: "
              f"batch_results.txt ({self.report_count} entries), "
              f"batch_summary.txt{COLOR_RESET}")
