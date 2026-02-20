"""
Report Generator
================
Creates a structured report folder per classification session.

Folder structure:
    reports/
        {mode}_{model}_{timestamp}/
            minute_{HH-MM}.txt          # One file per calendar minute
            ...
            session_summary.txt         # Overall session summary

Minute files contain:
    - Header with session info
    - Table of classified flows with identifiers and top-3 predictions

Minute boundaries follow actual clock time, not relative session time.
"""

import os
import sys
import threading
import queue
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_REPORTS_DIR, CLASSIFICATION_QUEUE_TIMEOUT, CLASSIFICATION_BATCH_QUEUE_TIMEOUT,
    CLASSIFICATION_BENIGN_CLASS, CLASSIFICATION_SUSPICIOUS_THRESHOLD,
    CLASSIFICATION_REPORT_TABLE_WIDTH, CLASSIFICATION_REPORT_TABLE_COLUMNS,
    CLASSIFICATION_REPORT_FLUSH_INTERVAL,
    CLASSIFICATION_TIMESTAMP_FORMAT, CLASSIFICATION_MINUTE_KEY_FORMAT,
    COLOR_GREEN, COLOR_RED, COLOR_RESET
)


class ReportGenerator:
    """
    Writes classification results into per-minute files inside a session folder.
    Produces a session_summary.txt at the end.
    """

    def __init__(self, report_queue, stop_event, mode="live", model_name="default",
                 report_dir=None, duration=None, interface_name=None, has_label=False,
                 batch_completion_event=None):
        """
        Args:
            report_queue: queue.Queue of classification result dicts
            stop_event: threading.Event to signal stop
            mode: 'live', 'batch', 'csv', or 'simul'
            model_name: 'default' or 'all'
            report_dir: root reports directory (default: reports/)
            duration: session duration in seconds
            interface_name: network interface used (or batch filename)
            has_label: if True, batch has actual labels for comparison
            batch_completion_event: threading.Event to signal batch completion
        """
        self.report_queue = report_queue
        self.stop_event = stop_event
        self.mode = mode
        self.model_name = model_name
        self.duration = duration
        self.interface_name = interface_name
        self.has_label = has_label
        self.batch_completion_event = batch_completion_event
        self.report_count = 0

        # Root reports directory
        if report_dir is None:
            report_dir = CLASSIFICATION_REPORTS_DIR

        # Create session folder: {mode}_{model}_{timestamp}
        self.session_start = datetime.now()
        session_ts = self.session_start.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_folder_name = f"{mode}_{model_name}_{session_ts}"
        self.session_folder = os.path.join(report_dir, self.session_folder_name)
        os.makedirs(self.session_folder, exist_ok=True)

        # Report path exposed for the orchestrator to display
        self.report_path = self.session_folder

        # Batch mode processing
        if self.mode == "batch":
            self._batch_results_file = None
            self._batch_results_path = os.path.join(self.session_folder, "batch_results.txt")
            self._batch_log_rows = []  # Collect rows for batch_results.txt
        else:
            # Current minute file tracking (for live mode)
            self._current_minute_key = None  # "HH-MM" string of current minute
            self._current_file = None
            self._current_minute_count = 0
            self._current_minute_start = None
            self._current_minute_stats = {"threats": 0, "suspicious": 0, "clean": 0, "by_class": {}}

            # Per-minute stats for summary
            self._minute_stats = []  # list of dicts, one per minute file

        # Overall session stats
        self.stats = {
            "total": 0,
            "threats": 0,
            "suspicious": 0,
            "clean": 0,
            "by_class": {},
        }
        
        # Accuracy tracking for labeled batches
        if self.mode == "batch" and self.has_label:
            self.stats["correct_predictions"] = 0
            self.stats["accuracy"] = 0.0
            self.stats["by_class_accuracy"] = {}  # {predicted_class: {correct, total}}

    def _get_minute_key(self, ts_str=None):
        """Get the minute key (HH-MM) for the current or given time."""
        if ts_str:
            try:
                dt = datetime.strptime(ts_str, CLASSIFICATION_TIMESTAMP_FORMAT)
                return dt.strftime(CLASSIFICATION_MINUTE_KEY_FORMAT)
            except ValueError:
                pass
        return datetime.now().strftime(CLASSIFICATION_MINUTE_KEY_FORMAT)

    def _build_table_header(self):
        """Build the table header row."""
        cols = list(CLASSIFICATION_REPORT_TABLE_COLUMNS)
        
        # Add "Actual Label" column if this is a labeled batch
        if self.mode == "batch" and self.has_label:
            cols.append(("Actual Label", 14))
        
        header = " | ".join(name.ljust(width) for name, width in cols)
        separator = "-+-".join("-" * width for _, width in cols)
        return header, separator

    def _format_row(self, result):
        """Format a classification result as a table row."""
        ids = result["identifiers"]
        top3 = list(result["top3"])
        ts = result["timestamp"]

        src_ip = str(ids.get("Src IP", "?"))
        src_port = str(ids.get("Src Port", "?"))
        dst_ip = str(ids.get("Dst IP", "?"))
        dst_port = str(ids.get("Dst Port", "?"))
        protocol = str(ids.get("Protocol", "?"))

        # Pad top3 to always have 3 entries
        while len(top3) < 3:
            top3.append(("-", 0.0))

        cols = [
            (ts, 19),
            (src_ip, 18),
            (src_port, 8),
            (dst_ip, 18),
            (dst_port, 8),
            (protocol, 8),
            (top3[0][0], 14),
            (f"{top3[0][1]*100:.1f}%", 8),
            (top3[1][0], 14),
            (f"{top3[1][1]*100:.1f}%", 8),
            (top3[2][0], 14),
            (f"{top3[2][1]*100:.1f}%", 8),
        ]
        
        # Add actual label if this is a labeled batch
        if self.mode == "batch" and self.has_label:
            actual_label = result.get("actual_label", "?")
            cols.append((str(actual_label), 14))
        
        return " | ".join(str(val).ljust(width) for val, width in cols)

    def _open_minute_file(self, minute_key):
        """Close current minute file (if any) and open a new one."""
        self._close_minute_file()

        self._current_minute_key = minute_key
        self._current_minute_count = 0
        self._current_minute_start = datetime.now()
        self._current_minute_stats = {"threats": 0, "suspicious": 0, "clean": 0, "by_class": {}}

        filepath = os.path.join(self.session_folder, f"minute_{minute_key}.txt")
        self._current_file = open(filepath, "w", encoding="utf-8")

        # Write minute file header
        model_display = "All (with Infilteration)" if self.model_name == "all" else "Default"
        self._current_file.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
        self._current_file.write("  NIDS CLASSIFICATION - Minute Report\n")
        self._current_file.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
        self._current_file.write(f"  Session Mode:      {self.mode.upper()}\n")
        self._current_file.write(f"  Model:             {model_display}\n")
        self._current_file.write(f"  Session Started:   {self.session_start.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
        if self.duration:
            self._current_file.write(f"  Session Duration:  {self.duration}s\n")
        if self.interface_name:
            self._current_file.write(f"  Interface:         {self.interface_name}\n")
        self._current_file.write(f"  Minute Window:     {minute_key.replace('-', ':')}:00 - {minute_key.replace('-', ':')}:59\n")
        self._current_file.write(f"  File Generated:    {datetime.now().strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
        self._current_file.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n\n")

        # Write table header
        header, separator = self._build_table_header()
        self._current_file.write(header + "\n")
        self._current_file.write(separator + "\n")
        self._current_file.flush()

    def _close_minute_file(self):
        """Close the current minute file and record its stats."""
        if self._current_file is None:
            return

        # Write minute footer with stats
        self._current_file.write("\n" + "-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
        self._current_file.write(f"  Flows in this minute: {self._current_minute_count}")
        self._current_file.write(f"  |  Threats: {self._current_minute_stats['threats']}")
        self._current_file.write(f"  |  Suspicious: {self._current_minute_stats['suspicious']}")
        self._current_file.write(f"  |  Clean: {self._current_minute_stats['clean']}\n")
        if self._current_minute_stats["by_class"]:
            breakdown = ", ".join(f"{cls}: {cnt}" for cls, cnt in
                                 sorted(self._current_minute_stats["by_class"].items(), key=lambda x: -x[1]))
            self._current_file.write(f"  Breakdown: {breakdown}\n")
        self._current_file.write("-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
        self._current_file.flush()
        self._current_file.close()
        self._current_file = None

        # Record stats for summary
        self._minute_stats.append({
            "minute_key": self._current_minute_key,
            "count": self._current_minute_count,
            "start": self._current_minute_start,
            "end": datetime.now(),
            "threats": self._current_minute_stats["threats"],
            "suspicious": self._current_minute_stats["suspicious"],
            "clean": self._current_minute_stats["clean"],
            "by_class": dict(self._current_minute_stats["by_class"]),
        })

    def _classify_threat_level(self, result):
        """Determine threat level for a result. Returns 'threat', 'suspicious', or 'clean'."""
        top3 = result["top3"]
        predicted = top3[0][0]
        if predicted != CLASSIFICATION_BENIGN_CLASS:
            return "threat"
        elif len(top3) >= 2 and top3[1][0] != CLASSIFICATION_BENIGN_CLASS and top3[1][1] >= CLASSIFICATION_SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "clean"

    def _update_stats(self, result):
        """Update both session-level and minute-level stats (or batch stats)."""
        top3 = result["top3"]
        predicted = top3[0][0]
        level = self._classify_threat_level(result)

        # Session stats
        self.stats["total"] += 1
        if level == "threat":
            self.stats["threats"] += 1
        elif level == "suspicious":
            self.stats["suspicious"] += 1
        else:
            self.stats["clean"] += 1

        if predicted not in self.stats["by_class"]:
            self.stats["by_class"][predicted] = 0
        self.stats["by_class"][predicted] += 1

        # Accuracy tracking for labeled batches
        if self.mode == "batch" and self.has_label:
            actual_label = result.get("actual_label")
            if actual_label is not None:
                if predicted == actual_label:
                    self.stats["correct_predictions"] += 1
                
                # Track per-class precision (of flows predicted as X, how many are actually X)
                if predicted not in self.stats["by_class_accuracy"]:
                    self.stats["by_class_accuracy"][predicted] = {"correct": 0, "total": 0}
                self.stats["by_class_accuracy"][predicted]["total"] += 1
                if predicted == actual_label:
                    self.stats["by_class_accuracy"][predicted]["correct"] += 1
                
                # Calculate overall accuracy
                if self.stats["total"] > 0:
                    self.stats["accuracy"] = (self.stats["correct_predictions"] / self.stats["total"]) * 100

        # Minute stats (only for live mode)
        if self.mode != "batch":
            if level == "threat":
                self._current_minute_stats["threats"] += 1
            elif level == "suspicious":
                self._current_minute_stats["suspicious"] += 1
            else:
                self._current_minute_stats["clean"] += 1

            if predicted not in self._current_minute_stats["by_class"]:
                self._current_minute_stats["by_class"][predicted] = 0
            self._current_minute_stats["by_class"][predicted] += 1

    def _write_result(self, result):
        """Write a single result to the appropriate file.
        
        For live mode: writes to minute files
        For batch mode: collects rows in memory for batch_results.txt
        """
        if self.mode == "batch":
            # Batch mode: collect rows
            row = self._format_row(result)
            self._batch_log_rows.append(row)
            self.report_count += 1
        else:
            # Live mode: write to minute file
            minute_key = self._get_minute_key(result.get("timestamp"))

            # Open new minute file if needed
            if minute_key != self._current_minute_key:
                self._open_minute_file(minute_key)

            # Write table row
            row = self._format_row(result)
            self._current_file.write(row + "\n")
            self._current_minute_count += 1
            self.report_count += 1

            # Flush periodically
            if self.report_count % 10 == 0:
                self._current_file.flush()

        # Update stats (works for both modes)
        self._update_stats(result)

    def _write_batch_reports(self):
        """Write batch mode reports: batch_results.txt and batch_summary.txt.
        
        batch_results.txt: Detailed log of all classified flows
        batch_summary.txt: Summary statistics
        """
        session_end = datetime.now()
        model_display = "All (with Infilteration)" if self.model_name == "all" else "Default"
        
        # Write batch_results.txt with all collected flows
        with open(self._batch_results_path, "w", encoding="utf-8") as f:
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write("  NIDS CLASSIFICATION - BATCH RESULTS\n")
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write(f"  Session Mode:      {self.mode.upper()}\n")
            f.write(f"  Model:             {model_display}\n")
            f.write(f"  Batch File:        {self.interface_name}\n")
            f.write(f"  Session Started:   {self.session_start.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            f.write(f"  Session Ended:     {session_end.strftime(CLASSIFICATION_TIMESTAMP_FORMAT)}\n")
            elapsed = (session_end - self.session_start).total_seconds()
            f.write(f"  Processing Time:   {int(elapsed)}s\n")
            f.write(f"  Total Flows:       {self.stats['total']}\n")
            f.write("=" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n\n")

            # Write table header
            header, separator = self._build_table_header()
            f.write(header + "\n")
            f.write(separator + "\n")

            # Write all collected rows
            for row in self._batch_log_rows:
                f.write(row + "\n")

            # Write footer with summary
            f.write("\n" + "-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")
            f.write(f"  Total Flows:    {self.stats['total']}")
            f.write(f"  |  Threats: {self.stats['threats']}")
            f.write(f"  |  Suspicious: {self.stats['suspicious']}")
            f.write(f"  |  Clean: {self.stats['clean']}\n")
            if self.stats["by_class"]:
                breakdown = ", ".join(f"{cls}: {cnt}" for cls, cnt in
                                     sorted(self.stats["by_class"].items(), key=lambda x: -x[1]))
                f.write(f"  Breakdown: {breakdown}\n")
            f.write("-" * CLASSIFICATION_REPORT_TABLE_WIDTH + "\n")

        # Write batch_summary.txt with statistics
        summary_path = os.path.join(self.session_folder, "batch_summary.txt")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  NIDS CLASSIFICATION - BATCH SUMMARY\n")
            f.write("=" * 100 + "\n\n")
            f.write(f"  Session Mode:      {self.mode.upper()}\n")
            f.write(f"  Model:             {model_display}\n")
            f.write(f"  Batch File:        {self.interface_name}\n")
            f.write(f"  Session Started:   {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Session Ended:     {session_end.strftime('%Y-%m-%d %H:%M:%S')}\n")
            elapsed = (session_end - self.session_start).total_seconds()
            f.write(f"  Processing Time:   {int(elapsed)}s\n")
            f.write(f"  Report Folder:     {self.session_folder_name}\n")
            f.write(f"  Report Files:      batch_results.txt, batch_summary.txt\n")
            f.write("\n" + "=" * 100 + "\n\n")

            # Overall statistics
            f.write("  CLASSIFICATION STATISTICS\n")
            f.write("  " + "-" * 96 + "\n\n")
            f.write(f"  Total Flows Classified: {self.stats['total']}\n")
            
            # Accuracy metrics for labeled batches
            if self.has_label and "accuracy" in self.stats:
                f.write(f"  Accuracy:               {self.stats['accuracy']:.2f}% ({self.stats['correct_predictions']}/{self.stats['total']})\n\n")
            else:
                f.write(f"  Threats Detected:       {self.stats['threats']}")
                if self.stats['total'] > 0:
                    pct = (self.stats['threats'] / self.stats['total'] * 100)
                    f.write(f" ({pct:.1f}%)")
                f.write("\n")
                f.write(f"  Suspicious Flows:       {self.stats['suspicious']}")
                if self.stats['total'] > 0:
                    pct = (self.stats['suspicious'] / self.stats['total'] * 100)
                    f.write(f" ({pct:.1f}%)")
                f.write("\n")
                f.write(f"  Clean Flows:            {self.stats['clean']}")
                if self.stats['total'] > 0:
                    pct = (self.stats['clean'] / self.stats['total'] * 100)
                    f.write(f" ({pct:.1f}%)")
                f.write("\n\n")

            if self.stats["by_class"]:
                if self.has_label and "by_class_accuracy" in self.stats:
                    f.write("  Per-Class Precision (of predicted, how many correct):\n")
                    for cls in sorted(self.stats["by_class"].keys()):
                        count = self.stats["by_class"].get(cls, 0)
                        if cls in self.stats["by_class_accuracy"]:
                            acc_info = self.stats["by_class_accuracy"][cls]
                            accuracy = (acc_info["correct"] / acc_info["total"] * 100) if acc_info["total"] > 0 else 0
                            f.write(f"    {cls:20s}: {accuracy:6.2f}% ({acc_info['correct']}/{acc_info['total']})  |  Predicted: {count:6d}\n")
                        else:
                            f.write(f"    {cls:20s}: N/A  |  Predicted: {count:6d}\n")
                else:
                    f.write("  Classification Breakdown:\n")
                    for cls, count in sorted(self.stats["by_class"].items(), key=lambda x: -x[1]):
                        pct = (count / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
                        f.write(f"    {cls:20s}: {count:6d} ({pct:5.1f}%)\n")

            f.write("\n" + "=" * 100 + "\n")

    def _write_session_summary(self):
        """Write the session_summary.txt file."""
        summary_path = os.path.join(self.session_folder, "session_summary.txt")
        session_end = datetime.now()
        model_display = "All (with Infilteration)" if self.model_name == "all" else "Default"

        with open(summary_path, "w", encoding="utf-8") as f:
            # Session header
            f.write("=" * 100 + "\n")
            f.write("  NIDS CLASSIFICATION - SESSION SUMMARY\n")
            f.write("=" * 100 + "\n\n")
            f.write(f"  Session Mode:      {self.mode.upper()}\n")
            f.write(f"  Model:             {model_display}\n")
            f.write(f"  Session Started:   {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Session Ended:     {session_end.strftime('%Y-%m-%d %H:%M:%S')}\n")
            elapsed = (session_end - self.session_start).total_seconds()
            f.write(f"  Actual Duration:   {int(elapsed)}s\n")
            if self.duration:
                f.write(f"  Planned Duration:  {self.duration}s\n")
            if self.interface_name:
                f.write(f"  Interface:         {self.interface_name}\n")
            f.write(f"  Report Folder:     {self.session_folder_name}\n")
            f.write(f"  Minute Files:      {len(self._minute_stats)}\n")
            f.write("\n" + "=" * 100 + "\n\n")

            # Per-minute summaries
            if self._minute_stats:
                f.write("  MINUTE-BY-MINUTE BREAKDOWN\n")
                f.write("  " + "-" * 96 + "\n\n")

                for i, ms in enumerate(self._minute_stats, 1):
                    start_str = ms["start"].strftime("%H:%M:%S") if ms["start"] else "?"
                    end_str = ms["end"].strftime("%H:%M:%S") if ms["end"] else "?"
                    f.write(f"  Minute {i}: {ms['minute_key'].replace('-', ':')} "
                            f"({start_str} - {end_str})\n")
                    f.write(f"    File:       minute_{ms['minute_key']}.txt\n")
                    f.write(f"    Flows:      {ms['count']}\n")
                    f.write(f"    Threats:    {ms['threats']}\n")
                    f.write(f"    Suspicious: {ms['suspicious']}\n")
                    f.write(f"    Clean:      {ms['clean']}\n")
                    if ms["by_class"]:
                        breakdown = ", ".join(f"{cls}: {cnt}" for cls, cnt in
                                             sorted(ms["by_class"].items(), key=lambda x: -x[1]))
                        f.write(f"    Breakdown:  {breakdown}\n")
                    f.write("\n")

                f.write("  " + "-" * 96 + "\n\n")

            # Overall session summary
            f.write("  FULL SESSION SUMMARY\n")
            f.write("  " + "-" * 96 + "\n\n")
            f.write(f"  Total Flows Classified: {self.stats['total']}\n")
            f.write(f"  Threats Detected:       {self.stats['threats']}\n")
            f.write(f"  Suspicious Flows:       {self.stats['suspicious']}\n")
            f.write(f"  Clean Flows:            {self.stats['clean']}\n\n")

            if self.stats["by_class"]:
                f.write("  Classification Breakdown:\n")
                for cls, count in sorted(self.stats["by_class"].items(), key=lambda x: -x[1]):
                    pct = (count / self.stats["total"] * 100) if self.stats["total"] > 0 else 0
                    f.write(f"    {cls:20s}: {count:6d} ({pct:5.1f}%)\n")

            f.write("\n" + "=" * 100 + "\n")

    def run(self):
        """Main loop: read from report_queue and write results.
        
        For live mode: writes to minute files
        For batch mode: collects results and writes batch_results.txt and batch_summary.txt
        """
        print(f"{COLOR_GREEN}[REPORT] Started. Writing to: {self.session_folder}{COLOR_RESET}")

        try:
            while True:
                try:
                    # Use faster timeout for batch mode
                    timeout = CLASSIFICATION_BATCH_QUEUE_TIMEOUT if self.mode == "batch" else CLASSIFICATION_QUEUE_TIMEOUT
                    result = self.report_queue.get(timeout=timeout)

                    # Sentinel: end of pipeline input
                    if result is None:
                        self.report_queue.task_done()
                        break

                    self._write_result(result)
                    self.report_queue.task_done()
                except queue.Empty:
                    if self.stop_event.is_set():
                        break
                    continue
                except Exception as e:
                    print(f"{COLOR_RED}[REPORT] Error writing result: {e}{COLOR_RESET}")

            # Drain remaining items in queue
            while not self.report_queue.empty():
                try:
                    result = self.report_queue.get_nowait()
                    if result is None:
                        self.report_queue.task_done()
                        continue
                    self._write_result(result)
                    self.report_queue.task_done()
                except queue.Empty:
                    break

            # Close files and write summary based on mode
            if self.mode == "batch":
                # Batch mode: write batch reports
                print(f"{COLOR_GREEN}[REPORT] Writing batch reports...{COLOR_RESET}")
                self._write_batch_reports()
                # Signal that batch processing is complete
                if self.batch_completion_event:
                    print(f"{COLOR_GREEN}[REPORT] Setting batch completion event...{COLOR_RESET}")
                    self.batch_completion_event.set()
                    print(f"{COLOR_GREEN}[REPORT] Batch completion event set!{COLOR_RESET}")
                else:
                    print(f"{COLOR_RED}[REPORT] ERROR: batch_completion_event is None!{COLOR_RESET}")
            else:
                # Live mode: close minute file and write session summary
                self._close_minute_file()
                self._write_session_summary()

        except Exception as e:
            print(f"{COLOR_RED}[REPORT] Fatal error: {e}{COLOR_RESET}")
            import traceback
            traceback.print_exc()
        finally:
            if self.mode != "batch" and hasattr(self, '_current_file') and self._current_file:
                self._current_file.close()

        if self.mode == "batch":
            print(f"{COLOR_GREEN}[REPORT] Stopped. {self.report_count} entries in batch mode. "
                  f"Reports in: {self.session_folder}{COLOR_RESET}")
        else:
            print(f"{COLOR_GREEN}[REPORT] Stopped. {self.report_count} entries across "
                  f"{len(self._minute_stats)} minute file(s) in: {self.session_folder}{COLOR_RESET}")
