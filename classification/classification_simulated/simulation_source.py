"""
Simulation Source
=================

Reads a **pre-shuffled** CSV from  temp/simul/  and feeds rows
one-by-one into the classification pipeline's flow_queue, simulating
real-time network traffic at a configurable rate (default: 5 flows / s).

The source file must already exist — run the shuffler first::

    python -m classification.classification_simulated.shuffler

Workflow:
    1. Verify the shuffled CSV exists in  temp/simul/.
    2. Read the header line (instant) and note the file size.
    3. Stream rows sequentially into flow_queue at the configured rate.
    4. When the session duration expires (stop_event set), feeding stops
       immediately — no temp files to clean up.

The dict format pushed to flow_queue is identical to what
FlowMeterSource produces: training column names as keys, plus an
``__identifiers__`` sub-dict and an optional ``actual_label`` key.

Design note — the source CSV files are 3.6-3.7 GB (~8 M rows).
Loading them entirely into memory is not feasible.  This implementation
streams sequentially using line-by-line binary reads.  Because the
files are pre-shuffled, sequential reading already produces a good mix
of attack types from the very first row.
"""

import os
import sys
import csv
import time
import threading

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS,
    CLASSIFICATION_SIMUL_FLOWS_PER_SECOND,
    COLOR_CYAN, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_RESET,
    COLOR_DARK_GRAY,
)


# ============================================================
# Simulation Source
# ============================================================

class SimulationSource:
    """
    Streams a **pre-shuffled** simulation CSV and drip-feeds rows into
    the classification pipeline's ``flow_queue`` at a steady rate.

    Each row is converted to the same dict format that
    ``FlowMeterSource.QueueWriter.write()`` produces, so the
    downstream Preprocessor, Classifier, ThreatHandler, and
    ReportGenerator work unchanged.

    The source **never** loads the full file into memory.  It reads
    the header line, then streams rows sequentially.  Because the CSV
    has been pre-shuffled by ``shuffler.py``, sequential reading already
    produces a good mix of attack types.

    If the shuffled file does not exist the source refuses to start and
    prints instructions to run the shuffler first.

    Args:
        flow_queue:     queue.Queue shared with the Preprocessor thread.
        source_csv:     path to the shuffled CSV inside  temp/simul/.
        has_label:      True if the CSV has a ``Label`` column.
        stop_event:     threading.Event — set when classification should stop.
        flows_per_sec:  how many rows to push per second (default from config).
    """

    def __init__(self, flow_queue, source_csv, has_label, stop_event,
                 flows_per_sec=None):
        self.flow_queue = flow_queue
        self.source_csv = source_csv
        self.has_label = has_label
        self.stop_event = stop_event
        self.flows_per_sec = (
            flows_per_sec if flows_per_sec is not None
            else CLASSIFICATION_SIMUL_FLOWS_PER_SECOND
        )

        self.flow_count = 0
        self.total_rows = 0          # estimated from file size
        self._thread = None
        self._header: list[str] = []  # column names
        self._file_size = 0           # bytes
        self._data_start_offset = 0   # byte offset where data rows begin
        self._identifier_columns = CLASSIFICATION_IDENTIFIER_COLUMNS

    # ── public API (matches FlowMeterSource interface) ─────────

    def start(self) -> bool:
        """Verify the shuffled CSV exists, prepare the source, and begin feeding."""
        # ── Check that the pre-shuffled file exists ──────────────
        if not os.path.isfile(self.source_csv):
            basename = os.path.basename(self.source_csv)
            print(f"\n{COLOR_RED}{'=' * 70}{COLOR_RESET}")
            print(f"{COLOR_RED}  ERROR: Shuffled simulation file not found:{COLOR_RESET}")
            print(f"{COLOR_RED}    {self.source_csv}{COLOR_RESET}")
            print(f"{COLOR_RED}")
            print(f"  Run the shuffler first to create the pre-shuffled files:{COLOR_RESET}")
            print(f"{COLOR_YELLOW}    python -m classification.classification_simulated.shuffler{COLOR_RESET}")
            print(f"{COLOR_RED}{'=' * 70}{COLOR_RESET}\n")
            return False

        try:
            self._prepare_source()
        except Exception as exc:
            print(f"{COLOR_RED}[SIMUL] Failed to prepare simulation data: {exc}{COLOR_RESET}")
            import traceback
            traceback.print_exc()
            return False

        self._thread = threading.Thread(
            target=self._feed_loop,
            name="simul-source",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self):
        """Signal the feed loop to stop."""
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── lightweight preparation (instant) ──────────────────────

    def _prepare_source(self):
        """
        Read the CSV header, measure file size, and estimate total rows.

        This is extremely fast regardless of file size — it only reads
        the first line and samples a few more for the row-length estimate.
        """
        if not os.path.isfile(self.source_csv):
            raise FileNotFoundError(f"Shuffled CSV not found: {self.source_csv}")

        self._file_size = os.path.getsize(self.source_csv)
        file_size_mb = self._file_size / (1024 * 1024)

        # --- Read header (binary mode for reliable offset tracking) ---
        with open(self.source_csv, "rb") as f:
            header_line = f.readline()
            self._data_start_offset = f.tell()    # byte offset where rows begin

            # Sample a few rows to estimate average row length
            sample_bytes = 0
            sample_count = 0
            for _ in range(200):
                line = f.readline()
                if not line:
                    break
                sample_bytes += len(line)
                sample_count += 1

        # Parse header (decode from bytes)
        self._header = [h.strip() for h in header_line.decode("utf-8").strip().split(",")]

        # Estimate total rows
        if sample_count > 0:
            avg_row_len = sample_bytes / sample_count
            data_bytes = self._file_size - self._data_start_offset
            self.total_rows = int(data_bytes / avg_row_len)
        else:
            self.total_rows = 0

        print(f"{COLOR_CYAN}[SIMUL] Source: {os.path.basename(self.source_csv)}"
              f"  ({file_size_mb:,.1f} MB, ~{self.total_rows:,} rows est., "
              f"{len(self._header)} cols){COLOR_RESET}")
        print(f"{COLOR_CYAN}[SIMUL] Streaming sequentially from pre-shuffled file{COLOR_RESET}")

    # ── feed loop (runs in its own thread) ─────────────────────

    def _feed_loop(self):
        """
        Stream rows sequentially from the pre-shuffled CSV and push each
        row into ``flow_queue`` at the configured rate.

        Reads lines as bytes starting from the first data row. Because
        the file is pre-shuffled, sequential reading already produces a
        representative mix of attack / benign traffic.
        """
        interval = 1.0 / self.flows_per_sec if self.flows_per_sec > 0 else 0
        label_col = "Label" if (self.has_label and "Label" in self._header) else None

        print(f"{COLOR_GREEN}[SIMUL] Feeding at {self.flows_per_sec} flows/sec "
              f"(interval {interval*1000:.1f} ms). "
              f"Labels: {'yes' if label_col else 'no'}{COLOR_RESET}\n")

        try:
            with open(self.source_csv, "rb") as bf:
                # Skip header line — start at data
                bf.seek(self._data_start_offset)

                while not self.stop_event.is_set():
                    line_bytes = bf.readline()

                    # Handle EOF — all rows consumed
                    if not line_bytes:
                        print(f"{COLOR_CYAN}[SIMUL] Reached end of shuffled file.{COLOR_RESET}")
                        break

                    # Decode and parse the line
                    try:
                        line_str = line_bytes.decode("utf-8").strip()
                        if not line_str:
                            continue
                        values = next(csv.reader([line_str]))
                        if len(values) != len(self._header):
                            continue  # skip malformed rows
                        row_dict = dict(zip(self._header, values))
                    except Exception:
                        continue  # skip unparseable lines

                    self._push_row(row_dict, label_col)
                    self.flow_count += 1

                    # Log first few flows
                    if self.flow_count <= 5:
                        dst = row_dict.get("Dst Port", "?")
                        proto = row_dict.get("Protocol", "?")
                        lbl = row_dict.get("Label", "") if label_col else ""
                        tag = f"  [{lbl}]" if lbl else ""
                        print(f"{COLOR_CYAN}[SIMUL] Flow #{self.flow_count}: "
                              f"Dst Port={dst}, Protocol={proto}{tag}{COLOR_RESET}")
                    elif self.flow_count == 6:
                        print(f"{COLOR_DARK_GRAY}[SIMUL] (further flow logs suppressed){COLOR_RESET}")

                    # Throttle to configured rate
                    if interval > 0:
                        time.sleep(interval)

        except Exception as exc:
            print(f"{COLOR_RED}[SIMUL] Feed loop error: {exc}{COLOR_RESET}")
            import traceback
            traceback.print_exc()

        rows_fed = self.flow_count
        total = self.total_rows
        status = "stopped (duration reached)" if self.stop_event.is_set() else "finished (all rows fed)"
        print(f"\n{COLOR_CYAN}[SIMUL] Source {status}. "
              f"Fed {rows_fed:,} / ~{total:,} rows.{COLOR_RESET}")

    def _push_row(self, row_dict, label_col):
        """
        Convert a CSV row dict into the format expected by the
        Preprocessor (identical to FlowMeterSource.QueueWriter output)
        and push it onto the flow_queue.

        Expected output format::

            {
                "Dst Port": ...,
                "Protocol": ...,
                "Timestamp": ...,
                "Flow Duration": ...,
                ... (all 78 feature columns) ...
                "__identifiers__": { "Dst Port": ..., "Protocol": ..., "Timestamp": ... },
                "actual_label": "DDoS"   # only if labeled
            }
        """
        # Strip whitespace from keys (CSV sometimes has trailing spaces)
        clean = {k.strip(): v for k, v in row_dict.items() if k is not None}

        # Extract the actual label before it gets dropped
        actual_label = None
        if label_col and label_col in clean:
            actual_label = clean.pop(label_col).strip()

        # Build identifiers sub-dict (for threat display / reporting)
        identifiers = {}
        for col in self._identifier_columns:
            if col in clean:
                identifiers[col] = clean[col]

        # Attach metadata keys the pipeline expects
        clean["__identifiers__"] = identifiers
        if actual_label is not None:
            clean["actual_label"] = actual_label

        self.flow_queue.put(clean)
