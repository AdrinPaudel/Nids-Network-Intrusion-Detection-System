"""
Batch Data Source
Reads CSV files from data/batch/ folder and pushes flows to the queue.
Used for batch processing instead of live CICFlowMeter capture.
"""

import os
import sys
import threading
import queue
import csv
import pandas as pd
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS, CLASSIFICATION_QUEUE_TIMEOUT,
    CLASSIFICATION_BATCH_PROGRESS_INTERVAL, CLASSIFICATION_LABEL_COLUMN,
    COLOR_CYAN, COLOR_RED, COLOR_GREEN, COLOR_RESET
)

# Keep backward compatibility
IDENTIFIER_COLUMNS = CLASSIFICATION_IDENTIFIER_COLUMNS


class BatchSource:
    """
    Batch data source that reads flows from a CSV file
    and pushes them to the flow_queue.
    """

    def __init__(self, flow_queue, csv_file_path, stop_event, has_label=False):
        """
        Args:
            flow_queue: queue.Queue to push flow dicts
            csv_file_path: path to CSV file to read
            stop_event: threading.Event to signal stop
            has_label: if True, file has Label column; if False, no labels
        """
        self.flow_queue = flow_queue
        self.csv_file_path = csv_file_path
        self.stop_event = stop_event
        self.has_label = has_label
        self.flow_count = 0

        # Validation
        if not os.path.exists(csv_file_path):
            raise FileNotFoundError(f"CSV file not found: {csv_file_path}")

        self.thread = None
        self.running = False

    def start(self):
        """Start the batch reading thread."""
        print(f"{COLOR_CYAN}[BATCH] Reading from: {self.csv_file_path}{COLOR_RESET}")

        self.running = True
        self.thread = threading.Thread(
            target=self._read_csv,
            name="batch-source",
            daemon=True
        )
        self.thread.start()
        return True

    def _read_csv(self):
        """Read CSV file and push flows to queue."""
        try:
            # Read CSV file
            df = pd.read_csv(self.csv_file_path)
            print(f"{COLOR_GREEN}[BATCH] Loaded {len(df)} rows from CSV{COLOR_RESET}")

            # Get column names
            columns = df.columns.tolist()

            # Check if label column exists
            has_label_column = CLASSIFICATION_LABEL_COLUMN in columns if self.has_label else False

            # Process each row
            for idx, row in df.iterrows():
                if self.stop_event.is_set():
                    print(f"{COLOR_CYAN}[BATCH] Stop signal received. Stopping at row {idx + 1}.{COLOR_RESET}")
                    break

                # Create flow dict with identifiers and raw features
                flow_dict = {}
                identifiers = {}

                # Extract identifier columns into __identifiers__ dict (matching CICFlowMeterSource format)  
                for col in IDENTIFIER_COLUMNS:
                    if col in columns:
                        identifiers[col] = row[col]
                    else:
                        identifiers[col] = None

                flow_dict["__identifiers__"] = identifiers

                # Add all other columns as features (raw data), EXCLUDING identifier columns to avoid duplicates
                for col in columns:
                    if col not in IDENTIFIER_COLUMNS:  # Don't add identifier columns twice
                        flow_dict[col] = row[col]

                # Store actual label if this is a labeled batch
                if self.has_label and has_label_column:
                    flow_dict["actual_label"] = row[CLASSIFICATION_LABEL_COLUMN]
                else:
                    flow_dict["actual_label"] = None

                # Push to queue
                try:
                    self.flow_queue.put(flow_dict, timeout=CLASSIFICATION_QUEUE_TIMEOUT)
                    self.flow_count += 1

                    # Print progress periodically
                    if self.flow_count % CLASSIFICATION_BATCH_PROGRESS_INTERVAL == 0:
                        print(f"{COLOR_CYAN}[BATCH] Processed {self.flow_count} flows...{COLOR_RESET}")

                except queue.Full:
                    print(f"{COLOR_RED}[BATCH] Queue full at row {idx + 1}. Waiting...{COLOR_RESET}")
                    # Retry with longer timeout
                    self.flow_queue.put(flow_dict, timeout=10)
                    self.flow_count += 1

            print(f"{COLOR_GREEN}[BATCH] Finished reading CSV. Total flows: {self.flow_count}{COLOR_RESET}")

        except Exception as e:
            print(f"{COLOR_RED}[BATCH] Error reading CSV: {e}{COLOR_RESET}")
            import traceback
            traceback.print_exc()
        finally:
            # Inject sentinel so downstream pipeline (preprocessor → classifier → report)
            # knows there are no more flows and can shut down sequentially
            self.flow_queue.put(None)
            print(f"{COLOR_CYAN}[BATCH] Sentinel injected into flow_queue.{COLOR_RESET}")
            self.running = False

    def stop(self):
        """Stop the batch source."""
        print(f"{COLOR_CYAN}[BATCH] Stopping...{COLOR_RESET}")
        self.stop_event.set()

        # Wait for thread
        if self.thread:
            self.thread.join(timeout=30)

        print(f"{COLOR_GREEN}[BATCH] Stopped. Total flows read: {self.flow_count}{COLOR_RESET}")

    def wait(self):
        """Wait for the batch source to finish reading."""
        if self.thread:
            self.thread.join()

