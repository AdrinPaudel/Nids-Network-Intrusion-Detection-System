"""
Batch Data Source
Loads a CSV file and separates identifiers, features, and labels.
"""

import os
import sys
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS, CLASSIFICATION_LABEL_COLUMN,
    COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_RESET
)


class BatchSource:
    """
    Loads a batch CSV file and separates it into:
        - identifiers_df: Flow ID, Src IP, Dst IP, etc.
        - features_df:    All feature columns (raw, before preprocessing)
        - labels:         Actual labels (Series or None if unlabeled)
    """

    def __init__(self, csv_path, has_label=False):
        """
        Args:
            csv_path:  Path to the batch CSV file.
            has_label: True if the CSV contains a Label column.
        """
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Batch CSV not found: {csv_path}")

        self.csv_path = csv_path
        self.has_label = has_label
        self.total_rows = 0

    def load(self):
        """
        Read the CSV and split into identifiers, features, and labels.

        Returns:
            tuple: (features_df, identifiers_df, labels)
                - features_df:    DataFrame of raw feature columns (no identifiers, no Label)
                - identifiers_df: DataFrame of identifier columns (or None)
                - labels:         Series of actual labels (or None)
        """
        print(f"{COLOR_CYAN}[BATCH-SOURCE] Loading: {self.csv_path}{COLOR_RESET}")

        df = pd.read_csv(self.csv_path)
        self.total_rows = len(df)
        columns = df.columns.tolist()

        print(f"{COLOR_GREEN}[BATCH-SOURCE] Loaded {self.total_rows:,} rows, "
              f"{len(columns)} columns{COLOR_RESET}")

        # Extract identifier columns
        id_cols_present = [c for c in CLASSIFICATION_IDENTIFIER_COLUMNS if c in columns]
        if id_cols_present:
            identifiers_df = df[id_cols_present].copy()
        else:
            identifiers_df = None

        # Extract labels
        labels = None
        if self.has_label and CLASSIFICATION_LABEL_COLUMN in columns:
            labels = df[CLASSIFICATION_LABEL_COLUMN].copy()
            print(f"{COLOR_CYAN}[BATCH-SOURCE] Label column found. "
                  f"Unique labels: {labels.nunique()}{COLOR_RESET}")

        # Build feature DataFrame (everything except identifiers and Label)
        drop_cols = set(CLASSIFICATION_IDENTIFIER_COLUMNS) | {CLASSIFICATION_LABEL_COLUMN}
        feature_cols = [c for c in columns if c not in drop_cols]
        features_df = df[feature_cols].copy()

        print(f"{COLOR_GREEN}[BATCH-SOURCE] Features: {len(feature_cols)}, "
              f"Identifiers: {len(id_cols_present)}, "
              f"Has labels: {labels is not None}{COLOR_RESET}")

        return features_df, identifiers_df, labels
