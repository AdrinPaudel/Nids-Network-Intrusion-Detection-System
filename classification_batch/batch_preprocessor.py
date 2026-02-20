"""
Batch Preprocessor
Vectorized preprocessing that matches the training pipeline exactly.

Steps (same as classification/preprocessor.py but vectorized):
    1. Convert to numeric, handle inf/nan
    2. One-hot encode Protocol → Protocol_0, Protocol_6, Protocol_17
    3. Build full 80-feature DataFrame in scaler's expected column order
    4. Scale ALL 80 features using the saved scaler
    5. Select only the features the model expects
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_DROP_COLUMNS,
    COLOR_CYAN, COLOR_GREEN, COLOR_YELLOW, COLOR_RESET
)


class BatchPreprocessor:
    """
    Vectorized preprocessor for batch classification.
    Loads the same scaler/feature artifacts as classification/preprocessor.py
    and applies them to an entire DataFrame at once.
    """

    def __init__(self, use_all_classes=False, model_dir=None):
        """
        Args:
            use_all_classes: If True, use trained_model_all/ (all variant).
            model_dir:       Override model directory path.
        """
        if model_dir is None:
            if use_all_classes:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model_all")
            else:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model")
        self.model_dir = model_dir

        # Load artifacts
        self.scaler = None
        self.scaler_feature_names = None   # 80 features the scaler expects
        self.selected_features = None      # ~40 features the model expects
        self._load_artifacts()

    def _load_artifacts(self):
        """Load scaler, selected features, and label encoder from trained model."""
        print(f"{COLOR_CYAN}[BATCH-PREPROC] Loading artifacts from: {self.model_dir}{COLOR_RESET}")

        scaler_path = os.path.join(self.model_dir, "scaler.joblib")
        features_path = os.path.join(self.model_dir, "selected_features.joblib")

        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"Selected features not found: {features_path}")

        self.scaler = joblib.load(scaler_path)
        self.selected_features = joblib.load(features_path)

        if hasattr(self.scaler, 'feature_names_in_'):
            self.scaler_feature_names = list(self.scaler.feature_names_in_)
        else:
            raise ValueError("Scaler missing feature_names_in_. Cannot determine expected features.")

        print(f"{COLOR_GREEN}[BATCH-PREPROC] Scaler: {len(self.scaler_feature_names)} features, "
              f"Model expects: {len(self.selected_features)} selected features{COLOR_RESET}")

    def preprocess(self, features_df):
        """
        Vectorized preprocessing of an entire DataFrame.

        Matches the exact same pipeline as classification/preprocessor.py:
            1. Drop any remaining identifier/label columns
            2. Convert to numeric, replace inf/nan with 0
            3. One-hot encode Protocol into Protocol_0, Protocol_6, Protocol_17
            4. Build full 80-feature DataFrame in scaler's expected column order
            5. Scale ALL 80 features
            6. Select model's features

        Args:
            features_df: DataFrame of raw feature columns (no identifiers, no Label).

        Returns:
            DataFrame with model-ready features (scaled, selected).
        """
        start_time = time.time()
        n_rows = len(features_df)

        print(f"{COLOR_CYAN}[BATCH-PREPROC] Preprocessing {n_rows:,} rows...{COLOR_RESET}")

        # Work on a copy
        df = features_df.copy()

        # 1. Drop any lingering identifier/label columns
        drop_cols = [c for c in CLASSIFICATION_DROP_COLUMNS if c in df.columns]
        if drop_cols:
            df = df.drop(columns=drop_cols)

        # 2. Convert to numeric, handle inf/nan
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # 3. One-hot encode Protocol (matching training: drop_first=False)
        if "Protocol" in df.columns:
            protocol = df["Protocol"].astype(int)
            df.drop(columns=["Protocol"], inplace=True)
        else:
            protocol = pd.Series(0, index=df.index)

        df["Protocol_0"] = (protocol == 0).astype(int)
        df["Protocol_6"] = (protocol == 6).astype(int)
        df["Protocol_17"] = (protocol == 17).astype(int)

        # 4. Build full 80-feature DataFrame in scaler's expected column order
        full_df = pd.DataFrame(0.0, index=df.index, columns=self.scaler_feature_names)
        for col in self.scaler_feature_names:
            if col in df.columns:
                full_df[col] = df[col].values

        # 5. Scale ALL 80 features
        scaled_values = self.scaler.transform(full_df)
        scaled_df = pd.DataFrame(scaled_values, index=df.index, columns=self.scaler_feature_names)

        # 6. Select model's features
        X_ready = scaled_df[self.selected_features]

        elapsed = time.time() - start_time
        print(f"{COLOR_GREEN}[BATCH-PREPROC] Done. {n_rows:,} rows → "
              f"{X_ready.shape[1]} features in {elapsed:.2f}s "
              f"({n_rows / elapsed:,.0f} rows/s){COLOR_RESET}")

        return X_ready
