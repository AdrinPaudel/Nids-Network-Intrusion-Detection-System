"""
Batch Classifier
Vectorized classification with top-3 predictions and confidence scores.
Uses numpy vectorized ops for speed (matches tester.py performance).
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import COLOR_CYAN, COLOR_GREEN, COLOR_RESET


class BatchClassifier:
    """
    Vectorized classifier that loads the trained RF model
    and classifies an entire DataFrame at once.

    Produces top-3 predictions with confidence for each row,
    matching the output format of classification/classifier.py.
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

        self.model = None
        self.label_encoder = None
        self.class_names = None
        self._load_model()

    def _load_model(self):
        """Load the trained model and label encoder."""
        print(f"{COLOR_CYAN}[BATCH-CLASSIFIER] Loading model from: {self.model_dir}{COLOR_RESET}")

        model_path = os.path.join(self.model_dir, "random_forest_model.joblib")
        encoder_path = os.path.join(self.model_dir, "label_encoder.joblib")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder not found: {encoder_path}")

        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)
        self.class_names = self.label_encoder.classes_

        print(f"{COLOR_GREEN}[BATCH-CLASSIFIER] Model loaded. "
              f"Trees: {self.model.n_estimators}, "
              f"Classes: {list(self.class_names)}{COLOR_RESET}")

    def classify(self, X_ready, identifiers_df=None, labels=None):
        """
        Classify all rows and produce top-3 predictions per flow.

        Args:
            X_ready:         DataFrame of preprocessed features (from BatchPreprocessor).
            identifiers_df:  DataFrame of identifier columns (or None).
            labels:          Series of actual labels (or None).

        Returns:
            list of dicts, each matching classification/classifier.py output:
                {
                    'identifiers': {col: val, ...},
                    'top3': [(class_name, confidence), ...],
                    'predicted_class': str,
                    'confidence': float,
                    'timestamp': str,
                    'actual_label': str or None,
                }
        """
        n_rows = len(X_ready)
        print(f"{COLOR_CYAN}[BATCH-CLASSIFIER] Classifying {n_rows:,} flows...{COLOR_RESET}")

        start_time = time.time()

        # Vectorized prediction
        y_pred_proba = self.model.predict_proba(X_ready)

        # Vectorized top-3 extraction using numpy
        top3_indices = np.argsort(y_pred_proba, axis=1)[:, -3:][:, ::-1]
        top3_probs = np.take_along_axis(y_pred_proba, top3_indices, axis=1)
        top3_names = self.class_names[top3_indices]

        elapsed = time.time() - start_time
        speed = n_rows / elapsed if elapsed > 0 else 0

        print(f"{COLOR_GREEN}[BATCH-CLASSIFIER] Done. {n_rows:,} flows in {elapsed:.2f}s "
              f"({speed:,.0f} flows/s){COLOR_RESET}")

        # Build result list matching classification/classifier.py format
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        results = []

        for i in range(n_rows):
            # Identifiers
            if identifiers_df is not None:
                identifiers = identifiers_df.iloc[i].to_dict()
            else:
                identifiers = {}

            # Top-3
            top3 = [
                (str(top3_names[i, j]), float(top3_probs[i, j]))
                for j in range(min(3, top3_names.shape[1]))
            ]

            result = {
                "identifiers": identifiers,
                "top3": top3,
                "predicted_class": top3[0][0],
                "confidence": top3[0][1],
                "timestamp": timestamp,
            }

            # Actual label
            if labels is not None:
                result["actual_label"] = str(labels.iloc[i])
            else:
                result["actual_label"] = None

            results.append(result)

        return results, {
            "total_flows": n_rows,
            "elapsed_seconds": elapsed,
            "flows_per_second": speed,
        }
