"""
Classification Preprocessor
Takes raw flow dicts from the flow_queue, applies the same preprocessing
as the training pipeline (clean, scale, select features), and pushes
preprocessed data to the classifier_queue.
"""

import os
import sys
import threading
import queue
import numpy as np
import pandas as pd
import joblib
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_DROP_COLUMNS, CLASSIFICATION_QUEUE_TIMEOUT, CLASSIFICATION_BATCH_QUEUE_TIMEOUT,
    CLASSIFICATION_BATCH_SIZE, CLASSIFICATION_BATCH_TIMEOUT,
    COLOR_CYAN, COLOR_YELLOW, COLOR_GREEN, COLOR_RESET
)

# Keep backward compatibility
DROP_COLUMNS = CLASSIFICATION_DROP_COLUMNS


class Preprocessor:
    """
    Real-time preprocessor that transforms raw CICFlowMeter flows
    into model-ready feature vectors using the saved training artifacts.

    Pipeline matches training:
        1. Drop identifier columns
        2. Convert to numeric, handle inf/nan
        3. One-hot encode Protocol
        4. Scale ALL 80 features using the saved scaler
        5. Select only the 40 features the model expects
    """

    def __init__(self, flow_queue, classifier_queue, stop_event,
                 model_dir=None, use_all_classes=False, batch_size=None, batch_timeout=None, mode="live"):
        """
        Args:
            flow_queue: queue.Queue of raw flow dicts from CICFlowMeter
            classifier_queue: queue.Queue to push preprocessed results
            stop_event: threading.Event to signal stop
            model_dir: path to trained_model directory (default: trained_model/)
            use_all_classes: if True, use trained_model_all/
            batch_size: number of flows to batch before processing (default from config)
            batch_timeout: max seconds to wait for a full batch (default from config)
            mode: 'live' or 'batch' - batch mode uses faster queue timeouts
        """
        self.flow_queue = flow_queue
        self.classifier_queue = classifier_queue
        self.stop_event = stop_event
        self.mode = mode
        self.batch_size = batch_size if batch_size is not None else CLASSIFICATION_BATCH_SIZE
        self.batch_timeout = batch_timeout if batch_timeout is not None else CLASSIFICATION_BATCH_TIMEOUT
        self.processed_count = 0

        # Determine model directory
        if model_dir is None:
            if use_all_classes:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model_all")
            else:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model")
        self.model_dir = model_dir

        # Load artifacts
        self.scaler = None
        self.scaler_feature_names = None  # The 80 features the scaler expects
        self.selected_features = None     # The 40 features the model expects
        self.label_encoder = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Load the scaler, feature list, and label encoder from the trained model."""
        print(f"{COLOR_CYAN}[PREPROCESSOR] Loading artifacts from: {self.model_dir}{COLOR_RESET}")

        scaler_path = os.path.join(self.model_dir, "scaler.joblib")
        features_path = os.path.join(self.model_dir, "selected_features.joblib")
        encoder_path = os.path.join(self.model_dir, "label_encoder.joblib")

        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"Selected features not found: {features_path}")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder not found: {encoder_path}")

        self.scaler = joblib.load(scaler_path)
        self.selected_features = joblib.load(features_path)
        self.label_encoder = joblib.load(encoder_path)

        # Get the full feature list the scaler was fitted on (80 features)
        if hasattr(self.scaler, 'feature_names_in_'):
            self.scaler_feature_names = list(self.scaler.feature_names_in_)
        else:
            raise ValueError("Scaler does not have feature_names_in_. Cannot determine expected features.")

        print(f"{COLOR_GREEN}[PREPROCESSOR] Loaded scaler ({len(self.scaler_feature_names)} features), "
              f"model expects {len(self.selected_features)} selected features, "
              f"{len(self.label_encoder.classes_)} classes: {list(self.label_encoder.classes_)}{COLOR_RESET}")

    def _preprocess_flow(self, flow_dict):
        """
        Preprocess a single raw flow dict into a model-ready feature vector.

        Matches the training pipeline order:
            1. Extract identifiers
            2. Drop identifier columns (Flow ID, Src IP, Dst IP, Src Port, Timestamp, Label)
            3. Convert to numeric, handle inf/nan
            4. One-hot encode Protocol → Protocol_0, Protocol_6, Protocol_17
            5. Build full 80-feature vector in scaler's expected order
            6. Scale ALL 80 features with the saved scaler
            7. Select only the 40 features the model needs

        Args:
            flow_dict: dict from CICFlowMeter with training column names as keys

        Returns:
            dict with keys: 'features' (numpy array), 'identifiers' (dict),
                  'feature_names' (list), or None on error
        """
        try:
            # 1. Extract identifiers (already saved by CICFlowMeter source)
            identifiers = flow_dict.pop("__identifiers__", {})
            # Also extract actual_label if present (for labeled batches)
            actual_label = flow_dict.pop("actual_label", None)

            # 2. Create a DataFrame and drop identifier/useless columns
            df = pd.DataFrame([flow_dict])
            cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
            df = df.drop(columns=cols_to_drop, errors='ignore')

            # 3. Convert all columns to numeric, handle inf/nan
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(0)

            # 4. One-hot encode Protocol (matching training: drop_first=False)
            protocol_val = 0
            if "Protocol" in df.columns:
                protocol_val = int(df["Protocol"].iloc[0])
                df = df.drop(columns=["Protocol"])

            # Add Protocol one-hot columns
            df["Protocol_0"] = 1 if protocol_val == 0 else 0
            df["Protocol_17"] = 1 if protocol_val == 17 else 0
            df["Protocol_6"] = 1 if protocol_val == 6 else 0

            # 5. Build full 80-feature DataFrame in scaler's expected column order
            full_df = pd.DataFrame(columns=self.scaler_feature_names, dtype=float)
            full_df.loc[0] = 0.0  # Initialize with zeros

            # Fill in available features
            for col in self.scaler_feature_names:
                if col in df.columns:
                    full_df.at[0, col] = float(df[col].iloc[0])

            # 6. Scale ALL 80 features
            features_scaled = self.scaler.transform(full_df)
            scaled_df = pd.DataFrame(features_scaled, columns=self.scaler_feature_names)

            # 7. Select only the 40 features the model expects
            final_features = scaled_df[self.selected_features].values[0]

            result = {
                "features": final_features,  # 1D array of shape (40,)
                "identifiers": identifiers,
                "feature_names": list(self.selected_features),
            }
            # Include actual_label if present (for labeled batches)
            if actual_label is not None:
                result["actual_label"] = actual_label
            return result

        except Exception as e:
            print(f"{COLOR_YELLOW}[PREPROCESSOR] Error processing flow: {e}{COLOR_RESET}")
            return None

    def run(self):
        """Main loop: read from flow_queue, preprocess, push to classifier_queue.
        Runs until a None sentinel is received from flow_queue, then
        propagates None to classifier_queue for sequential pipeline shutdown."""
        print(f"{COLOR_GREEN}[PREPROCESSOR] Started. Waiting for flows...{COLOR_RESET}")

        batch = []
        last_batch_time = time.time()

        while True:
            try:
                # Use faster timeout for batch mode
                timeout = CLASSIFICATION_BATCH_QUEUE_TIMEOUT if self.mode == "batch" else CLASSIFICATION_QUEUE_TIMEOUT
                flow_dict = self.flow_queue.get(timeout=timeout)

                # Sentinel: end of pipeline input
                if flow_dict is None:
                    self.flow_queue.task_done()
                    break

                batch.append(flow_dict)
                self.flow_queue.task_done()

            except queue.Empty:
                # If stop_event is set and queue is empty, exit
                if self.stop_event.is_set():
                    break

            # Process batch if full or timeout
            current_time = time.time()
            should_process = (
                len(batch) >= self.batch_size or
                (len(batch) > 0 and (current_time - last_batch_time) >= self.batch_timeout)
            )

            if should_process and len(batch) > 0:
                for flow_dict in batch:
                    result = self._preprocess_flow(flow_dict)
                    if result is not None:
                        self.classifier_queue.put(result)
                        self.processed_count += 1

                batch = []
                last_batch_time = current_time

        # Process remaining batch items
        if batch:
            for flow_dict in batch:
                result = self._preprocess_flow(flow_dict)
                if result is not None:
                    self.classifier_queue.put(result)
                    self.processed_count += 1
            batch = []

        # Drain any remaining items in flow_queue
        remaining = 0
        while not self.flow_queue.empty():
            try:
                flow_dict = self.flow_queue.get_nowait()
                if flow_dict is None:
                    self.flow_queue.task_done()
                    continue
                result = self._preprocess_flow(flow_dict)
                if result is not None:
                    self.classifier_queue.put(result)
                    self.processed_count += 1
                    remaining += 1
                self.flow_queue.task_done()
            except queue.Empty:
                break

        if remaining > 0:
            print(f"{COLOR_CYAN}[PREPROCESSOR] Processed {remaining} remaining flows from queue{COLOR_RESET}")

        # Propagate sentinel to classifier
        self.classifier_queue.put(None)

        print(f"{COLOR_GREEN}[PREPROCESSOR] Stopped. Total processed: {self.processed_count}{COLOR_RESET}")
