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
    CLASSIFICATION_DEBUG_FLOWS, CLASSIFICATION_DEBUG_TOP_FEATURES,
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
                 model_dir=None, use_all_classes=False, batch_size=None, batch_timeout=None, mode="live", debug=False):
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
            debug: if True, print detailed feature values for first N flows
        """
        self.flow_queue = flow_queue
        self.classifier_queue = classifier_queue
        self.stop_event = stop_event
        self.mode = mode
        self.debug = debug
        self.debug_count = 0
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

    def _preprocess_batch(self, flow_dicts):
        """
        Vectorized batch preprocessing of multiple raw flow dicts at once.

        Matches the training pipeline order:
            1. Extract identifiers
            2. Drop identifier columns (Flow ID, Src IP, Dst IP, Src Port, Timestamp, Label)
            3. Convert to numeric, handle inf/nan
            4. One-hot encode Protocol → Protocol_0, Protocol_6, Protocol_17
            5. Build full 80-feature matrix in scaler's expected order
            6. Scale ALL 80 features with the saved scaler
            7. Select only the 40 features the model needs

        Args:
            flow_dicts: list of dicts from CICFlowMeter with training column names as keys

        Returns:
            list of dicts with keys: 'features' (numpy array), 'identifiers' (dict),
                  'feature_names' (list). Failed flows are skipped.
        """
        if not flow_dicts:
            return []

        try:
            # 1. Extract identifiers and actual_labels before DataFrame creation
            identifiers_list = []
            actual_labels = []
            clean_dicts = []

            for fd in flow_dicts:
                identifiers_list.append(fd.pop("__identifiers__", {}))
                actual_labels.append(fd.pop("actual_label", None))
                clean_dicts.append(fd)

            # 2. Create ONE DataFrame for all flows and drop identifier columns
            df = pd.DataFrame(clean_dicts)
            cols_to_drop = [c for c in DROP_COLUMNS if c in df.columns]
            df = df.drop(columns=cols_to_drop, errors='ignore')

            # 3. Extract protocol values before dropping, then convert all to numeric
            if "Protocol" in df.columns:
                protocol_vals = pd.to_numeric(df["Protocol"], errors='coerce').fillna(0).astype(int)
                df = df.drop(columns=["Protocol"])
            else:
                protocol_vals = pd.Series([0] * len(df), dtype=int)

            df = df.apply(pd.to_numeric, errors='coerce')
            df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

            # 4. One-hot encode Protocol (vectorized)
            df["Protocol_0"] = (protocol_vals.values == 0).astype(int)
            df["Protocol_17"] = (protocol_vals.values == 17).astype(int)
            df["Protocol_6"] = (protocol_vals.values == 6).astype(int)

            # 5. Build full 80-feature DataFrame in scaler's expected column order (vectorized)
            full_df = pd.DataFrame(0.0, index=range(len(df)), columns=self.scaler_feature_names)
            common_cols = [c for c in self.scaler_feature_names if c in df.columns]
            if common_cols:
                full_df[common_cols] = df[common_cols].values

            # 6. Scale ALL 80 features (single sklearn call for entire batch)
            features_scaled = self.scaler.transform(full_df)

            # 7. Select only the 40 features the model expects (vectorized indexing)
            if not hasattr(self, '_selected_indices'):
                self._selected_indices = [self.scaler_feature_names.index(f) for f in self.selected_features]
            final_features = features_scaled[:, self._selected_indices]

            # DEBUG: Print feature values for first N flows
            if self.debug and self.debug_count < CLASSIFICATION_DEBUG_FLOWS:
                for i in range(min(len(flow_dicts), CLASSIFICATION_DEBUG_FLOWS - self.debug_count)):
                    self.debug_count += 1
                    print(f"\n{COLOR_CYAN}{'='*70}")
                    print(f"[DEBUG PREPROCESSOR] Flow #{self.debug_count}")
                    print(f"{'='*70}{COLOR_RESET}")

                    # Show identifiers
                    ident = identifiers_list[i]
                    print(f"  Src: {ident.get('src_ip','?')}:{ident.get('src_port','?')} -> "
                          f"Dst: {ident.get('dst_ip','?')}:{ident.get('dst_port','?')} "
                          f"Proto: {ident.get('protocol','?')}")

                    # Show top features by absolute scaled value (most impactful)
                    feat_vals = list(zip(self.selected_features, final_features[i]))
                    feat_vals.sort(key=lambda x: abs(x[1]), reverse=True)
                    print(f"\n  Top {CLASSIFICATION_DEBUG_TOP_FEATURES} features (by |scaled value|):")
                    for fname, fval in feat_vals[:CLASSIFICATION_DEBUG_TOP_FEATURES]:
                        # Also show pre-scaled value
                        pre_idx = self.scaler_feature_names.index(fname)
                        raw_val = full_df.iloc[i][fname]
                        print(f"    {fname:<35} raw={raw_val:<15.4f} scaled={fval:<12.6f}")

                    print(f"{COLOR_CYAN}{'='*70}{COLOR_RESET}")

            # Build results list
            results = []
            feature_names_list = list(self.selected_features)
            for i in range(len(flow_dicts)):
                result = {
                    "features": final_features[i],  # 1D array of shape (40,)
                    "identifiers": identifiers_list[i],
                    "feature_names": feature_names_list,
                }
                if actual_labels[i] is not None:
                    result["actual_label"] = actual_labels[i]
                results.append(result)

            return results

        except Exception as e:
            print(f"{COLOR_YELLOW}[PREPROCESSOR] Batch error ({len(flow_dicts)} flows): {e}{COLOR_RESET}")
            # Fallback: try processing individually
            results = []
            for i, fd in enumerate(flow_dicts):
                try:
                    single_result = self._preprocess_batch([fd])
                    results.extend(single_result)
                except Exception:
                    pass
            return results

    def run(self):
        """Main loop: read from flow_queue, preprocess in vectorized batches, push to classifier_queue.
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
                results = self._preprocess_batch(batch)
                for result in results:
                    self.classifier_queue.put(result)
                    self.processed_count += 1

                batch = []
                last_batch_time = current_time

        # Process remaining batch items
        if batch:
            results = self._preprocess_batch(batch)
            for result in results:
                self.classifier_queue.put(result)
                self.processed_count += 1
            batch = []

        # Drain any remaining items in flow_queue (process in batches)
        drain_batch = []
        while not self.flow_queue.empty():
            try:
                flow_dict = self.flow_queue.get_nowait()
                if flow_dict is None:
                    self.flow_queue.task_done()
                    continue
                drain_batch.append(flow_dict)
                self.flow_queue.task_done()
            except queue.Empty:
                break

        if drain_batch:
            results = self._preprocess_batch(drain_batch)
            for result in results:
                self.classifier_queue.put(result)
                self.processed_count += 1
            print(f"{COLOR_CYAN}[PREPROCESSOR] Processed {len(drain_batch)} remaining flows from queue{COLOR_RESET}")

        # Propagate sentinel to classifier
        self.classifier_queue.put(None)

        print(f"{COLOR_GREEN}[PREPROCESSOR] Stopped. Total processed: {self.processed_count}{COLOR_RESET}")
