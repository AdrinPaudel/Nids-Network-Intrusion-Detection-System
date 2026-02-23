"""
Classifier
Wrapper around the trained RandomForest model.
Takes preprocessed feature vectors from classifier_queue,
predicts class probabilities, and sends top-3 results to
threat_handler_queue and report_queue.
"""

import os
import sys
import threading
import queue
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import numpy as np
import pandas as pd
import joblib
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_QUEUE_TIMEOUT, CLASSIFICATION_BATCH_QUEUE_TIMEOUT,
    CLASSIFICATION_CLASSIFIER_BATCH_SIZE, CLASSIFICATION_CLASSIFIER_BATCH_TIMEOUT,
    CLASSIFICATION_DEBUG_FLOWS,
    COLOR_CYAN, COLOR_RED, COLOR_GREEN, COLOR_RESET
)


class Classifier:
    """
    Real-time classifier that loads the trained RF model
    and classifies preprocessed flows.
    """

    def __init__(self, classifier_queue, threat_queue, report_queue, stop_event,
                 model_dir=None, use_all_classes=False, mode="live", debug=False):
        """
        Args:
            classifier_queue: queue.Queue of preprocessed flow dicts
            threat_queue: queue.Queue to push classification results for threat handler
            report_queue: queue.Queue to push classification results for report generator
            stop_event: threading.Event to signal stop
            model_dir: path to trained_model directory
            use_all_classes: if True, use trained_model_all/
            mode: 'live' or 'batch' - batch mode uses faster queue timeouts
            debug: if True, print detailed prediction probabilities for first N flows
        """
        self.classifier_queue = classifier_queue
        self.threat_queue = threat_queue
        self.report_queue = report_queue
        self.stop_event = stop_event
        self.mode = mode
        self.debug = debug
        self.debug_count = 0
        self.classified_count = 0
        self.batch_size = CLASSIFICATION_CLASSIFIER_BATCH_SIZE
        self.batch_timeout = CLASSIFICATION_CLASSIFIER_BATCH_TIMEOUT

        # Determine model directory
        if model_dir is None:
            if use_all_classes:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model_all")
            else:
                model_dir = os.path.join(PROJECT_ROOT, "trained_model")
        self.model_dir = model_dir

        # Load model and label encoder
        self.model = None
        self.label_encoder = None
        self._load_model()

    def _load_model(self):
        """Load the trained Random Forest model and label encoder."""
        print(f"{COLOR_CYAN}[CLASSIFIER] Loading model from: {self.model_dir}{COLOR_RESET}")

        model_path = os.path.join(self.model_dir, "random_forest_model.joblib")
        encoder_path = os.path.join(self.model_dir, "label_encoder.joblib")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder not found: {encoder_path}")

        self.model = joblib.load(model_path)
        self.label_encoder = joblib.load(encoder_path)

        class_names = list(self.label_encoder.classes_)
        print(f"{COLOR_GREEN}[CLASSIFIER] Model loaded. "
              f"Trees: {self.model.n_estimators}, "
              f"Classes: {class_names}{COLOR_RESET}")

    def _classify_batch(self, preprocessed_list):
        """
        Classify a batch of preprocessed flows at once using vectorized predict_proba.

        Args:
            preprocessed_list: list of dicts with 'features', 'identifiers', 'feature_names',
                               and optionally 'actual_label'

        Returns:
            list of result dicts with 'identifiers', 'top3', 'predicted_class',
            'confidence', 'timestamp', and optionally 'actual_label'
        """
        if not preprocessed_list:
            return []

        try:
            # Stack all feature vectors into a single 2D array
            features_array = np.array([p["features"] for p in preprocessed_list])
            feature_names = preprocessed_list[0].get("feature_names", None)

            # Create single DataFrame for entire batch
            if feature_names is not None:
                features_df = pd.DataFrame(features_array, columns=feature_names)
            else:
                features_df = features_array

            # Single predict_proba call for the entire batch
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                all_probabilities = self.model.predict_proba(features_df)

            # Build results for each flow
            class_names = self.label_encoder.classes_
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            results = []

            for i, preprocessed in enumerate(preprocessed_list):
                probabilities = all_probabilities[i]
                predictions = list(zip(class_names, probabilities))
                predictions.sort(key=lambda x: x[1], reverse=True)
                top3 = [(name, float(conf)) for name, conf in predictions[:3]]

                result = {
                    "identifiers": preprocessed["identifiers"],
                    "top3": top3,
                    "predicted_class": top3[0][0],
                    "confidence": top3[0][1],
                    "timestamp": timestamp,
                }
                if "actual_label" in preprocessed:
                    result["actual_label"] = preprocessed["actual_label"]
                results.append(result)

                # DEBUG: Print full probability distribution for first N flows
                if self.debug and self.debug_count < CLASSIFICATION_DEBUG_FLOWS:
                    self.debug_count += 1
                    ident = preprocessed.get("identifiers", {})
                    print(f"\n{COLOR_CYAN}{'='*70}")
                    print(f"[DEBUG CLASSIFIER] Flow #{self.debug_count}")
                    print(f"{'='*70}{COLOR_RESET}")
                    print(f"  Src: {ident.get('src_ip','?')}:{ident.get('src_port','?')} -> "
                          f"Dst: {ident.get('dst_ip','?')}:{ident.get('dst_port','?')}")
                    print(f"  Prediction: {top3[0][0]} ({top3[0][1]*100:.2f}%)")
                    print(f"  All class probabilities:")
                    for cls_name, prob in predictions:
                        bar = '\u2588' * int(prob * 40)
                        print(f"    {cls_name:<20} {prob*100:>7.3f}%  {bar}")
                    print(f"{COLOR_CYAN}{'='*70}{COLOR_RESET}")

            return results

        except Exception as e:
            print(f"\033[93m[CLASSIFIER] Batch classification error: {e}\033[0m")
            # Fallback: try individually
            results = []
            for p in preprocessed_list:
                try:
                    single = self._classify_batch([p])
                    results.extend(single)
                except Exception:
                    pass
            return results

    def run(self):
        """Main loop: read from classifier_queue in batches, classify, push to threat and report queues.
        Runs until a None sentinel is received, then propagates None to
        threat_queue and report_queue for sequential pipeline shutdown."""
        warnings.filterwarnings("ignore", category=UserWarning)
        print(f"{COLOR_GREEN}[CLASSIFIER] Started. Waiting for preprocessed flows...{COLOR_RESET}")

        batch = []
        last_batch_time = time.time()

        while True:
            try:
                # Use faster timeout for batch mode
                timeout = CLASSIFICATION_BATCH_QUEUE_TIMEOUT if self.mode == "batch" else CLASSIFICATION_QUEUE_TIMEOUT
                preprocessed = self.classifier_queue.get(timeout=timeout)

                # Sentinel: end of pipeline input
                if preprocessed is None:
                    self.classifier_queue.task_done()
                    break

                batch.append(preprocessed)
                self.classifier_queue.task_done()

            except queue.Empty:
                # If stop_event is set and queue is empty, exit
                if self.stop_event.is_set():
                    break
                # Fall through to check batch processing

            # Process batch if full or timeout
            current_time = time.time()
            should_process = (
                len(batch) >= self.batch_size or
                (len(batch) > 0 and (current_time - last_batch_time) >= self.batch_timeout)
            )

            if should_process and len(batch) > 0:
                results = self._classify_batch(batch)
                for result in results:
                    if self.mode != "batch":
                        self.threat_queue.put(result)
                    self.report_queue.put(result)
                    self.classified_count += 1
                batch = []
                last_batch_time = current_time

        # Process remaining batch items
        if batch:
            results = self._classify_batch(batch)
            for result in results:
                if self.mode != "batch":
                    self.threat_queue.put(result)
                self.report_queue.put(result)
                self.classified_count += 1
            batch = []

        # Drain remaining items in batches
        drain_batch = []
        while not self.classifier_queue.empty():
            try:
                preprocessed = self.classifier_queue.get_nowait()
                if preprocessed is None:
                    self.classifier_queue.task_done()
                    continue
                drain_batch.append(preprocessed)
                self.classifier_queue.task_done()
            except queue.Empty:
                break

        if drain_batch:
            results = self._classify_batch(drain_batch)
            for result in results:
                if self.mode != "batch":
                    self.threat_queue.put(result)
                self.report_queue.put(result)
                self.classified_count += 1
            print(f"{COLOR_CYAN}[CLASSIFIER] Classified {len(drain_batch)} remaining flows{COLOR_RESET}")

        # Propagate sentinel to threat handler and report generator
        if self.mode != "batch":
            self.threat_queue.put(None)
        self.report_queue.put(None)

        print(f"{COLOR_GREEN}[CLASSIFIER] Stopped. Total classified: {self.classified_count}{COLOR_RESET}")
