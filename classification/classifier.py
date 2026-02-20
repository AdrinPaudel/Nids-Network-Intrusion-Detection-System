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

from config import CLASSIFICATION_QUEUE_TIMEOUT, CLASSIFICATION_BATCH_QUEUE_TIMEOUT, COLOR_CYAN, COLOR_RED, COLOR_GREEN, COLOR_RESET


class Classifier:
    """
    Real-time classifier that loads the trained RF model
    and classifies preprocessed flows.
    """

    def __init__(self, classifier_queue, threat_queue, report_queue, stop_event,
                 model_dir=None, use_all_classes=False, mode="live"):
        """
        Args:
            classifier_queue: queue.Queue of preprocessed flow dicts
            threat_queue: queue.Queue to push classification results for threat handler
            report_queue: queue.Queue to push classification results for report generator
            stop_event: threading.Event to signal stop
            model_dir: path to trained_model directory
            use_all_classes: if True, use trained_model_all/
            mode: 'live' or 'batch' - batch mode uses faster queue timeouts
        """
        self.classifier_queue = classifier_queue
        self.threat_queue = threat_queue
        self.report_queue = report_queue
        self.stop_event = stop_event
        self.mode = mode
        self.classified_count = 0

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

    def _classify(self, preprocessed):
        """
        Classify a single preprocessed flow.

        Args:
            preprocessed: dict with 'features', 'identifiers', 'feature_names', and optionally 'actual_label'

        Returns:
            dict with:
                'identifiers': original flow identifiers
                'top3': list of (class_name, confidence) tuples, sorted descending
                'predicted_class': top predicted class name
                'confidence': confidence of top prediction
                'timestamp': classification timestamp
                'actual_label': actual label if present in preprocessed (for labeled batches)
        """
        try:
            features = preprocessed["features"].reshape(1, -1)
            feature_names = preprocessed.get("feature_names", None)

            # Create DataFrame with feature names to avoid sklearn warning
            if feature_names is not None:
                features_df = pd.DataFrame(features, columns=feature_names)
            else:
                features_df = features

            # Get probability predictions
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                probabilities = self.model.predict_proba(features_df)[0]

            # Build (class_name, confidence) pairs
            class_names = self.label_encoder.classes_
            predictions = list(zip(class_names, probabilities))

            # Sort by confidence descending, take top 3
            predictions.sort(key=lambda x: x[1], reverse=True)
            top3 = [(name, float(conf)) for name, conf in predictions[:3]]

            result = {
                "identifiers": preprocessed["identifiers"],
                "top3": top3,
                "predicted_class": top3[0][0],
                "confidence": top3[0][1],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            # Include actual_label if present (for labeled batches)
            if "actual_label" in preprocessed:
                result["actual_label"] = preprocessed["actual_label"]
            return result

        except Exception as e:
            print(f"\033[93m[CLASSIFIER] Classification error: {e}\033[0m")
            return None

    def run(self):
        """Main loop: read from classifier_queue, classify, push to threat and report queues.
        Runs until a None sentinel is received, then propagates None to
        threat_queue and report_queue for sequential pipeline shutdown."""
        warnings.filterwarnings("ignore", category=UserWarning)
        print(f"{COLOR_GREEN}[CLASSIFIER] Started. Waiting for preprocessed flows...{COLOR_RESET}")

        while True:
            try:
                # Use faster timeout for batch mode
                timeout = CLASSIFICATION_BATCH_QUEUE_TIMEOUT if self.mode == "batch" else CLASSIFICATION_QUEUE_TIMEOUT
                preprocessed = self.classifier_queue.get(timeout=timeout)

                # Sentinel: end of pipeline input
                if preprocessed is None:
                    self.classifier_queue.task_done()
                    break

                result = self._classify(preprocessed)

                if result is not None:
                    # Skip threat handler in batch mode
                    if self.mode != "batch":
                        self.threat_queue.put(result)
                    self.report_queue.put(result)
                    self.classified_count += 1

                self.classifier_queue.task_done()

            except queue.Empty:
                # If stop_event is set and queue is empty, exit
                if self.stop_event.is_set():
                    break
                continue
            except Exception as e:
                print(f"{COLOR_RED}[CLASSIFIER] Error: {e}{COLOR_RESET}")

        # Drain remaining items
        remaining = 0
        while not self.classifier_queue.empty():
            try:
                preprocessed = self.classifier_queue.get_nowait()
                if preprocessed is None:
                    self.classifier_queue.task_done()
                    continue
                result = self._classify(preprocessed)
                if result is not None:
                    # Skip threat handler in batch mode
                    if self.mode != "batch":
                        self.threat_queue.put(result)
                    self.report_queue.put(result)
                    self.classified_count += 1
                    remaining += 1
                self.classifier_queue.task_done()
            except queue.Empty:
                break

        if remaining > 0:
            print(f"{COLOR_CYAN}[CLASSIFIER] Classified {remaining} remaining flows{COLOR_RESET}")

        # Propagate sentinel to threat handler and report generator
        if self.mode != "batch":
            self.threat_queue.put(None)
        self.report_queue.put(None)

        print(f"{COLOR_GREEN}[CLASSIFIER] Stopped. Total classified: {self.classified_count}{COLOR_RESET}")
