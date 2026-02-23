"""
Diagnostic script: Test if the classification pipeline produces correct results
when fed KNOWN attack data from the training CSV files.

This verifies:
1. The model can still classify training data correctly
2. The real-time preprocessor produces the same results as training preprocessing
3. Where feature values diverge between Python CICFlowMeter and Java CICFlowMeter
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def load_artifacts(model_dir="trained_model"):
    """Load all model artifacts."""
    path = os.path.join(PROJECT_ROOT, model_dir)
    scaler = joblib.load(os.path.join(path, "scaler.joblib"))
    selected = joblib.load(os.path.join(path, "selected_features.joblib"))
    le = joblib.load(os.path.join(path, "label_encoder.joblib"))
    model = joblib.load(os.path.join(path, "random_forest_model.joblib"))
    return scaler, selected, le, model


def preprocess_row_training_style(row, scaler, selected_features):
    """
    Preprocess a single CSV row using the TRAINING pipeline approach:
    1. Drop identifiers
    2. Handle Protocol one-hot encoding
    3. Scale all 80 features
    4. Select 40 features
    """
    from config import PREPROCESSING_DROP_COLUMNS

    scaler_features = list(scaler.feature_names_in_)

    # Drop identifiers (but keep Dst Port and Protocol)
    drop_cols = PREPROCESSING_DROP_COLUMNS  # Flow ID, Src IP, Dst IP, Src Port, Timestamp
    data = {}
    for col, val in row.items():
        if col in drop_cols or col == 'Label':
            continue
        data[col] = val

    # Extract protocol and remove from data
    protocol = int(float(data.pop("Protocol", 0)))

    # Convert all to numeric
    for k in list(data.keys()):
        try:
            data[k] = float(data[k])
        except (ValueError, TypeError):
            data[k] = 0.0

    # One-hot encode protocol
    data["Protocol_0"] = 1 if protocol == 0 else 0
    data["Protocol_6"] = 1 if protocol == 6 else 0
    data["Protocol_17"] = 1 if protocol == 17 else 0

    # Build 80-feature vector in scaler order
    feature_vec = []
    for f in scaler_features:
        feature_vec.append(data.get(f, 0.0))

    feature_vec = np.array(feature_vec).reshape(1, -1)

    # Replace inf/nan
    feature_vec = np.nan_to_num(feature_vec, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale
    scaled = scaler.transform(feature_vec)

    # Select features
    selected_indices = [scaler_features.index(f) for f in selected_features]
    final = scaled[0, selected_indices]

    return final, feature_vec[0]


def preprocess_row_realtime_style(row, scaler, selected_features):
    """
    Preprocess a single CSV row using the REAL-TIME pipeline approach
    (mimicking classification/preprocessor.py _preprocess_batch).
    """
    from config import CLASSIFICATION_DROP_COLUMNS

    scaler_features = list(scaler.feature_names_in_)

    # Simulate what the real-time preprocessor does
    data = dict(row)

    # Drop classification columns (includes Label)
    drop_cols = CLASSIFICATION_DROP_COLUMNS  # Flow ID, Src IP, Dst IP, Src Port, Timestamp, Label
    for c in drop_cols:
        data.pop(c, None)

    # Extract protocol
    protocol = 0
    if "Protocol" in data:
        try:
            protocol = int(float(data.pop("Protocol")))
        except:
            data.pop("Protocol", None)

    # Convert all to numeric
    for k in list(data.keys()):
        try:
            data[k] = float(data[k])
        except (ValueError, TypeError):
            data[k] = 0.0

    # Replace inf/nan
    for k in data:
        v = data[k]
        if np.isinf(v) or np.isnan(v):
            data[k] = 0.0

    # One-hot encode
    data["Protocol_0"] = 1 if protocol == 0 else 0
    data["Protocol_6"] = 1 if protocol == 6 else 0
    data["Protocol_17"] = 1 if protocol == 17 else 0

    # Build 80-feature vector
    feature_vec = []
    for f in scaler_features:
        feature_vec.append(data.get(f, 0.0))

    feature_vec = np.array(feature_vec).reshape(1, -1)

    # Scale
    scaled = scaler.transform(feature_vec)

    # Select features
    selected_indices = [scaler_features.index(f) for f in selected_features]
    final = scaled[0, selected_indices]

    return final, feature_vec[0]


def classify(features_1d, model, le, selected_features):
    """Classify a single preprocessed feature vector."""
    features_df = pd.DataFrame([features_1d], columns=selected_features)
    probas = model.predict_proba(features_df)[0]
    predictions = list(zip(le.classes_, probas))
    predictions.sort(key=lambda x: x[1], reverse=True)
    return predictions


def main():
    print("=" * 80)
    print("NIDS CLASSIFICATION PIPELINE DIAGNOSTIC")
    print("=" * 80)

    # Load artifacts
    scaler, selected, le, model = load_artifacts("trained_model")
    scaler_features = list(scaler.feature_names_in_)

    print(f"\nModel: {len(le.classes_)} classes: {list(le.classes_)}")
    print(f"Scaler: {len(scaler_features)} features")
    print(f"Selected: {len(selected)} features")

    # ================================================================
    # TEST 1: Does the model classify training data correctly?
    # ================================================================
    print("\n" + "=" * 80)
    print("TEST 1: Classify KNOWN training data rows")
    print("=" * 80)

    # Load different CSV files for different attack types
    test_files = {
        "Botnet": ("data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", "Bot"),
        "DoS": ("data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv", "DoS"),
        "DDoS": ("data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv", "DDoS"),
    }

    for attack_name, (csv_path, label_prefix) in test_files.items():
        full_path = os.path.join(PROJECT_ROOT, csv_path)
        if not os.path.exists(full_path):
            print(f"\n  [{attack_name}] CSV not found: {csv_path}")
            continue

        df = pd.read_csv(full_path, nrows=10000)

        # Find attack rows
        attack_mask = df["Label"].str.contains(label_prefix, case=False, na=False)
        benign_mask = df["Label"].str.contains("Benign", case=False, na=False)

        if attack_mask.sum() == 0:
            print(f"\n  [{attack_name}] No attack rows found with label containing '{label_prefix}'")
            print(f"    Labels in file: {df['Label'].unique()[:10]}")
            continue

        attack_rows = df[attack_mask].head(5)
        benign_rows = df[benign_mask].head(2)

        print(f"\n--- {attack_name} (from {os.path.basename(csv_path)}) ---")
        print(f"    Labels in file: {df['Label'].value_counts().to_dict()}")

        for idx, (_, row) in enumerate(attack_rows.iterrows()):
            features_train, raw_train = preprocess_row_training_style(row, scaler, selected)
            features_rt, raw_rt = preprocess_row_realtime_style(row, scaler, selected)

            preds_train = classify(features_train, model, le, selected)
            preds_rt = classify(features_rt, model, le, selected)

            actual = row["Label"]

            print(f"\n  Attack Row {idx+1} (actual: {actual}):")
            print(f"    Training-style -> {preds_train[0][0]:15s} ({preds_train[0][1]*100:5.1f}%)"
                  f"  | 2nd: {preds_train[1][0]:15s} ({preds_train[1][1]*100:5.1f}%)")
            print(f"    Realtime-style -> {preds_rt[0][0]:15s} ({preds_rt[0][1]*100:5.1f}%)"
                  f"  | 2nd: {preds_rt[1][0]:15s} ({preds_rt[1][1]*100:5.1f}%)")

            # Check if training and realtime produce same features
            diff = np.abs(features_train - features_rt)
            if np.max(diff) > 1e-10:
                print(f"    WARNING: Training vs Realtime features differ! Max diff: {np.max(diff):.6f}")
                for i, fname in enumerate(selected):
                    if diff[i] > 1e-10:
                        print(f"      {fname}: train={features_train[i]:.6f} rt={features_rt[i]:.6f}")

        # Also test benign
        for idx, (_, row) in enumerate(benign_rows.iterrows()):
            features_rt, _ = preprocess_row_realtime_style(row, scaler, selected)
            preds = classify(features_rt, model, le, selected)
            print(f"\n  Benign Row {idx+1} (actual: {row['Label']}):")
            print(f"    -> {preds[0][0]:15s} ({preds[0][1]*100:5.1f}%)"
                  f"  | 2nd: {preds[1][0]:15s} ({preds[1][1]*100:5.1f}%)")

    # ================================================================
    # TEST 2: Simulate what Python CICFlowMeter would produce
    # ================================================================
    print("\n" + "=" * 80)
    print("TEST 2: Simulate Python CICFlowMeter output mapping")
    print("=" * 80)

    # Take a known attack row and simulate what it would look like
    # if it came from Python CICFlowMeter
    csv_path = os.path.join(PROJECT_ROOT, "data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path, nrows=5000)
        attack = df[df["Label"] == "Bot"].iloc[0]

        from classification.flowmeter_source import PYTHON_CFM_TO_TRAINING, TIME_BASED_FIELDS, SECONDS_TO_MICROSECONDS

        # Reverse map: training name -> python CFM name
        training_to_python = {v: k for k, v in PYTHON_CFM_TO_TRAINING.items()}

        print("\n  Key features in training data vs simulated Python CICFlowMeter:")
        print(f"  {'Feature':40s} {'Training CSV':>15s} {'Py CFM (sec)':>15s} {'Py CFM (us)':>15s}")
        print("  " + "-" * 87)

        for fname in selected[:20]:  # Top 20 selected features
            training_val = attack.get(fname, "N/A")
            py_key = training_to_python.get(fname, None)

            if py_key and py_key in TIME_BASED_FIELDS:
                # This is a time-based field. In training data it's in microseconds.
                # Python CFM would produce seconds, then we multiply by 1M.
                try:
                    training_us = float(training_val)
                    simulated_sec = training_us / SECONDS_TO_MICROSECONDS
                    converted_back = simulated_sec * SECONDS_TO_MICROSECONDS
                    print(f"  {fname:40s} {training_us:15.2f} {simulated_sec:15.6f} {converted_back:15.2f}  [TIME]")
                except:
                    print(f"  {fname:40s} {str(training_val):>15s} {'?':>15s} {'?':>15s}  [TIME]")
            else:
                print(f"  {fname:40s} {str(training_val):>15s}")

    # ================================================================
    # TEST 3: Check what Python CICFlowMeter actually outputs
    # ================================================================
    print("\n" + "=" * 80)
    print("TEST 3: Check cicflowmeter package flow.get_data() output keys")
    print("=" * 80)

    try:
        from cicflowmeter.flow import Flow
        # Check what attributes a Flow object has
        import inspect
        members = [m for m in dir(Flow) if not m.startswith('_')]
        print(f"\n  Flow class methods/attrs: {members}")

        # Try to find get_data method
        if hasattr(Flow, 'get_data'):
            sig = inspect.signature(Flow.get_data)
            print(f"  Flow.get_data signature: {sig}")

            # Try to read the source
            try:
                source = inspect.getsource(Flow.get_data)
                # Find all the keys it returns
                import re
                keys = re.findall(r'"(\w+)"', source)
                unique_keys = sorted(set(keys))
                print(f"\n  Keys found in get_data() source ({len(unique_keys)}):")
                for k in unique_keys:
                    mapped = PYTHON_CFM_TO_TRAINING.get(k, "*** UNMAPPED ***")
                    print(f"    {k:30s} -> {mapped}")

                unmapped_training = set(PYTHON_CFM_TO_TRAINING.keys()) - set(unique_keys)
                if unmapped_training:
                    print(f"\n  MAPPING keys NOT in get_data() output ({len(unmapped_training)}):")
                    for k in sorted(unmapped_training):
                        print(f"    {k:30s} -> {PYTHON_CFM_TO_TRAINING[k]} *** MISSING from CICFlowMeter ***")
            except:
                print("  Could not read get_data source")
    except ImportError:
        print("\n  cicflowmeter not installed, skipping package inspection")

    # ================================================================
    # TEST 4: Check feature value ranges
    # ================================================================
    print("\n" + "=" * 80)
    print("TEST 4: Training data feature statistics (for comparison)")
    print("=" * 80)

    csv_path = os.path.join(PROJECT_ROOT, "data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path, nrows=50000)

        print(f"\n  {'Feature':40s} {'Mean':>15s} {'Std':>15s} {'Min':>15s} {'Max':>15s}")
        print("  " + "-" * 102)

        for fname in selected[:20]:
            if fname in df.columns:
                vals = pd.to_numeric(df[fname], errors='coerce').dropna()
                vals = vals.replace([np.inf, -np.inf], np.nan).dropna()
                print(f"  {fname:40s} {vals.mean():15.2f} {vals.std():15.2f} {vals.min():15.2f} {vals.max():15.2f}")
            else:
                print(f"  {fname:40s} NOT IN CSV")

    print("\n" + "=" * 80)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
