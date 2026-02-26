#!/usr/bin/env python
"""
Compare captured CICFlowMeter flows with CICIDS2018 training data.

Usage:
    python compare_flows.py                          # Auto-find latest captured flows
    python compare_flows.py data/captured_flows/flows_20250115_143000.csv

Loads a captured flows CSV (from --save-flows) and compares key features
against DoS-Hulk training data medians. Highlights mismatches that cause
the model to classify flows as Benign instead of DoS.
"""

import os
import sys
import glob
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# Key features for DoS-Hulk classification (by importance)
# These are the features that matter most for RED classification
# ============================================================
KEY_FEATURES = [
    "Dst Port",
    "Fwd Seg Size Min",
    "Init Fwd Win Byts",
    "TotLen Fwd Pkts",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Pkt Len Max",
    "Pkt Len Min",
    "Pkt Len Mean",
    "Flow Duration",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Pkts/s",
    "Init Bwd Win Byts",
    "Fwd Header Len",
    "Bwd Header Len",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "FIN Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "Fwd Act Data Pkts",
    "TotLen Bwd Pkts",
    "Flow IAT Mean",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Pkt Len Var",
    "Pkt Len Std",
    "Protocol",
]


def load_training_dos_hulk():
    """Load DoS-Hulk flows from CICIDS2018 training data."""
    dos_file = os.path.join(PROJECT_ROOT, "data", "raw",
                            "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv")
    if not os.path.exists(dos_file):
        print(f"[!] Training data not found: {dos_file}")
        return None

    print(f"[*] Loading training data: {os.path.basename(dos_file)} ...")
    df = pd.read_csv(dos_file, low_memory=False)
    df.columns = df.columns.str.strip()

    # Filter DoS-Hulk
    if "Label" in df.columns:
        hulk = df[df["Label"].str.strip().str.lower() == "dos attacks-hulk"].copy()
        if len(hulk) == 0:
            # Try alternate label names
            for label_pattern in ["hulk", "dos-hulk", "dos attacks-hulk"]:
                hulk = df[df["Label"].str.strip().str.lower().str.contains(label_pattern)].copy()
                if len(hulk) > 0:
                    break
        print(f"[*] DoS-Hulk training flows: {len(hulk):,}")
        return hulk
    return None


def find_latest_flows():
    """Find the most recent captured flows CSV."""
    flows_dir = os.path.join(PROJECT_ROOT, "data", "captured_flows")
    if not os.path.isdir(flows_dir):
        return None
    csvs = sorted(glob.glob(os.path.join(flows_dir, "flows_*.csv")))
    return csvs[-1] if csvs else None


def compare_features(captured_df, training_df, features):
    """Compare feature distributions between captured and training flows."""
    print(f"\n{'='*100}")
    print(f"  FEATURE COMPARISON: Captured Flows vs DoS-Hulk Training Data")
    print(f"{'='*100}")
    print(f"  Captured flows: {len(captured_df):,}")
    print(f"  Training flows: {len(training_df):,}")
    print(f"{'='*100}\n")

    header = f"{'Feature':<25} {'Captured Median':>18} {'Training Median':>18} {'Match?':>8} {'Captured Mean':>16} {'Training Mean':>16}"
    print(header)
    print("-" * len(header))

    mismatches = []
    for feat in features:
        cap_exists = feat in captured_df.columns
        train_exists = feat in training_df.columns

        if not cap_exists and not train_exists:
            continue

        if not cap_exists:
            print(f"{feat:<25} {'MISSING':>18} ", end="")
            train_vals = pd.to_numeric(training_df[feat], errors="coerce").dropna()
            print(f"{train_vals.median():>18.2f} {'  !!':>8}")
            mismatches.append((feat, "MISSING in captured", train_vals.median()))
            continue

        if not train_exists:
            cap_vals = pd.to_numeric(captured_df[feat], errors="coerce").dropna()
            print(f"{feat:<25} {cap_vals.median():>18.2f} {'MISSING':>18}")
            continue

        cap_vals = pd.to_numeric(captured_df[feat], errors="coerce").dropna()
        train_vals = pd.to_numeric(training_df[feat], errors="coerce").dropna()

        if len(cap_vals) == 0 or len(train_vals) == 0:
            continue

        cap_med = cap_vals.median()
        train_med = train_vals.median()
        cap_mean = cap_vals.mean()
        train_mean = train_vals.mean()

        # Determine if they match reasonably
        if train_med == 0:
            match = "OK" if abs(cap_med) < 10 else "!!"
        else:
            ratio = abs(cap_med / train_med) if train_med != 0 else float('inf')
            match = "OK" if 0.3 <= ratio <= 3.0 else "!!"

        if match == "!!":
            mismatches.append((feat, cap_med, train_med))

        print(f"{feat:<25} {cap_med:>18.2f} {train_med:>18.2f} {'  ' + match:>8} {cap_mean:>16.2f} {train_mean:>16.2f}")

    print(f"\n{'='*100}")
    if mismatches:
        print(f"\n  [!] MISMATCHED FEATURES ({len(mismatches)}):")
        print(f"  {'-'*80}")
        for feat, cap_val, train_val in mismatches:
            if isinstance(cap_val, str):
                print(f"  {feat:<30} Captured: {cap_val:<15} Training: {train_val:.2f}")
            else:
                print(f"  {feat:<30} Captured: {cap_val:<15.2f} Training: {train_val:.2f}")
        print(f"\n  These features are likely causing GREEN (Benign) classification.")
        print(f"  The model expects values close to the Training column for DoS-Hulk.\n")
    else:
        print(f"\n  [OK] All key features look reasonable!\n")

    return mismatches


def show_distributions(captured_df, training_df, features, top_n=10):
    """Show detailed distributions for the most important features."""
    print(f"\n{'='*100}")
    print(f"  DETAILED DISTRIBUTIONS (Top {top_n} features)")
    print(f"{'='*100}\n")

    count = 0
    for feat in features:
        if feat not in captured_df.columns or feat not in training_df.columns:
            continue
        if count >= top_n:
            break

        cap_vals = pd.to_numeric(captured_df[feat], errors="coerce").dropna()
        train_vals = pd.to_numeric(training_df[feat], errors="coerce").dropna()

        if len(cap_vals) == 0:
            continue

        count += 1
        print(f"  {feat}:")
        print(f"    Captured  - min={cap_vals.min():.2f}  25%={cap_vals.quantile(0.25):.2f}  "
              f"median={cap_vals.median():.2f}  75%={cap_vals.quantile(0.75):.2f}  max={cap_vals.max():.2f}")
        print(f"    Training  - min={train_vals.min():.2f}  25%={train_vals.quantile(0.25):.2f}  "
              f"median={train_vals.median():.2f}  75%={train_vals.quantile(0.75):.2f}  max={train_vals.max():.2f}")

        # Show value counts for low-cardinality features
        if cap_vals.nunique() <= 10:
            vc = cap_vals.value_counts().head(5)
            vc_str = ", ".join(f"{v}={c}" for v, c in vc.items())
            print(f"    Captured value counts: {vc_str}")
        print()


def run_model_test(captured_df):
    """Run the captured flows through the model to see predictions."""
    import joblib

    model_dir = os.path.join(PROJECT_ROOT, "trained_model")
    model = joblib.load(os.path.join(model_dir, "random_forest_model.joblib"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
    selected_features = joblib.load(os.path.join(model_dir, "selected_features.joblib"))
    label_encoder = joblib.load(os.path.join(model_dir, "label_encoder.joblib"))

    scaler_features = list(scaler.feature_names_in_)

    # Preprocess like the pipeline does
    df = captured_df.copy()

    # Drop identifier columns
    drop_cols = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Timestamp", "Label"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')

    # Extract and one-hot encode Protocol
    if "Protocol" in df.columns:
        protocol_vals = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0).astype(int)
        df = df.drop(columns=["Protocol"])
    else:
        protocol_vals = pd.Series([0] * len(df), dtype=int)

    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    df["Protocol_0"] = (protocol_vals.values == 0).astype(int)
    df["Protocol_17"] = (protocol_vals.values == 17).astype(int)
    df["Protocol_6"] = (protocol_vals.values == 6).astype(int)

    # Build 80-feature matrix
    full_df = pd.DataFrame(0.0, index=range(len(df)), columns=scaler_features)
    common_cols = [c for c in scaler_features if c in df.columns]
    if common_cols:
        full_df[common_cols] = df[common_cols].values

    # Scale
    features_scaled = scaler.transform(full_df)

    # Select features
    selected_indices = [scaler_features.index(f) for f in selected_features]
    final_features = features_scaled[:, selected_indices]

    # Predict
    probas = model.predict_proba(final_features)
    classes = label_encoder.classes_

    # Summarize predictions
    print(f"\n{'='*100}")
    print(f"  MODEL PREDICTIONS ON CAPTURED FLOWS")
    print(f"{'='*100}")

    predicted = classes[np.argmax(probas, axis=1)]
    for cls in classes:
        count = (predicted == cls).sum()
        pct = count / len(predicted) * 100
        print(f"  {cls:<20} {count:>6} flows ({pct:>5.1f}%)")

    # Show confidence distribution for DoS predictions
    dos_mask = predicted == "DoS"
    benign_mask = predicted == "Benign"

    if dos_mask.any():
        dos_confs = np.max(probas[dos_mask], axis=1)
        print(f"\n  DoS confidence: min={dos_confs.min():.3f}  median={np.median(dos_confs):.3f}  max={dos_confs.max():.3f}")

    if benign_mask.any():
        ben_confs = np.max(probas[benign_mask], axis=1)
        print(f"  Benign confidence: min={ben_confs.min():.3f}  median={np.median(ben_confs):.3f}  max={ben_confs.max():.3f}")

        # For Benign-predicted, what's the 2nd highest class?
        ben_probas = probas[benign_mask]
        benign_idx = list(classes).index("Benign")
        ben_probas_no_benign = ben_probas.copy()
        ben_probas_no_benign[:, benign_idx] = 0
        second_class_idx = np.argmax(ben_probas_no_benign, axis=1)
        second_confs = np.max(ben_probas_no_benign, axis=1)

        print(f"\n  For Benign-predicted flows, 2nd highest class distribution:")
        for cls_idx, cls_name in enumerate(classes):
            if cls_name == "Benign":
                continue
            mask = second_class_idx == cls_idx
            if mask.any():
                count = mask.sum()
                avg_conf = second_confs[mask].mean()
                print(f"    2nd={cls_name:<15} {count:>5} flows  avg_conf={avg_conf:.3f}")

    # Threat level assessment
    print(f"\n  THREAT LEVELS (using same logic as live classification):")
    red = yellow = green = 0
    for i in range(len(probas)):
        top_idx = np.argsort(-probas[i])
        top_class = classes[top_idx[0]]
        top_conf = probas[i][top_idx[0]]

        if top_class != "Benign":
            red += 1
        elif len(top_idx) >= 2:
            second_class = classes[top_idx[1]]
            second_conf = probas[i][top_idx[1]]
            if second_class != "Benign" and second_conf >= 0.25:
                yellow += 1
            else:
                green += 1
        else:
            green += 1

    total = red + yellow + green
    print(f"    RED:    {red:>6} ({red/total*100:.1f}%)")
    print(f"    YELLOW: {yellow:>6} ({yellow/total*100:.1f}%)")
    print(f"    GREEN:  {green:>6} ({green/total*100:.1f}%)")
    print(f"    Total:  {total:>6}")
    print()


def main():
    # Find captured flows CSV
    if len(sys.argv) > 1:
        csv_path = sys.argv[1]
    else:
        csv_path = find_latest_flows()
        if csv_path is None:
            print("[!] No captured flows found in data/captured_flows/")
            print("[!] Run classification with --save-flows first:")
            print("    python classification.py --vm --save-flows --duration 300")
            return

    if not os.path.exists(csv_path):
        print(f"[!] File not found: {csv_path}")
        return

    print(f"\n{'='*100}")
    print(f"  FLOW COMPARISON TOOL")
    print(f"{'='*100}")
    print(f"  Captured flows: {csv_path}")

    # Load captured flows
    captured_df = pd.read_csv(csv_path, low_memory=False)
    captured_df.columns = captured_df.columns.str.strip()
    print(f"  Loaded: {len(captured_df):,} flows, {len(captured_df.columns)} columns")
    print(f"  Columns: {', '.join(captured_df.columns[:15])}{'...' if len(captured_df.columns) > 15 else ''}")

    # Load training data
    training_df = load_training_dos_hulk()
    if training_df is None:
        print("[!] Cannot load training data for comparison")
        return

    # Compare features
    mismatches = compare_features(captured_df, training_df, KEY_FEATURES)

    # Show detailed distributions
    show_distributions(captured_df, training_df, KEY_FEATURES, top_n=15)

    # Run model predictions
    try:
        run_model_test(captured_df)
    except Exception as e:
        print(f"[!] Model test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
