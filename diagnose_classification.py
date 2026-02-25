#!/usr/bin/env python
"""
Diagnostic script to identify why DoS attacks are classified as Benign.

Run on the VICTIM VM after a classification session:
    python diagnose_classification.py

Or point to a specific report:
    python diagnose_classification.py --report reports/live_default_2026-02-26_00-33-29
"""

import os
import sys
import re
import socket
import platform
import argparse
import glob
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def test_1_so_rcvbuf():
    """Test what TCP window actually results from various SO_RCVBUF settings."""
    print("\n" + "=" * 70)
    print("  TEST 1: SO_RCVBUF Behavior on This System")
    print("=" * 70)
    print(f"  OS: {platform.system()} {platform.release()}")
    print()

    test_values = [225, 2053, 8192, 26883, 32738, 49136, 65535]
    print(f"  {'Requested SO_RCVBUF':>25} | {'Actual SO_RCVBUF':>20} | {'Ratio':>8}")
    print("  " + "-" * 60)

    for val in test_values:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, val)
            actual = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            s.close()
            ratio = actual / val if val > 0 else 0
            marker = " <<<< DIFFERENT!" if actual != val else ""
            print(f"  {val:>25} | {actual:>20} | {ratio:>8.2f}{marker}")
        except Exception as e:
            print(f"  {val:>25} | ERROR: {e}")

    print()
    print("  KEY INSIGHT: On Linux, the kernel DOUBLES SO_RCVBUF and enforces a")
    print("  minimum (~2304 bytes). The TCP SYN window will be based on the")
    print("  ACTUAL value, not the requested value.")
    print()
    print("  The training data has Init Fwd Win Byts = 225 for HULK.")
    print("  If SO_RCVBUF=225 results in actual=2304+, the TCP window will NOT")
    print("  be 225 and the model will see a very different feature value.")


def test_2_model_predictions():
    """Test model with synthetic ideal DoS features to verify model CAN detect DoS."""
    print("\n" + "=" * 70)
    print("  TEST 2: Model Response to Ideal DoS Features")
    print("=" * 70)

    try:
        import joblib
        import pandas as pd
    except ImportError:
        print("  ERROR: joblib/pandas not available. Run in venv.")
        return

    model_dir = os.path.join(PROJECT_ROOT, "trained_model")
    if not os.path.exists(model_dir):
        print(f"  ERROR: {model_dir} not found")
        return

    model = joblib.load(os.path.join(model_dir, "random_forest_model.joblib"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
    le = joblib.load(os.path.join(model_dir, "label_encoder.joblib"))
    selected_features = joblib.load(os.path.join(model_dir, "selected_features.joblib"))
    scaler_features = list(scaler.feature_names_in_)

    print(f"  Model classes: {list(le.classes_)}")
    print(f"  Selected features: {len(selected_features)}")
    print()

    # Create synthetic "ideal HULK" feature vector matching training data distributions
    # These are the RAW (pre-scaled) values we expect CICFlowMeter to produce
    hulk_ideal = {
        "Fwd Seg Size Min": 32,         # TCP with timestamps (Linux)
        "Dst Port": 80,                 # HTTP
        "TotLen Fwd Pkts": 0,           # 60% of HULK = no payload
        "Init Fwd Win Byts": 225,       # HULK training median
        "Pkt Len Max": 0,
        "Tot Bwd Pkts": 0,              # Server overwhelmed, no response
        "Tot Fwd Pkts": 2,              # SYN + ACK
        "Bwd Pkt Len Max": 0,
        "Bwd Pkt Len Std": 0,
        "Fwd Pkt Len Std": 0,
        "Fwd Pkt Len Max": 0,
        "Fwd Pkt Len Mean": 0,
        "Flow Duration": 7737,          # ~8ms in microseconds
        "Pkt Len Std": 0,
        "Pkt Len Var": 0,
        "Bwd Pkt Len Mean": 0,
        "Pkt Len Mean": 0,
        "Flow IAT Mean": 7737,
        "Fwd Pkts/s": 268000,           # Training median
        "Flow IAT Max": 7737,
        "Init Bwd Win Byts": 0,
        "Bwd Pkts/s": 0,
        "Bwd IAT Std": 0,
        "Flow Pkts/s": 268000,
        "Bwd IAT Max": 0,
        "RST Flag Cnt": 0,
        "Flow IAT Min": 7737,
        "Idle Min": 0,
        "Idle Mean": 0,
        "Bwd IAT Min": 0,
        "Flow Byts/s": 0,
        "Bwd IAT Mean": 0,
        "ACK Flag Cnt": 1,
        "Flow IAT Std": 0,
        "Bwd IAT Tot": 0,
        "Down/Up Ratio": 0,
        "PSH Flag Cnt": 0,
        "Protocol_6": 1,                # TCP
        "Protocol_0": 0,
        "URG Flag Cnt": 0,
    }

    test_cases = [
        ("Ideal HULK (Init Fwd Win=225)", hulk_ideal),
    ]

    # Test with different Init Fwd Win Byts to see sensitivity
    for win_val in [225, 450, 2304, 4096, 26883, 29200]:
        case = hulk_ideal.copy()
        case["Init Fwd Win Byts"] = win_val
        test_cases.append((f"HULK with Init Fwd Win={win_val}", case))

    # Test with a "real Linux default" scenario
    linux_default = hulk_ideal.copy()
    linux_default["Init Fwd Win Byts"] = 29200  # Common Linux default
    linux_default["Tot Fwd Pkts"] = 4
    linux_default["TotLen Fwd Pkts"] = 200
    linux_default["Flow Duration"] = 50000
    test_cases.append(("HULK-like but Linux default window", linux_default))

    print(f"  {'Test Case':<45} | {'Prediction':>12} | {'Confidence':>10} | {'2nd':>12} | {'2nd Conf':>10}")
    print("  " + "-" * 100)

    for name, features in test_cases:
        # Build full feature vector
        full = pd.DataFrame(0.0, index=[0], columns=scaler_features)
        for f, v in features.items():
            if f in scaler_features:
                full.at[0, f] = v

        # Scale
        scaled = scaler.transform(full)

        # Select features
        selected_indices = [scaler_features.index(f) for f in selected_features]
        final = scaled[:, selected_indices]

        # Predict
        proba = model.predict_proba(final)[0]
        classes = list(le.classes_)
        preds = sorted(zip(classes, proba), key=lambda x: x[1], reverse=True)

        top_class, top_conf = preds[0]
        sec_class, sec_conf = preds[1]
        marker = " ✓ DoS" if top_class == "DoS" else " ✗ WRONG" if "HULK" in name or "HULK" in name.upper() else ""
        print(f"  {name:<45} | {top_class:>12} | {top_conf:>9.1%} | {sec_class:>12} | {sec_conf:>9.1%}{marker}")

    print()


def test_3_parse_report(report_dir):
    """Parse a classification report to analyze what's happening with the actual flows."""
    print("\n" + "=" * 70)
    print("  TEST 3: Analyze Classification Report")
    print("=" * 70)

    if not report_dir:
        # Find the latest report
        reports_dir = os.path.join(PROJECT_ROOT, "reports")
        if not os.path.exists(reports_dir):
            print("  No reports/ directory found. Run a classification session first.")
            return
        sessions = sorted(glob.glob(os.path.join(reports_dir, "live_*")))
        if not sessions:
            sessions = sorted(glob.glob(os.path.join(reports_dir, "*")))
        if not sessions:
            print("  No report sessions found in reports/")
            return
        report_dir = sessions[-1]

    print(f"  Report: {report_dir}")

    minute_files = sorted(glob.glob(os.path.join(report_dir, "minute_*.txt")))
    if not minute_files:
        print("  No minute files found in report directory")
        return

    # Parse all flows from minute files
    flows = []
    for mf in minute_files:
        with open(mf, "r") as f:
            in_table = False
            for line in f:
                line = line.rstrip()
                if "---+---" in line or "---+-" in line:
                    in_table = True
                    continue
                if not in_table:
                    continue
                if not line.strip() or line.startswith("=") or line.startswith("-"):
                    if "Minute Summary" in line or "Total flows" in line:
                        in_table = False
                    continue

                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 12:
                    try:
                        flow = {
                            "timestamp": parts[0],
                            "src_ip": parts[1],
                            "src_port": parts[2],
                            "dst_ip": parts[3],
                            "dst_port": parts[4],
                            "protocol": parts[5],
                            "top1_class": parts[6],
                            "top1_conf": parts[7],
                            "top2_class": parts[8],
                            "top2_conf": parts[9],
                            "top3_class": parts[10],
                            "top3_conf": parts[11],
                        }
                        flows.append(flow)
                    except (IndexError, ValueError):
                        pass

    if not flows:
        print("  Could not parse any flows from minute files")
        print("  (Report format may differ — check minute files manually)")
        return

    print(f"  Total flows parsed: {len(flows)}")
    print()

    # Analyze by destination port
    by_port = {}
    for f in flows:
        port = f["dst_port"]
        if port not in by_port:
            by_port[port] = {"total": 0, "top1_classes": {}, "top1_confs": [], "top2_classes": {}}
        by_port[port]["total"] += 1

        cls = f["top1_class"]
        by_port[port]["top1_classes"][cls] = by_port[port]["top1_classes"].get(cls, 0) + 1

        try:
            conf = float(f["top1_conf"].replace("%", "")) / 100
            by_port[port]["top1_confs"].append(conf)
        except ValueError:
            pass

        cls2 = f["top2_class"]
        by_port[port]["top2_classes"][cls2] = by_port[port]["top2_classes"].get(cls2, 0) + 1

    print("  Breakdown by Destination Port:")
    print(f"  {'Port':<8} | {'Count':>6} | {'Top-1 Predictions':>40} | {'Top-2 Predictions':>40}")
    print("  " + "-" * 105)
    for port in sorted(by_port.keys(), key=lambda p: by_port[p]["total"], reverse=True)[:15]:
        info = by_port[port]
        top1_str = ", ".join(f"{c}:{n}" for c, n in sorted(info["top1_classes"].items(), key=lambda x: -x[1]))
        top2_str = ", ".join(f"{c}:{n}" for c, n in sorted(info["top2_classes"].items(), key=lambda x: -x[1]))
        print(f"  {port:<8} | {info['total']:>6} | {top1_str:>40} | {top2_str:>40}")

    # Port 80 specific analysis
    port80_flows = [f for f in flows if f["dst_port"].strip() == "80"]
    if port80_flows:
        print(f"\n  Port 80 flows (attack target): {len(port80_flows)}")

        # Show confidence distribution for port 80
        confs = []
        dos_as_2nd = 0
        dos_as_2nd_confs = []
        for f in port80_flows:
            try:
                conf = float(f["top1_conf"].replace("%", ""))
                confs.append(conf)
            except ValueError:
                pass

            if "DoS" in f["top2_class"] or "DDoS" in f["top2_class"]:
                dos_as_2nd += 1
                try:
                    c2 = float(f["top2_conf"].replace("%", ""))
                    dos_as_2nd_confs.append(c2)
                except ValueError:
                    pass

        if confs:
            print(f"  Top-1 confidence (Benign): mean={np.mean(confs):.1f}%, "
                  f"min={min(confs):.1f}%, max={max(confs):.1f}%")
        if dos_as_2nd > 0:
            print(f"  DoS/DDoS as 2nd prediction: {dos_as_2nd}/{len(port80_flows)} flows")
            if dos_as_2nd_confs:
                print(f"  DoS 2nd-place confidence: mean={np.mean(dos_as_2nd_confs):.1f}%, "
                      f"max={max(dos_as_2nd_confs):.1f}%")

        # Show sample port 80 flows
        print(f"\n  Sample port 80 flows (first 10):")
        print(f"  {'Src IP':<18} {'SrcPort':<8} {'Top1':>10} {'Conf':>7} {'Top2':>10} {'Conf':>7} {'Top3':>10} {'Conf':>7}")
        print("  " + "-" * 90)
        for f in port80_flows[:10]:
            print(f"  {f['src_ip']:<18} {f['src_port']:<8} "
                  f"{f['top1_class']:>10} {f['top1_conf']:>7} "
                  f"{f['top2_class']:>10} {f['top2_conf']:>7} "
                  f"{f['top3_class']:>10} {f['top3_conf']:>7}")


def test_4_feature_sensitivity():
    """Show which feature changes have the biggest impact on DoS vs Benign prediction."""
    print("\n" + "=" * 70)
    print("  TEST 4: Feature Sensitivity Analysis (DoS vs Benign)")
    print("=" * 70)

    try:
        import joblib
        import pandas as pd
    except ImportError:
        print("  ERROR: joblib/pandas not available")
        return

    model_dir = os.path.join(PROJECT_ROOT, "trained_model")
    model = joblib.load(os.path.join(model_dir, "random_forest_model.joblib"))
    scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
    le = joblib.load(os.path.join(model_dir, "label_encoder.joblib"))
    selected_features = joblib.load(os.path.join(model_dir, "selected_features.joblib"))
    scaler_features = list(scaler.feature_names_in_)
    selected_indices = [scaler_features.index(f) for f in selected_features]

    dos_idx = list(le.classes_).index("DoS") if "DoS" in le.classes_ else None
    benign_idx = list(le.classes_).index("Benign") if "Benign" in le.classes_ else None
    if dos_idx is None or benign_idx is None:
        print("  ERROR: DoS or Benign class not found")
        return

    # Baseline: a "realistic Linux attacker" HULK flow
    # This is what we THINK CICFlowMeter produces on the victim
    baseline = {f: 0.0 for f in scaler_features}
    baseline["Fwd Seg Size Min"] = 32
    baseline["Dst Port"] = 80
    baseline["Tot Fwd Pkts"] = 2
    baseline["TotLen Fwd Pkts"] = 0
    baseline["Tot Bwd Pkts"] = 0
    baseline["Flow Duration"] = 7737
    baseline["Init Fwd Win Byts"] = 225
    baseline["Init Bwd Win Byts"] = 0
    baseline["Protocol_6"] = 1
    baseline["ACK Flag Cnt"] = 1
    baseline["Fwd Pkts/s"] = 268000
    baseline["Flow Pkts/s"] = 268000
    baseline["Flow IAT Mean"] = 7737
    baseline["Flow IAT Max"] = 7737
    baseline["Flow IAT Min"] = 7737

    def predict_one(features_dict):
        full = pd.DataFrame(0.0, index=[0], columns=scaler_features)
        for f, v in features_dict.items():
            if f in scaler_features:
                full.at[0, f] = v
        scaled = scaler.transform(full)
        final = scaled[:, selected_indices]
        proba = model.predict_proba(final)[0]
        return proba[dos_idx], proba[benign_idx]

    base_dos, base_benign = predict_one(baseline)
    print(f"\n  Baseline (ideal HULK): Benign={base_benign:.1%}, DoS={base_dos:.1%}")
    print()

    # Now vary each key feature and see impact
    variations = [
        ("Init Fwd Win Byts", [225, 450, 2304, 4096, 8192, 26883, 29200, 65535]),
        ("Fwd Seg Size Min", [20, 32, 40]),
        ("Dst Port", [21, 80, 443, 8080, 22]),
        ("Tot Fwd Pkts", [1, 2, 3, 5, 10, 50]),
        ("TotLen Fwd Pkts", [0, 100, 200, 500, 1000]),
        ("Tot Bwd Pkts", [0, 1, 2, 3, 5]),
        ("Flow Duration", [3, 100, 7737, 50000, 1000000, 6767520, 15000000]),
        ("Init Bwd Win Byts", [0, 225, 26883, 29200, 65535]),
        ("Fwd Pkts/s", [100, 1000, 10000, 100000, 268000, 333333]),
        ("Flow Pkts/s", [100, 1000, 10000, 100000, 268000, 666667]),
        ("PSH Flag Cnt", [0, 1]),
        ("RST Flag Cnt", [0, 1]),
        ("ACK Flag Cnt", [0, 1]),
        ("Down/Up Ratio", [0, 1]),
    ]

    print(f"  Feature sensitivity (how each value changes DoS probability):")
    print(f"  {'Feature':<25} | {'Value':>12} | {'DoS Prob':>10} | {'Benign Prob':>10} | {'Delta DoS':>10}")
    print("  " + "-" * 80)

    for feat_name, values in variations:
        for val in values:
            test = baseline.copy()
            test[feat_name] = val
            dos_p, benign_p = predict_one(test)
            delta = dos_p - base_dos
            marker = " <<<" if abs(delta) > 0.05 else ""
            is_baseline = (val == baseline.get(feat_name, None))
            base_mark = " [BASE]" if is_baseline else ""
            print(f"  {feat_name:<25} | {val:>12.0f} | {dos_p:>9.1%} | {benign_p:>9.1%} | {delta:>+9.1%}{marker}{base_mark}")
        print("  " + "-" * 80)


def main():
    parser = argparse.ArgumentParser(description="Diagnose NIDS classification issues")
    parser.add_argument("--report", type=str, default=None, help="Path to report directory")
    parser.add_argument("--test", type=str, default="all",
                        help="Which tests to run: all, rcvbuf, model, report, sensitivity")
    args = parser.parse_args()

    print("=" * 70)
    print("  NIDS Classification Diagnostic")
    print("=" * 70)

    tests = args.test.split(",") if args.test != "all" else ["rcvbuf", "model", "report", "sensitivity"]

    if "rcvbuf" in tests:
        test_1_so_rcvbuf()

    if "model" in tests:
        test_2_model_predictions()

    if "report" in tests:
        test_3_parse_report(args.report)

    if "sensitivity" in tests:
        test_4_feature_sensitivity()

    print("\n" + "=" * 70)
    print("  DIAGNOSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
