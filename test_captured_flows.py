#!/usr/bin/env python
"""
Test Classification - Run captured flows through proper classification pipeline
Uses the actual classification/preprocessor.py for feature preprocessing
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings("ignore")

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def main():
    # Determine paths based on OS
    if sys.platform.startswith('win'):
        csv_file = r"z:\Nids\temp\flow_capture2.csv"
        model_path = r"z:\Nids\trained_model"
    else:
        csv_file = os.path.expanduser("~/Nids/temp/flow_capture2.csv")
        model_path = os.path.expanduser("~/Nids/trained_model")
    
    if not os.path.exists(csv_file):
        print(f"ERROR: {csv_file} not found")
        return
    
    # Read CSV
    df = pd.read_csv(csv_file)
    print(f"\nLoaded {len(df)} flows from {csv_file}\n")
    
    # Load training artifacts
    print("Loading trained model artifacts...")
    
    model = joblib.load(os.path.join(model_path, "random_forest_model.joblib"))
    scaler = joblib.load(os.path.join(model_path, "scaler.joblib"))
    label_encoder = joblib.load(os.path.join(model_path, "label_encoder.joblib"))
    selected_features_data = joblib.load(os.path.join(model_path, "selected_features.joblib"))
    
    # Convert selected_features to list
    if isinstance(selected_features_data, np.ndarray):
        selected_features_list = selected_features_data.tolist()
    else:
        selected_features_list = list(selected_features_data)
    
    print(f"  Model features (selected): {len(selected_features_list)}")
    print(f"  Sample selected features: {selected_features_list[:5]}")
    print(f"  Scaler expects: {len(scaler.feature_names_in_)} features")
    print(f"  Classes: {label_encoder.classes_}\n")
    
    # Get feature names from scaler
    scaler_feature_names = scaler.feature_names_in_
    
    # Map feature names to indices for selection
    feature_name_to_idx = {name: idx for idx, name in enumerate(scaler_feature_names)}
    selected_indices = [feature_name_to_idx[fname] for fname in selected_features_list]
    
    print(f"Scaler column order (first 10):\n  {list(scaler_feature_names[:10])}\n")
    
    # Drop the identifier column
    feature_columns = [c for c in df.columns if c != "__identifiers__"]
    
    # Drop identifiers that aren't model features
    identifier_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp']
    df_features = df[feature_columns].copy()
    df_features = df_features.drop(columns=[c for c in identifier_cols if c in df_features.columns], errors='ignore')
    
    print(f"Feature columns available in CSV: {len(df_features.columns)}")
    print(f"  {list(df_features.columns)[:10]}...\n")
    
    # Preprocess: prepare 80-feature DataFrame in scaler's expected order
    print("Preprocessing flows...")
    
    # Initialize with all zeros in scaler's expected format
    df_scaled_input = pd.DataFrame(0.0, index=range(len(df_features)), columns=scaler_feature_names)
    
    # Fill in available columns
    for col in scaler_feature_names:
        if col in df_features.columns:
            df_scaled_input[col] = df_features[col].values
    
    print(f"  Input to scaler: {df_scaled_input.shape}")
    
    # Check for any all-zero columns (missing features)
    missing_cols = []
    for col in scaler_feature_names:
        if (df_scaled_input[col] == 0).all():
            missing_cols.append(col)
    
    if missing_cols:
        print(f"  WARNING: {len(missing_cols)} columns are all-zero (missing from capture):")
        for col in missing_cols[:5]:
            print(f"    - {col}")
        if len(missing_cols) > 5:
            print(f"    ... and {len(missing_cols) - 5} more")
    
    # Scale
    print(f"\nScaling {len(df_scaled_input)} flows...")
    df_scaled = scaler.transform(df_scaled_input)
    
    # Select features - use numpy array indexing with indices
    selected_features_array = np.array(selected_indices, dtype=int)
    df_final = df_scaled[:, selected_features_array]
    print(f"After feature selection: {df_final.shape}")
    
    # Predict
    print(f"\nRunning predictions...")
    proba = model.predict_proba(df_final)
    predictions = model.predict(df_final)
    
    # Decode labels
    pred_labels = label_encoder.inverse_transform(predictions)
    
    print(f"\n{'='*80}")
    print(f"CLASSIFICATION RESULTS - {len(predictions)} flows classified")
    print(f"{'='*80}\n")
    
    # Create results dataframe
    results = []
    for i, (row, pred, prob, label) in enumerate(zip(df.to_dict('records'), predictions, proba, pred_labels)):
        # Get top-3 predictions
        top3_indices = np.argsort(prob)[::-1][:3]
        top3 = [(label_encoder.inverse_transform([idx])[0], prob[idx]) for idx in top3_indices]
        
        results.append({
            'dst_port': row['Dst Port'],
            'protocol': row['Protocol'],
            'src_port': row['Src Port'],
            'flow_duration': row['Flow Duration'],
            'prediction': label,
            'confidence': prob.max(),
            'top3': str(top3),
        })
    
    # Breakdown by prediction
    pred_counts = {}
    for r in results:
        label = r['prediction']
        if label not in pred_counts:
            pred_counts[label] = 0
        pred_counts[label] += 1
    
    print("Prediction Breakdown:")
    for label, count in sorted(pred_counts.items(), key=lambda x: -x[1]):
        pct = 100.0 * count / len(results)
        print(f"  {label:20s}: {count:3d} flows ({pct:5.1f}%)")
    
    # Breakdown by port
    print(f"\nBreakdown by Destination Port:")
    port_preds = {}
    for r in results:
        port = int(r['dst_port'])
        if port not in port_preds:
            port_preds[port] = {}
        label = r['prediction']
        if label not in port_preds[port]:
            port_preds[port][label] = 0
        port_preds[port][label] += 1
    
    for port in sorted(port_preds.keys()):
        print(f"\n  Port {port:5d}:")
        for label, count in sorted(port_preds[port].items(), key=lambda x: -x[1]):
            pct = 100.0 * count / sum(port_preds[port].values())
            print(f"    {label:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Confidence analysis
    print(f"\nConfidence Statistics:")
    confidences = [r['confidence'] for r in results]
    print(f"  Mean confidence:   {np.mean(confidences):.3f}")
    print(f"  Median confidence: {np.median(confidences):.3f}")
    print(f"  Min confidence:    {np.min(confidences):.3f}")
    print(f"  Max confidence:    {np.max(confidences):.3f}")
    print(f"  High confidence (>0.9): {sum(1 for c in confidences if c > 0.9)}/{len(confidences)}")
    
    # Flow duration analysis for HTTP flows
    http_flows = [r for r in results if int(r['dst_port']) == 80]
    if http_flows:
        print(f"\nHTTP Flows (Port 80) Analysis:")
        durations = [r['flow_duration'] for r in http_flows]
        print(f"  Count: {len(http_flows)}")
        print(f"  Avg duration: {np.mean(durations):.1f} ms")
        print(f"  Min duration: {np.min(durations):.1f} ms")
        print(f"  Max duration: {np.max(durations):.1f} ms")
        
        print(f"\n  Top predictions for HTTP flows:")
        http_preds = {}
        for r in http_flows:
            label = r['prediction']
            if label not in http_preds:
                http_preds[label] = 0
            http_preds[label] += 1
        for label, count in sorted(http_preds.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / len(http_flows)
            print(f"    {label:20s}: {count:3d} ({pct:5.1f}%)")
    
    # UDP flows analysis
    udp_flows = [r for r in results if int(r['protocol']) == 17]
    if udp_flows:
        print(f"\nUDP Flows Analysis:")
        print(f"  Count: {len(udp_flows)}")
        print(f"  Top predictions:")
        udp_preds = {}
        for r in udp_flows:
            label = r['prediction']
            if label not in udp_preds:
                udp_preds[label] = 0
            udp_preds[label] += 1
        for label, count in sorted(udp_preds.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / len(udp_flows)
            print(f"    {label:20s}: {count:3d} ({pct:5.1f}%)")
    
    # Export detailed results
    results_df = pd.DataFrame(results)
    if sys.platform.startswith('win'):
        results_file = r"z:\Nids\temp\classification_results.csv"
    else:
        results_file = os.path.expanduser("~/Nids/temp/classification_results.csv")
    
    results_df.to_csv(results_file, index=False)
    print(f"\n{'='*80}")
    print(f"Detailed results saved to: {results_file}")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
