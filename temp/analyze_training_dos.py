"""Analyze ACTUAL CICIDS2018 training data for DoS-Hulk flows.
Compare with what our attack produces to find the gap."""

import pandas as pd
import numpy as np
import joblib
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Key features (top 40 used by model)
KEY_FEATURES = [
    "Fwd Seg Size Min", "Dst Port", "TotLen Fwd Pkts", "Init Fwd Win Byts",
    "Pkt Len Max", "Tot Bwd Pkts", "Tot Fwd Pkts", "Bwd Pkt Len Max",
    "Bwd Pkt Len Std", "Fwd Pkt Len Std", "Fwd Pkt Len Max", "Fwd Pkt Len Mean",
    "Flow Duration", "Pkt Len Std", "Pkt Len Var", "Bwd Pkt Len Mean",
    "Pkt Len Mean", "Flow IAT Mean", "Fwd Pkts/s", "Flow IAT Max",
    "Init Bwd Win Byts", "Bwd Pkts/s", "Bwd IAT Std", "Flow Pkts/s",
    "Bwd IAT Max", "RST Flag Cnt", "Flow IAT Min", "Idle Min",
    "Idle Mean", "Bwd IAT Min", "Flow Byts/s", "Bwd IAT Mean",
    "ACK Flag Cnt", "Flow IAT Std", "Bwd IAT Tot", "Down/Up Ratio",
    "PSH Flag Cnt", "URG Flag Cnt", "Active Mean", "Pkt Len Min",
]

print("=" * 80)
print("  CICIDS2018 HULK TRAINING DATA ANALYSIS")
print("=" * 80)

# Load data
print("\n[1] Loading Friday-16-02-2018 (DoS-Hulk day)...")
df = pd.read_csv(os.path.join(PROJECT_ROOT, "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"), low_memory=False)
df = df[df['Label'] != 'Label']  # Remove header row duplicates

hulk = df[df['Label'] == 'DoS attacks-Hulk'].copy()
benign = df[df['Label'] == 'Benign'].copy()

# Convert numeric
for col in KEY_FEATURES:
    if col in hulk.columns:
        hulk[col] = pd.to_numeric(hulk[col], errors='coerce')
        benign[col] = pd.to_numeric(benign[col], errors='coerce')

print(f"  HULK flows: {len(hulk):,}")
print(f"  Benign flows: {len(benign):,}")

# Show distributions for key features
print(f"\n[2] HULK vs Benign feature distributions (key features):")
print(f"{'Feature':<25} | {'HULK median':>12} | {'HULK p25':>10} | {'HULK p75':>10} | {'Benign med':>12} | {'Separation':>10}")
print("-" * 95)

for feat in KEY_FEATURES:
    if feat not in hulk.columns:
        continue
    h = hulk[feat].dropna()
    b = benign[feat].dropna()
    if len(h) == 0 or len(b) == 0:
        continue
    h_med = h.median()
    h_p25 = h.quantile(0.25)
    h_p75 = h.quantile(0.75)
    b_med = b.median()
    
    # Mark features where HULK differs strongly from Benign
    if b_med != 0:
        ratio = h_med / b_med if b_med != 0 else float('inf')
    else:
        ratio = float('inf') if h_med != 0 else 1.0
    marker = " ***" if abs(h_med - b_med) > 0.1 * max(abs(h_med), abs(b_med), 1) else ""
    
    print(f"{feat:<25} | {h_med:>12.1f} | {h_p25:>10.1f} | {h_p75:>10.1f} | {b_med:>12.1f}{marker}")

# Critical: Init Fwd Win Byts distribution
print(f"\n[3] Init Fwd Win Byts distribution for HULK:")
h_win = hulk['Init Fwd Win Byts'].dropna()
print(f"  Value counts (top 10):")
vc = h_win.value_counts().head(10)
for val, cnt in vc.items():
    print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_win)*100:>5.1f}%)")

print(f"\n  Percentiles:")
for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
    print(f"    p{p:>2}: {h_win.quantile(p/100):>10.0f}")

# Critical: Tot Bwd Pkts distribution for HULK
print(f"\n[4] Tot Bwd Pkts distribution for HULK:")
h_bwd = hulk['Tot Bwd Pkts'].dropna()
print(f"  Value counts (top 10):")
vc = h_bwd.value_counts().head(10)
for val, cnt in vc.items():
    print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_bwd)*100:>5.1f}%)")

# Critical: Tot Fwd Pkts
print(f"\n[5] Tot Fwd Pkts distribution for HULK:")
h_fwd = hulk['Tot Fwd Pkts'].dropna()
print(f"  Value counts (top 10):")
vc = h_fwd.value_counts().head(10)
for val, cnt in vc.items():
    print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_fwd)*100:>5.1f}%)")

# Critical: TotLen Fwd Pkts
print(f"\n[6] TotLen Fwd Pkts distribution for HULK:")
h_totlen = hulk['TotLen Fwd Pkts'].dropna()
print(f"  Value counts (top 10):")
vc = h_totlen.value_counts().head(10)
for val, cnt in vc.items():
    print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_totlen)*100:>5.1f}%)")

# Critical: Init Bwd Win Byts
print(f"\n[7] Init Bwd Win Byts distribution for HULK:")
h_bwd_win = hulk['Init Bwd Win Byts'].dropna()
print(f"  Value counts (top 10):")
vc = h_bwd_win.value_counts().head(10)
for val, cnt in vc.items():
    print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_bwd_win)*100:>5.1f}%)")

# RST, FIN, SYN, ACK, PSH flags
for flag in ['RST Flag Cnt', 'FIN Flag Cnt', 'SYN Flag Cnt', 'ACK Flag Cnt', 'PSH Flag Cnt']:
    if flag in hulk.columns:
        h_f = hulk[flag].dropna()
        print(f"\n[*] {flag} for HULK:")
        vc = h_f.value_counts().head(5)
        for val, cnt in vc.items():
            print(f"    {val:>10.0f}: {cnt:>8,} ({cnt/len(h_f)*100:>5.1f}%)")

# Flow Duration  
print(f"\n[8] Flow Duration (µs) for HULK:")
h_dur = hulk['Flow Duration'].dropna()
print(f"  Percentiles:")
for p in [1, 5, 10, 25, 50, 75, 90, 95, 99]:
    print(f"    p{p:>2}: {h_dur.quantile(p/100):>15.0f}")

# Now test what the model predicts for ACTUAL HULK flows
print(f"\n\n{'='*80}")
print(f"  MODEL PREDICTION ON ACTUAL HULK TRAINING SAMPLES")
print(f"{'='*80}")
model = joblib.load(os.path.join(PROJECT_ROOT, "trained_model/random_forest_model.joblib"))
scaler = joblib.load(os.path.join(PROJECT_ROOT, "trained_model/scaler.joblib"))
le = joblib.load(os.path.join(PROJECT_ROOT, "trained_model/label_encoder.joblib"))
selected_features = joblib.load(os.path.join(PROJECT_ROOT, "trained_model/selected_features.joblib"))
scaler_features = list(scaler.feature_names_in_)
selected_indices = [scaler_features.index(f) for f in selected_features if f in scaler_features]

def predict(features_dict):
    full = pd.DataFrame(0.0, index=[0], columns=scaler_features)
    for f, v in features_dict.items():
        if f in scaler_features:
            full.at[0, f] = v
    scaled = scaler.transform(full)
    final = scaled[:, selected_indices]
    proba = model.predict_proba(final)[0]
    classes = list(le.classes_)
    preds = sorted(zip(classes, proba), key=lambda x: x[1], reverse=True)
    return preds

# Scenario 1: "Perfect training HULK" (server overwhelmed)
# Median values from training data
print(f"\nScenario 1: HULK ideal (training medians, server overwhelmed)")
ideal = {f: 0.0 for f in scaler_features}
ideal["Fwd Seg Size Min"] = 32
ideal["Dst Port"] = 80
ideal["TotLen Fwd Pkts"] = 0
ideal["Init Fwd Win Byts"] = 225
ideal["Tot Bwd Pkts"] = 0
ideal["Tot Fwd Pkts"] = 2
ideal["Flow Duration"] = 7737
ideal["Init Bwd Win Byts"] = 0
ideal["Protocol_6"] = 1
ideal["ACK Flag Cnt"] = 1
ideal["Fwd Pkts/s"] = 268000
ideal["Flow Pkts/s"] = 268000
ideal["Flow IAT Mean"] = 7737
ideal["Flow IAT Max"] = 7737
ideal["Flow IAT Min"] = 7737
preds = predict(ideal)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 2: OUR HULK connect+RST close (server responds with SYN-ACK)
print(f"\nScenario 2: OUR HULK (connect+RST, server responds)")
ours = ideal.copy()
ours["Tot Fwd Pkts"] = 3       # SYN + ACK + RST
ours["Tot Bwd Pkts"] = 1       # SYN-ACK
ours["Init Bwd Win Byts"] = 29200  # Server's default window
ours["Bwd Pkt Len Max"] = 60   # SYN-ACK header ~60 bytes
ours["Bwd Pkt Len Mean"] = 60
ours["Pkt Len Max"] = 60
ours["Pkt Len Mean"] = 15      # (0+0+0+60)/4
ours["Pkt Len Std"] = 26
ours["Pkt Len Var"] = 675
ours["Flow Duration"] = 300    # ~300µs for quick handshake+RST
ours["Fwd Pkts/s"] = 10000000  # Very fast
ours["Bwd Pkts/s"] = 3333333
ours["Flow Pkts/s"] = 13333333
ours["Flow IAT Mean"] = 100
ours["Flow IAT Max"] = 200
ours["Flow IAT Min"] = 50
ours["RST Flag Cnt"] = 1       # We RST close
ours["ACK Flag Cnt"] = 3       # SYN_ACK(bwd) + ACK(fwd) + RST/ACK(fwd)
ours["Down/Up Ratio"] = 0      # 0/3 = 0
ours["Bwd IAT Tot"] = 0
ours["Bwd IAT Mean"] = 0
ours["Bwd IAT Max"] = 0
ours["Bwd IAT Min"] = 0
preds = predict(ours)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 3: Same but WITHOUT RST (normal close)
print(f"\nScenario 3: OUR HULK (connect+normal close, longer exchange)")
s3 = ours.copy()
s3["Tot Fwd Pkts"] = 4         # SYN + ACK + FIN + ACK
s3["Tot Bwd Pkts"] = 2         # SYN-ACK + FIN-ACK
s3["RST Flag Cnt"] = 0
s3["FIN Flag Cnt"] = 2
s3["ACK Flag Cnt"] = 4
s3["Flow Duration"] = 1000
s3["Fwd Pkts/s"] = 4000000
s3["Bwd Pkts/s"] = 2000000
s3["Flow Pkts/s"] = 6000000
preds = predict(s3)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 4: What if window is NOT actually 225 but 29200?
print(f"\nScenario 4: OUR HULK but Init Fwd Win Byts is 29200 (route fix NOT working)")
s4 = ours.copy()
s4["Init Fwd Win Byts"] = 29200
preds = predict(s4)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 5: Same as 2 but Init Bwd Win Byts = 0 (what if server IS overwhelmed)
print(f"\nScenario 5: OUR HULK but Init Bwd Win Byts=0 (server overwhelmed)")
s5 = ours.copy()
s5["Init Bwd Win Byts"] = 0
s5["Tot Bwd Pkts"] = 0
s5["Bwd Pkt Len Max"] = 0
s5["Bwd Pkt Len Mean"] = 0
s5["Bwd Pkts/s"] = 0
s5["Pkt Len Max"] = 0
s5["Pkt Len Mean"] = 0
s5["Pkt Len Std"] = 0
s5["Pkt Len Var"] = 0
preds = predict(s5)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 6: HULK with server response + longer flow duration (like training ~8ms)
print(f"\nScenario 6: HULK connect+RST, but matching training 8ms flow duration")
s6 = ideal.copy()
s6["Tot Fwd Pkts"] = 3
s6["Tot Bwd Pkts"] = 1
s6["Init Bwd Win Byts"] = 29200
s6["Bwd Pkt Len Max"] = 60
s6["Bwd Pkt Len Mean"] = 60
s6["Pkt Len Max"] = 60
s6["Pkt Len Mean"] = 15
s6["RST Flag Cnt"] = 1
s6["ACK Flag Cnt"] = 3
# Keep training-like duration and rates
s6["Flow Duration"] = 7737
s6["Fwd Pkts/s"] = 388     # 3 pkts / 7737µs
s6["Bwd Pkts/s"] = 129
s6["Flow Pkts/s"] = 517
s6["Flow IAT Mean"] = 2579
s6["Flow IAT Max"] = 5000
s6["Flow IAT Min"] = 500
preds = predict(s6)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 7: Vary Init Fwd Win Byts systematically with server response present
print(f"\nInit Fwd Win Byts sweep (with server response present):")
for win in [225, 450, 1000, 2304, 4096, 8192, 14600, 26883, 29200, 43800, 65535]:
    test = ours.copy()
    test["Init Fwd Win Byts"] = win
    preds = predict(test)
    top = preds[0]
    sec = preds[1]
    label = 'RED' if top[0] != 'Benign' else 'YELLOW' if sec[1] >= 0.25 else 'GREEN'
    print(f"  Win={win:>6}: {top[0]:<10} {top[1]:>6.1%} | {sec[0]:<10} {sec[1]:>6.1%} -> {label}")

# Scenario 8: HULK that sends GET request (completed connection subset)
print(f"\nScenario 8: HULK with GET request (completed connection, like 40% of training)")
s8 = ideal.copy()
s8["Init Fwd Win Byts"] = 225
s8["Tot Fwd Pkts"] = 4         # SYN + ACK + GET + FIN/RST
s8["TotLen Fwd Pkts"] = 200    # GET request ~200 bytes
s8["Fwd Pkt Len Max"] = 200
s8["Fwd Pkt Len Mean"] = 50    # (0+0+200+0)/4
s8["Fwd Pkt Len Std"] = 100
s8["Tot Bwd Pkts"] = 3         # SYN-ACK + HTTP response + FIN
s8["Bwd Pkt Len Max"] = 1460   # HTTP response
s8["Bwd Pkt Len Mean"] = 500
s8["Bwd Pkt Len Std"] = 600
s8["Init Bwd Win Byts"] = 29200
s8["Flow Duration"] = 50000    # ~50ms
s8["Pkt Len Max"] = 1460
s8["Pkt Len Mean"] = 300
s8["Pkt Len Std"] = 500
s8["Pkt Len Var"] = 250000
s8["PSH Flag Cnt"] = 2         # GET push + response push
s8["ACK Flag Cnt"] = 5
s8["RST Flag Cnt"] = 1
s8["Fwd Pkts/s"] = 80000
s8["Bwd Pkts/s"] = 60000
s8["Flow Pkts/s"] = 140000
s8["Flow IAT Mean"] = 8333
s8["Flow IAT Max"] = 20000
s8["Flow IAT Min"] = 1000
s8["Flow Byts/s"] = 4000000
s8["Bwd IAT Tot"] = 20000
s8["Bwd IAT Mean"] = 10000
s8["Bwd IAT Max"] = 15000
s8["Bwd IAT Min"] = 5000
s8["Down/Up Ratio"] = 0
preds = predict(s8)
for cls, prob in preds:
    print(f"  {cls:<15} {prob:>7.1%}")
print(f"  -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

# Scenario 9: What does a training HULK that HAS backward traffic look like?
print(f"\n\n[9] Actual HULK flows that HAVE backward traffic:")
hulk_with_bwd = hulk[pd.to_numeric(hulk['Tot Bwd Pkts'], errors='coerce') > 0]
print(f"  HULK flows with Tot Bwd Pkts > 0: {len(hulk_with_bwd):,} / {len(hulk):,} ({len(hulk_with_bwd)/len(hulk)*100:.1f}%)")

if len(hulk_with_bwd) > 0:
    for feat in ["Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "Init Fwd Win Byts", 
                 "Init Bwd Win Byts", "Flow Duration", "Bwd Pkt Len Max", "Bwd Pkt Len Mean",
                 "Fwd Pkt Len Max", "Fwd Pkt Len Mean", "PSH Flag Cnt", "RST Flag Cnt",
                 "ACK Flag Cnt", "Pkt Len Max", "Down/Up Ratio"]:
        if feat in hulk_with_bwd.columns:
            vals = pd.to_numeric(hulk_with_bwd[feat], errors='coerce').dropna()
            print(f"  {feat:<25}: median={vals.median():>10.0f}  p25={vals.quantile(0.25):>10.0f}  p75={vals.quantile(0.75):>10.0f}")
    
    # Test model with "HULK with backward traffic" median values
    print(f"\n  Predicting with HULK-with-bwd median values:")
    s9 = {f: 0.0 for f in scaler_features}
    for feat in scaler_features:
        if feat in hulk_with_bwd.columns:
            vals = pd.to_numeric(hulk_with_bwd[feat], errors='coerce').dropna()
            if len(vals) > 0:
                s9[feat] = vals.median()
    # Ensure protocol
    s9["Protocol_6"] = 1
    s9["Protocol_0"] = 0
    preds = predict(s9)
    for cls, prob in preds:
        print(f"    {cls:<15} {prob:>7.1%}")
    print(f"    -> {'RED' if preds[0][0] != 'Benign' else 'YELLOW' if preds[1][1] >= 0.25 else 'GREEN'}")

print(f"\n{'='*80}")
print(f"  ANALYSIS COMPLETE")
print(f"{'='*80}")
