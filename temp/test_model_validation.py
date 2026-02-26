"""Validate model on REAL training data and simulate CICFlowMeter output."""
import joblib, numpy as np, pandas as pd, warnings
warnings.filterwarnings('ignore')

model = joblib.load('trained_model/random_forest_model.joblib')
scaler = joblib.load('trained_model/scaler.joblib')
le = joblib.load('trained_model/label_encoder.joblib')
sel_feats = list(joblib.load('trained_model/selected_features.joblib'))
all_feats = list(scaler.feature_names_in_)

df = pd.read_csv('data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv')
lbl_col = 'Label'

# Get DoS-Hulk rows
dos = df[df[lbl_col] == 'DoS attacks-Hulk'].head(50)
print(f"DoS-Hulk: {len(dos)} rows loaded")

# Show key features
for col in ['Dst Port','Tot Fwd Pkts','Tot Bwd Pkts','TotLen Fwd Pkts','Flow Duration',
            'Init Fwd Win Byts','Init Bwd Win Byts','Fwd Seg Size Min','SYN Flag Cnt',
            'RST Flag Cnt','Flow Byts/s','Flow Pkts/s','Fwd Pkts/s','Bwd Pkts/s','Protocol']:
    if col in dos.columns:
        vals = dos[col].head(5).tolist()
        print(f"  {col:25s}: {vals}")

# Preprocess exactly like pipeline
print("\n=== Predicting on REAL DoS-Hulk rows ===")
protocol_vals = pd.to_numeric(dos['Protocol'], errors='coerce').fillna(0).astype(int)
drop_cols = ['Flow ID','Src IP','Dst IP','Src Port','Timestamp','Label','Protocol']
data = dos.drop(columns=[c for c in drop_cols if c in dos.columns])
data = data.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
data['Protocol_0'] = (protocol_vals.values == 0).astype(int)
data['Protocol_17'] = (protocol_vals.values == 17).astype(int)
data['Protocol_6'] = (protocol_vals.values == 6).astype(int)

full_df = pd.DataFrame(0.0, index=range(len(data)), columns=all_feats)
common = [c for c in all_feats if c in data.columns]
full_df[common] = data[common].values

scaled = scaler.transform(full_df)
sel_idx = [all_feats.index(f) for f in sel_feats]
final = scaled[:, sel_idx]
preds = model.predict(final)
pred_labels = le.inverse_transform(preds)
proba = model.predict_proba(final)

for i in range(min(10, len(pred_labels))):
    top3 = sorted(zip(le.classes_, proba[i]), key=lambda x: -x[1])[:3]
    actual = dos.iloc[i][lbl_col]
    print(f"  Row {i}: actual={actual} -> pred={pred_labels[i]} ({top3[0][0]}={top3[0][1]*100:.1f}% {top3[1][0]}={top3[1][1]*100:.1f}%)")

attack_count = sum(pred_labels != "Benign")
print(f"\nOverall: {attack_count}/{len(pred_labels)} classified as attack ({attack_count*100/len(pred_labels):.0f}%)")

# Now test: what does a SYNTHETIC row matching our socket-leak look like?
print("\n=== SYNTHETIC socket-leak HULK features ===")
# Use the MEDIAN values from training DoS-Hulk 
print("\nTraining DoS-Hulk medians/modes:")
for f in sel_feats[:15]:
    if f in dos.columns:
        med = dos[f].median()
        print(f"  {f:30s}: median={med:.2f}")
    elif f.startswith('Protocol'):
        print(f"  {f:30s}: (one-hot)")

# Build synthetic row matching training DoS-Hulk medians
syn = {f: 0.0 for f in all_feats}
for f in all_feats:
    if f in dos.columns:
        syn[f] = dos[f].median()
    elif f == 'Protocol_6':
        syn[f] = 1.0
syn_row = np.array([[syn[f] for f in all_feats]])
syn_scaled = scaler.transform(syn_row)
syn_final = syn_scaled[:, sel_idx]
syn_proba = model.predict_proba(syn_final)[0]
top3 = sorted(zip(le.classes_, syn_proba), key=lambda x: -x[1])[:3]
print(f"\nSynthetic median DoS-Hulk: {top3[0][0]}={top3[0][1]*100:.1f}% {top3[1][0]}={top3[1][1]*100:.1f}% {top3[2][0]}={top3[2][1]*100:.1f}%")
top_class = top3[0][0]
if top_class != 'Benign':
    print(f"  => RED")
elif top3[1][1] >= 0.25:
    print(f"  => YELLOW")
else:
    print(f"  => GREEN")

# Now test our socket-leak flow
print("\n=== Our Socket-Leak Flow (post-CICFlowMeter fixes) ===")
our = {f: 0.0 for f in all_feats}
our['Protocol_6'] = 1.0
our['Dst Port'] = 80
our['Tot Fwd Pkts'] = 2
our['Tot Bwd Pkts'] = 1
our['TotLen Fwd Pkts'] = 0
our['TotLen Bwd Pkts'] = 0
our['Fwd Header Len'] = 64  # 32*2
our['Bwd Header Len'] = 32  # 32*1
our['Fwd Seg Size Min'] = 32
our['Flow Duration'] = 1000  # 1ms in microseconds
our['Flow Byts/s'] = 0
our['Flow Pkts/s'] = 3000  # 3/0.001
our['Fwd Pkts/s'] = 2000
our['Bwd Pkts/s'] = 1000
our['Init Fwd Win Byts'] = 29200
our['Init Bwd Win Byts'] = 219
our['SYN Flag Cnt'] = 2
our['ACK Flag Cnt'] = 2
our['Flow IAT Mean'] = 500  # 0.5ms
our['Flow IAT Max'] = 1000
our['Fwd IAT Tot'] = 1000
our['Fwd IAT Max'] = 1000
our['Fwd IAT Mean'] = 1000
our['Subflow Fwd Pkts'] = 2
our['Subflow Bwd Pkts'] = 1

our_row = np.array([[our[f] for f in all_feats]])
our_scaled = scaler.transform(our_row)
our_final = our_scaled[:, sel_idx]
our_proba = model.predict_proba(our_final)[0]
top3 = sorted(zip(le.classes_, our_proba), key=lambda x: -x[1])[:3]
print(f"Socket-leak: {top3[0][0]}={top3[0][1]*100:.1f}% {top3[1][0]}={top3[1][1]*100:.1f}% {top3[2][0]}={top3[2][1]*100:.1f}%")
top_class = top3[0][0]
if top_class != 'Benign':
    print(f"  => RED")
elif top3[1][1] >= 0.25:
    print(f"  => YELLOW")
else:
    print(f"  => GREEN")

# Compare key features scaled values
print("\n=== Key Features: Training Median vs Our Flow (SCALED values) ===")
for i, f in enumerate(sel_feats[:20]):
    syn_val = syn_final[0, i]
    our_val = our_final[0, i]
    diff = abs(syn_val - our_val)
    marker = " ***" if diff > 0.5 else ""
    print(f"  {f:30s}: training={syn_val:8.4f}  ours={our_val:8.4f}  diff={diff:.4f}{marker}")
