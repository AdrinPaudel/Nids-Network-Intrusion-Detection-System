"""Test model with features matching HTTP GET HULK + 4 CICFlowMeter fixes."""
import joblib, numpy as np, pandas as pd, warnings
warnings.filterwarnings('ignore')

model = joblib.load('trained_model/random_forest_model.joblib')
scaler = joblib.load('trained_model/scaler.joblib')
le = joblib.load('trained_model/label_encoder.joblib')
sel_feats = list(joblib.load('trained_model/selected_features.joblib'))
all_feats = list(scaler.feature_names_in_)

# Load training data for comparison
df = pd.read_csv('data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv')
dos = df[df['Label'] == 'DoS attacks-Hulk']

print(f"=== TRAINING DATA DoS-Hulk (n={len(dos)}) ===")
for col in sel_feats[:25]:
    if col in dos.columns:
        vals = pd.to_numeric(dos[col], errors='coerce').dropna()
        if len(vals) > 0:
            med = vals.median()
            p25 = vals.quantile(0.25)
            p75 = vals.quantile(0.75)
            print(f"  {col:30s}: median={med:12.2f}  [p25={p25:.2f}, p75={p75:.2f}]")

def test(name, overrides):
    base = {f: 0.0 for f in all_feats}
    base['Protocol_6'] = 1.0  # TCP
    base.update(overrides)
    row = np.array([[base[f] for f in all_feats]])
    scaled = scaler.transform(row)
    sel_idx = [all_feats.index(f) for f in sel_feats]
    selected = scaled[:, sel_idx]
    proba = model.predict_proba(selected)[0]
    top3 = sorted(zip(le.classes_, proba), key=lambda x: -x[1])[:3]
    top_class = top3[0][0]
    if top_class != 'Benign':
        color = 'RED'
    elif top3[1][1] >= 0.25:
        color = 'YELLOW'
    else:
        color = 'GREEN'
    print(f"  {name:55s} => {color:6s} {top3[0][0]}={top3[0][1]*100:.1f}%  {top3[1][0]}={top3[1][1]*100:.1f}%")

# ===== HTTP GET HULK: What CICFlowMeter will produce after all 4 fixes =====
# Flow: SYN(fwd) + SYN-ACK(bwd) + ACK(fwd) + GET(fwd) + ACK(bwd) + 404-response(bwd) + FIN(bwd)
# With CICFlowMeter Fix 2 (payload-only): 
#   Fwd pkt lengths: [0, 0, ~300] → TotLen Fwd = ~300, Mean = 100
#   Bwd pkt lengths: [0, 0, ~500, 0] → Bwd Pkt Max = ~500
# With CICFlowMeter Fix 3 (no duplication): correct counts

dur_us = 1500  # ~1.5ms on LAN (training median = 1147µs)
dur_s = dur_us / 1e6

# HTTP GET request ~ 300 bytes payload
get_size = 300
# Server 404 response ~ 500 bytes payload (python -m http.server)
resp_size = 500

# Packet counts after Fix 3 (no duplication)
tot_fwd = 3  # SYN + ACK + GET
tot_bwd = 4  # SYN-ACK + ACK(for GET) + 404-response + FIN

# TCP headers: 32 bytes each (with timestamp options on Linux)
fwd_hdr = 32 * tot_fwd  # 96
bwd_hdr = 32 * tot_bwd  # 128

# Rates
flow_pkts_s = (tot_fwd + tot_bwd) / dur_s
fwd_pkts_s = tot_fwd / dur_s
bwd_pkts_s = tot_bwd / dur_s
flow_byts_s = (get_size + resp_size) / dur_s

# Fwd packet lengths (payload-only after Fix 2): [0(SYN), 0(ACK), 300(GET)]
fwd_pkt_max = get_size
fwd_pkt_min = 0
fwd_pkt_mean = get_size / tot_fwd  # ~100
fwd_pkt_std = ((2 * (0 - fwd_pkt_mean)**2 + (get_size - fwd_pkt_mean)**2) / tot_fwd) ** 0.5

# Bwd packet lengths (payload-only): [0(SYN-ACK), 0(ACK), 500(resp), 0(FIN)]
bwd_pkt_max = resp_size
bwd_pkt_min = 0
bwd_pkt_mean = resp_size / tot_bwd  # ~125
bwd_pkt_std = ((3 * (0 - bwd_pkt_mean)**2 + (resp_size - bwd_pkt_mean)**2) / tot_bwd) ** 0.5

# All pkt lengths combined
all_lens = [0, 0, get_size, 0, 0, resp_size, 0]
pkt_mean = np.mean(all_lens)
pkt_max = max(all_lens)
pkt_min = min(all_lens)
pkt_std = np.std(all_lens)
pkt_var = np.var(all_lens)

print("\n=== HTTP GET HULK + 4 CICFlowMeter Fixes ===")
print(f"Fwd: {tot_fwd} pkts, TotLen={get_size}, Bwd: {tot_bwd} pkts, BwdMax={resp_size}")
print(f"Duration={dur_us}µs, Rates: {flow_pkts_s:.0f}/{fwd_pkts_s:.0f}/{bwd_pkts_s:.0f}")

# Test with SO_RCVBUF=26883 (majority case in first 50 rows)
hulk_base = {
    'Dst Port': 80,
    'Tot Fwd Pkts': tot_fwd, 'Tot Bwd Pkts': tot_bwd,
    'TotLen Fwd Pkts': get_size, 'TotLen Bwd Pkts': resp_size,
    'Fwd Pkt Len Max': fwd_pkt_max, 'Fwd Pkt Len Min': fwd_pkt_min,
    'Fwd Pkt Len Mean': fwd_pkt_mean, 'Fwd Pkt Len Std': fwd_pkt_std,
    'Bwd Pkt Len Max': bwd_pkt_max, 'Bwd Pkt Len Min': bwd_pkt_min,
    'Bwd Pkt Len Mean': bwd_pkt_mean, 'Bwd Pkt Len Std': bwd_pkt_std,
    'Pkt Len Max': pkt_max, 'Pkt Len Min': pkt_min,
    'Pkt Len Mean': pkt_mean, 'Pkt Len Std': pkt_std, 'Pkt Len Var': pkt_var,
    'Pkt Size Avg': pkt_mean,
    'Fwd Seg Size Avg': fwd_pkt_mean, 'Bwd Seg Size Avg': bwd_pkt_mean,
    'Fwd Header Len': fwd_hdr, 'Bwd Header Len': bwd_hdr,
    'Fwd Seg Size Min': 32,
    'Fwd Act Data Pkts': 1,  # 1 pkt with data (GET)
    'Flow Duration': dur_us,
    'Flow Byts/s': flow_byts_s, 'Flow Pkts/s': flow_pkts_s,
    'Fwd Pkts/s': fwd_pkts_s, 'Bwd Pkts/s': bwd_pkts_s,
    'Init Bwd Win Byts': 219,
    'Subflow Fwd Pkts': tot_fwd, 'Subflow Bwd Pkts': tot_bwd,
    'Subflow Fwd Byts': get_size, 'Subflow Bwd Byts': resp_size,
    'Down/Up Ratio': tot_bwd / tot_fwd if tot_fwd > 0 else 0,
    # FIN flag from server
    'FIN Flag Cnt': 1,
    # SYN flags: SYN + SYN-ACK = 2 (or 0 like training?)
    'SYN Flag Cnt': 2,
    # ACK flags: ACK + SYN-ACK(has ACK) + all data pkts
    'ACK Flag Cnt': 6,
    # PSH flag on GET and response
    'PSH Flag Cnt': 2,
    # Flow IAT
    'Flow IAT Mean': dur_us / 6,  # 7 pkts → 6 intervals
    'Flow IAT Max': dur_us / 2,
    'Flow IAT Min': 0,
    'Flow IAT Std': dur_us / 10,
    'Fwd IAT Tot': dur_us, 'Fwd IAT Max': dur_us / 2, 'Fwd IAT Mean': dur_us / 2,
}

print("\nWith Init Fwd Win Byts = 26883:")
test('HULK GET (port 80, win=26883, bwdWin=219)', {**hulk_base, 'Init Fwd Win Byts': 26883})
test('HULK GET (port 80, win=225, bwdWin=219)', {**hulk_base, 'Init Fwd Win Byts': 225})

print("\nWith Init Fwd Win Byts = 29200 (Linux default):")
test('HULK GET (port 80, win=29200, bwdWin=219)', {**hulk_base, 'Init Fwd Win Byts': 29200})

# What if server response is larger (like Apache)?
print("\nWith larger server response (935 bytes like training):")
resp2 = 935
bwd_pkt_mean2 = resp2 / tot_bwd
bwd_pkt_std2 = ((3 * (0 - bwd_pkt_mean2)**2 + (resp2 - bwd_pkt_mean2)**2) / tot_bwd) ** 0.5
all_lens2 = [0, 0, get_size, 0, 0, resp2, 0]
test('HULK GET (resp=935, win=26883)', {
    **hulk_base, 'Init Fwd Win Byts': 26883,
    'TotLen Bwd Pkts': resp2,
    'Bwd Pkt Len Max': resp2, 'Bwd Pkt Len Mean': bwd_pkt_mean2, 'Bwd Pkt Len Std': bwd_pkt_std2,
    'Pkt Len Max': resp2, 'Pkt Len Mean': np.mean(all_lens2), 'Pkt Len Std': np.std(all_lens2), 'Pkt Len Var': np.var(all_lens2),
    'Flow Byts/s': (get_size + resp2) / dur_s,
    'Subflow Bwd Byts': resp2,
})

# With SYN Flag Cnt = 0 (like training data shows)
print("\nWith SYN Flag Cnt = 0 (matching training):")
test('HULK GET (syn=0, win=26883)', {**hulk_base, 'Init Fwd Win Byts': 26883, 'SYN Flag Cnt': 0})

# Test: what if we get fewer bwd pkts (2-3 instead of 4)?
print("\nWith fewer bwd pkts (server ACK piggybacked):")
test('HULK GET (bwd=3, win=26883)', {
    **hulk_base, 'Init Fwd Win Byts': 26883,
    'Tot Bwd Pkts': 3, 'Bwd Header Len': 32*3, 'Subflow Bwd Pkts': 3,
    'Bwd Pkt Len Mean': resp_size/3, 
    'Bwd Pkts/s': 3/dur_s,
    'Flow Pkts/s': 6/dur_s,
})
test('HULK GET (bwd=2, win=26883)', {
    **hulk_base, 'Init Fwd Win Byts': 26883,
    'Tot Bwd Pkts': 2, 'Bwd Header Len': 32*2, 'Subflow Bwd Pkts': 2,
    'Bwd Pkt Len Mean': resp_size/2,
    'Bwd Pkts/s': 2/dur_s,
    'Flow Pkts/s': 5/dur_s,
})

# Compare with REAL training data predictions
print("\n=== REAL Training Data Predictions ===")
protocol_vals = pd.to_numeric(dos['Protocol'].head(20), errors='coerce').fillna(0).astype(int)
drop_cols = ['Flow ID','Src IP','Dst IP','Src Port','Timestamp','Label','Protocol']
data = dos.head(20).drop(columns=[c for c in drop_cols if c in dos.columns])
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
proba = model.predict_proba(final)

red = yellow = green = 0
for i in range(len(proba)):
    top3 = sorted(zip(le.classes_, proba[i]), key=lambda x: -x[1])[:3]
    if top3[0][0] != 'Benign':
        red += 1
    elif top3[1][1] >= 0.25:
        yellow += 1
    else:
        green += 1
print(f"  Training DoS-Hulk (n=20): RED={red} YELLOW={yellow} GREEN={green}")
