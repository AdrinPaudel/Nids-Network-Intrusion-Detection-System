"""Test different TCP close methods for model prediction."""
import pandas as pd, numpy as np, joblib, warnings
warnings.filterwarnings('ignore')

model = joblib.load('trained_model/random_forest_model.joblib')
scaler = joblib.load('trained_model/scaler.joblib')
le = joblib.load('trained_model/label_encoder.joblib')
sel = joblib.load('trained_model/selected_features.joblib')
sf = list(scaler.feature_names_in_)
si = [sf.index(f) for f in sel if f in sf]
classes = list(le.classes_)

def predict(d):
    full = pd.DataFrame(0.0, index=[0], columns=sf)
    for f, v in d.items():
        if f in sf: full.at[0, f] = v
    sc = scaler.transform(full)
    fn = sc[:, si]
    pr = model.predict_proba(fn)[0]
    ps = sorted(zip(classes, pr), key=lambda x: -x[1])
    lbl = 'RED' if ps[0][0] != 'Benign' else ('YELLOW' if ps[1][1] >= 0.25 else 'GREEN')
    probs = {c: pr for c, pr in ps}
    return probs, lbl

# Base features matching training HULK
base = {f: 0.0 for f in sf}
base.update({
    'Fwd Seg Size Min': 32, 'Dst Port': 80, 'Protocol_6': 1,
    'Init Fwd Win Byts': 225, 'Init Bwd Win Byts': 219,
    'RST Flag Cnt': 0, 'Flow Duration': 13085,
    'Fwd Pkts/s': 229, 'Bwd Pkts/s': 76, 'Flow Pkts/s': 305,
    'Flow IAT Mean': 4362, 'Flow IAT Max': 8000, 'Flow IAT Min': 1000,
    'Bwd Pkt Len Max': 60, 'Bwd Pkt Len Mean': 60,
    'Pkt Len Max': 60, 'Pkt Len Mean': 15
})

print("=" * 70)
print("APPROACH 1: iptables DROP RST")
print("connect + sleep(13ms) + send(G) + SO_LINGER RST, RST dropped")
print("CICFlowMeter sees: SYN,ACK,PSH+G(fwd); SYN-ACK,ACK(bwd)")
print("=" * 70)

# 3fwd/2bwd, RST=0, TotLen=1
t = base.copy()
t.update({'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 2, 'TotLen Fwd Pkts': 1,
          'ACK Flag Cnt': 4,
          'Bwd Pkt Len Mean': 30, 'Pkt Len Mean': 12.2,
          'Bwd IAT Tot': 100, 'Bwd IAT Mean': 100, 'Bwd IAT Max': 100, 'Bwd IAT Min': 100})
probs, lbl = predict(t)
print(f"  3fwd/2bwd TotLen=1:  DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

# Maybe server ACK arrives late (piggybacked or delayed)
t2 = base.copy()
t2.update({'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 1, 'TotLen Fwd Pkts': 1, 'ACK Flag Cnt': 3})
probs, lbl = predict(t2)
print(f"  3fwd/1bwd TotLen=1:  DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

# Realistic HULK GET request (~200-350 bytes)
t3 = base.copy()
t3.update({'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 2, 'TotLen Fwd Pkts': 200,
           'ACK Flag Cnt': 4,
           'Fwd Pkt Len Max': 200, 'Fwd Pkt Len Mean': 67, 'Fwd Seg Size Avg': 67,
           'Bwd IAT Tot': 100, 'Bwd IAT Mean': 100, 'Bwd IAT Max': 100, 'Bwd IAT Min': 100})
probs, lbl = predict(t3)
print(f"  3fwd/2bwd TotLen=200: DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

print()
print("=" * 70)
print("APPROACH 2: FIN close (no iptables, default socket close)")
print("connect + sleep(13ms) + close() -> FIN exchange")
print("=" * 70)

for fwd, bwd in [(3, 2), (3, 3), (4, 2), (4, 3)]:
    t = base.copy()
    t.update({'Tot Fwd Pkts': fwd, 'Tot Bwd Pkts': bwd,
              'FIN Flag Cnt': 2, 'ACK Flag Cnt': fwd + bwd - 1,
              'Bwd IAT Tot': 200 * max(1, bwd-1), 'Bwd IAT Mean': 200,
              'Bwd IAT Max': 200 * max(1, bwd-1), 'Bwd IAT Min': 200})
    probs, lbl = predict(t)
    print(f"  FIN {fwd}fwd/{bwd}bwd: DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

print()
print("=" * 70)
print("APPROACH 3: socket leak (keep socket open, never close)")
print("connect + send(G at 0ms) + sleep(13ms) + send(ET at 13ms) + leak")
print("CICFlowMeter sees: SYN,ACK+G,ET(fwd); SYN-ACK,ACK(bwd); idle timeout")
print("=" * 70)

t = base.copy()
t.update({'Tot Fwd Pkts': 4, 'Tot Bwd Pkts': 2, 'TotLen Fwd Pkts': 4,
          'ACK Flag Cnt': 5, 'RST Flag Cnt': 0, 'FIN Flag Cnt': 0,
          'Fwd Pkt Len Max': 3, 'Fwd Pkt Len Mean': 1, 'Fwd Seg Size Avg': 1,
          'Bwd IAT Tot': 200, 'Bwd IAT Mean': 200, 'Bwd IAT Max': 200, 'Bwd IAT Min': 200})
probs, lbl = predict(t)
print(f"  4fwd/2bwd TotLen=4:  DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

print()
print("=" * 70)
print("REFERENCE: Current state vs proposed fixes")
print("=" * 70)

# Current: bwdwin=29200, RST=1
curr = base.copy()
curr.update({'Init Bwd Win Byts': 29200, 'RST Flag Cnt': 1,
             'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 1, 'ACK Flag Cnt': 3,
             'Flow Duration': 300})
probs, lbl = predict(curr)
print(f"  CURRENT (bwdwin=29200,RST=1,fast): DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

# With victim fix + RST still on
fix1 = base.copy()
fix1.update({'RST Flag Cnt': 1, 'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 1, 'ACK Flag Cnt': 3})
probs, lbl = predict(fix1)
print(f"  +victim_win (bwdwin=219,RST=1,13ms): DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

# With victim fix + iptables RST drop
fix2 = base.copy()
fix2.update({'Tot Fwd Pkts': 3, 'Tot Bwd Pkts': 1, 'ACK Flag Cnt': 3})
probs, lbl = predict(fix2)
print(f"  +iptables (bwdwin=219,RST=0,13ms):   DoS={probs['DoS']:.1%}  Ben={probs['Benign']:.1%}  => {lbl}")

print()
print("=" * 70)
print("FEATURE IMPORTANCE CHECK")
print("=" * 70)
for f in ['TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Mean', 'Fwd Seg Size Avg',
          'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Var', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
          'FIN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Init Bwd Win Byts', 'Init Fwd Win Byts',
          'Flow Duration', 'Bwd Pkt Len Max', 'Bwd Pkt Len Mean']:
    status = "SELECTED" if f in sel else "not selected"
    print(f"  {f:<25} {status}")
