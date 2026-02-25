"""Correct model predictions with EXACT CICFlowMeter feature values.

CICFlowMeter (patched) measures TCP payload length, not raw packet length.
SYN/SYN-ACK/ACK/RST/FIN all have payload=0. So Bwd Pkt Len Max=0, not 60.

This changes our previous predictions significantly.
"""
import pandas as pd, numpy as np, joblib, warnings
warnings.filterwarnings('ignore')

model = joblib.load('trained_model/random_forest_model.joblib')
scaler = joblib.load('trained_model/scaler.joblib')
le = joblib.load('trained_model/label_encoder.joblib')
sel = joblib.load('trained_model/selected_features.joblib')
sf = list(scaler.feature_names_in_)
si = [sf.index(f) for f in sel if f in sf]
classes = list(le.classes_)

print(f"Selected features ({len(sel)}):")
for i, f in enumerate(sel):
    print(f"  {i+1:2d}. {f}")

def predict(d, label=""):
    full = pd.DataFrame(0.0, index=[0], columns=sf)
    for f, v in d.items():
        if f in sf: full.at[0, f] = v
    sc = scaler.transform(full)
    fn = sc[:, si]
    pr = model.predict_proba(fn)[0]
    ps = sorted(zip(classes, pr), key=lambda x: -x[1])
    lbl = 'RED' if ps[0][0] != 'Benign' else ('YELLOW' if ps[1][1] >= 0.25 else 'GREEN')
    dos = [p for c, p in ps if c == 'DoS'][0]
    ben = [p for c, p in ps if c == 'Benign'][0]
    if label:
        print(f"  {label:<55s} DoS={dos:.1%} Ben={ben:.1%} => {lbl}")
    return ps, lbl, dos

# =====================================================================
# CORRECT feature calculations for RST close flow (no data sent)
# =====================================================================
# Packets on wire:
#   t=0.0ms:   SYN         (fwd, payload=0, hdr=32)
#   t=0.5ms:   SYN-ACK     (bwd, payload=0, hdr=32)
#   t=1.0ms:   ACK         (fwd, payload=0, hdr=32)
#   t=14.0ms:  RST+ACK     (fwd, payload=0, hdr=32)
#
# CICFlowMeter (patched) measures TCP payload only:
#   All Pkt Len = 0 (no TCP payload in any packet)
#
# Derived features:
#   Tot Fwd Pkts = 3 (SYN, ACK, RST)
#   Tot Bwd Pkts = 1 (SYN-ACK)
#   TotLen Fwd Pkts = 0
#   Fwd Pkt Len Max/Mean = 0
#   Bwd Pkt Len Max/Mean = 0
#   Pkt Len Max/Mean/Var = 0
#   Flow Duration = 14000 us
#   Flow IAT: [0.5ms, 0.5ms, 13ms] -> Mean=4667, Max=13000, Min=500
#   Fwd IAT: [1ms, 13ms] -> Mean=7000, Max=13000, Min=1000
#   Bwd IAT: only 1 pkt -> 0
#   Fwd Pkts/s = 3/0.014 = 214.3
#   Bwd Pkts/s = 1/0.014 = 71.4
#   Flow Pkts/s = 4/0.014 = 285.7
#   RST Flag Cnt = 1
#   ACK Flag Cnt = 3 (SYN-ACK, ACK, RST+ACK)
#   FIN Flag Cnt = 0
#   Init Fwd Win Byts = 225
#   Init Bwd Win Byts = 219
#   Fwd Seg Size Min = 32

def make_rst_close_flow(bwdwin, dur_ms=14, fwd_win=225, rst=1, totlen=0, fwd=3, bwd=1):
    """Create feature vector for RST close flow."""
    dur = dur_ms * 1000  # us
    d = {f: 0.0 for f in sf}
    d.update({
        'Dst Port': 80, 'Protocol_6': 1,
        'Fwd Seg Size Min': 32,
        'Init Fwd Win Byts': fwd_win,
        'Init Bwd Win Byts': bwdwin,
        'Tot Fwd Pkts': fwd,
        'Tot Bwd Pkts': bwd,
        'TotLen Fwd Pkts': totlen,
        'RST Flag Cnt': rst,
        'FIN Flag Cnt': 0,
        'ACK Flag Cnt': fwd + bwd - 1,  # All except SYN have ACK
        'Flow Duration': dur,
        'Fwd Pkts/s': fwd / (dur / 1e6) if dur > 0 else 0,
        'Bwd Pkts/s': bwd / (dur / 1e6) if dur > 0 else 0,
        'Flow Pkts/s': (fwd + bwd) / (dur / 1e6) if dur > 0 else 0,
        # ALL payload features = 0 (patched CICFlowMeter measures TCP payload)
        'Fwd Pkt Len Max': 0, 'Fwd Pkt Len Mean': 0,
        'Bwd Pkt Len Max': 0, 'Bwd Pkt Len Mean': 0,
        'Pkt Len Max': 0, 'Pkt Len Mean': 0, 'Pkt Len Var': 0,
    })
    if totlen > 0:
        d['Fwd Pkt Len Max'] = totlen
        d['Fwd Pkt Len Mean'] = totlen / fwd
        d['Pkt Len Max'] = totlen
        d['Pkt Len Mean'] = totlen / (fwd + bwd)
    if fwd > 1:
        d['Fwd IAT Mean'] = dur / (fwd - 1) if fwd > 1 else 0
        d['Fwd IAT Max'] = dur * 0.93  # Most of duration is the sleep
        d['Fwd IAT Min'] = dur * 0.07
        d['Fwd IAT Tot'] = dur
    if bwd > 1:
        d['Bwd IAT Mean'] = dur / (bwd - 1)
        d['Bwd IAT Max'] = dur / (bwd - 1)
        d['Bwd IAT Min'] = dur / (bwd - 1)
        d['Bwd IAT Tot'] = dur
    # Flow IAT (all consecutive packets)
    total_pkts = fwd + bwd
    if total_pkts > 1:
        d['Flow IAT Mean'] = dur / (total_pkts - 1)
        d['Flow IAT Max'] = dur * 0.93
        d['Flow IAT Min'] = dur * 0.03
    return d

print()
print("=" * 75)
print("SCENARIO 1: RST close (safe, reliable) - CORRECTED payload=0")
print("  connect + sleep(13ms) + RST close with SO_LINGER")
print("  All Pkt Len features = 0 (corrected)")
print("=" * 75)

# A) With victim window fix (bwdwin=219)
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=1)
predict(f, "RST=1, bwdwin=219, dur=14ms, 3fwd/1bwd, payld=0")

# B) Without victim fix (bwdwin=29200)
f = make_rst_close_flow(bwdwin=29200, dur_ms=14, rst=1)
predict(f, "RST=1, bwdwin=29200, dur=14ms (current before iptables fix)")

# C) Fast RST close, no sleep (original behavior + victim fix)
f = make_rst_close_flow(bwdwin=219, dur_ms=0.3, rst=1)
predict(f, "RST=1, bwdwin=219, dur=0.3ms (no sleep)")

# D) Ideal: RST=0 (what we were trying to achieve)
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=0)
predict(f, "RST=0, bwdwin=219, dur=14ms (ideal, if achievable)")

# Duration sweep with RST=1 + bwdwin=219
print()
print("=" * 75)
print("SCENARIO 2: Duration sweep (RST=1, bwdwin=219, payload=0)")
print("=" * 75)
for dur_ms in [0.1, 0.3, 1, 3, 5, 8, 10, 13, 14, 16, 20, 30, 50, 100]:
    f = make_rst_close_flow(bwdwin=219, dur_ms=dur_ms, rst=1)
    predict(f, f"dur={dur_ms}ms")

# Can we improve with RST=1 by adding G byte?
print()
print("=" * 75)
print("SCENARIO 3: With send(G) - 1 byte payload (RST=1, bwdwin=219)")
print("=" * 75)
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=1, totlen=1)
predict(f, "RST=1, bwdwin=219, dur=14ms, TotLen=1")

f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=1, totlen=1, fwd=4, bwd=2)
predict(f, "RST=1, bwdwin=219, dur=14ms, TotLen=1, 4fwd/2bwd")

# Socket leak approach: RST=0, with send(G) at 13ms
print()
print("=" * 75)
print("SCENARIO 4: Socket leak (don't close, CICFlowMeter idle timeout)")
print("  connect + sleep(13ms) + send(G) + abandon socket")
print("  CICFlowMeter exports after 15s idle (no RST, no FIN)")
print("  IF server doesn't respond within 15s (needs Apache config)")
print("=" * 75)

# Server ACKs the G byte: 3fwd/2bwd
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=0, totlen=1, fwd=3, bwd=2)
predict(f, "Leak: RST=0, 3fwd/2bwd, TotLen=1 (server ACKs G)")

# Server doesn't ACK (very loaded): 3fwd/1bwd  
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=0, totlen=1, fwd=3, bwd=1)
predict(f, "Leak: RST=0, 3fwd/1bwd, TotLen=1 (no server ACK)")

# Without G byte - just leak after handshake
f = make_rst_close_flow(bwdwin=219, dur_ms=1, rst=0, totlen=0, fwd=2, bwd=1)
predict(f, "Leak: RST=0, 2fwd/1bwd, TotLen=0, dur=1ms (no G)")

# Socket leak + partial HTTP (keeps server waiting longer)
# GET / HTTP/1.1\r\nHost: target\r\n (no final \r\n)
# ~50 bytes forward, server waits ~20-120s for more headers
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=0, totlen=50, fwd=3, bwd=2)
predict(f, "Leak: RST=0, TotLen=50 (partial HTTP), 3fwd/2bwd")

# What about JUST the handshake + leak, no data at all?
# But duration would be ~1ms (too short)
# What if server retransmits SYN-ACK? (connection still establishing)
# No, handshake completes immediately

print()
print("=" * 75)
print("SCENARIO 5: What if we overwhelm the server?")
print("  If server can't respond, Tot Bwd Pkts=0, Init Bwd Win Byts=-1")
print("=" * 75)

# SYN + SYN retransmit, no server response
f = {ff: 0.0 for ff in sf}
f.update({
    'Dst Port': 80, 'Protocol_6': 1, 'Fwd Seg Size Min': 32,
    'Init Fwd Win Byts': 225, 'Init Bwd Win Byts': -1,
    'Tot Fwd Pkts': 2, 'Tot Bwd Pkts': 0, 'TotLen Fwd Pkts': 0,
    'RST Flag Cnt': 0, 'ACK Flag Cnt': 0,
    'Flow Duration': 1000000,  # 1 second (SYN retransmit)
    'Fwd Pkts/s': 2, 'Bwd Pkts/s': 0, 'Flow Pkts/s': 2,
    'Fwd IAT Mean': 1000000, 'Fwd IAT Max': 1000000, 'Fwd IAT Min': 1000000,
    'Fwd IAT Tot': 1000000,
})
predict(f, "SYN flood: 2fwd/0bwd, bwdwin=-1, dur=1s")

# SYN + connect timeout (like training)
f2 = dict(f)
f2['Flow Duration'] = 13085
f2['Fwd Pkts/s'] = 2 / 0.013085
f2['Flow Pkts/s'] = 2 / 0.013085
f2['Fwd IAT Mean'] = 13085
f2['Fwd IAT Max'] = 13085
f2['Fwd IAT Min'] = 13085
f2['Fwd IAT Tot'] = 13085
predict(f2, "SYN flood: 2fwd/0bwd, bwdwin=-1, dur=13ms")

print()
print("=" * 75)
print("VERDICT: Best achievable DoS% for each approach")
print("=" * 75)
results = []

# Safe approach
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=1)
_, _, dos = predict(f, "")
results.append(("SAFE: RST close + victim win=219 + sleep 13ms", dos, "RELIABLE"))

# Socket leak
f = make_rst_close_flow(bwdwin=219, dur_ms=14, rst=0, totlen=1, fwd=3, bwd=2)
_, _, dos = predict(f, "")
results.append(("LEAK: Socket leak, send(G), idle timeout export", dos, "NEEDS Apache timeout>15s"))

# Overwhelm server
f2['Tot Fwd Pkts'] = 2
f2['Init Bwd Win Byts'] = -1
_, _, dos = predict(f2, "")
results.append(("OVERWHELM: SYN flood, server unresponsive", dos, "NEEDS many threads/machines"))

print()
for name, dos, note in results:
    lbl = 'RED' if dos > 0.5 else 'YELLOW' if dos > 0.25 else 'GREEN'
    print(f"  {name}")
    print(f"    DoS={dos:.1%} => {lbl}  [{note}]")
    print()
