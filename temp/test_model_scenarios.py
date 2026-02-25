import pandas as pd, numpy as np, joblib, warnings
warnings.filterwarnings('ignore')

model = joblib.load('trained_model/random_forest_model.joblib')
scaler = joblib.load('trained_model/scaler.joblib')
le = joblib.load('trained_model/label_encoder.joblib')
sel_feats = joblib.load('trained_model/selected_features.joblib')
sf = list(scaler.feature_names_in_)
si = [sf.index(f) for f in sel_feats if f in sf]
classes = list(le.classes_)

def pred(d):
    full = pd.DataFrame(0.0, index=[0], columns=sf)
    for f,v in d.items():
        if f in sf: full.at[0,f]=v
    scaled = scaler.transform(full)
    final = scaled[:, si]
    proba = model.predict_proba(final)[0]
    ps = sorted(zip(classes,proba), key=lambda x:-x[1])
    lbl = 'RED' if ps[0][0]!='Benign' else ('YELLOW' if ps[1][1]>=0.25 else 'GREEN')
    return ps, lbl

# Our ACTUAL flow: connect+RST, bwdwin=29200 (can't change server)
base_ours = {f:0.0 for f in sf}
base_ours.update({
    'Fwd Seg Size Min':32, 'Dst Port':80, 'Protocol_6':1,
    'Init Fwd Win Byts':225,
    'Tot Fwd Pkts':3, 'Tot Bwd Pkts':1, 'TotLen Fwd Pkts':0,
    'Init Bwd Win Byts':29200,
    'Bwd Pkt Len Max':60, 'Bwd Pkt Len Mean':60,
    'Pkt Len Max':60, 'Pkt Len Mean':15,
    'RST Flag Cnt':1, 'ACK Flag Cnt':3,
})

print('=== FLOW DURATION SWEEP (our actual flow, RST=1, bwdwin=29200) ===')
for dur_us in [100, 300, 1000, 3000, 5000, 8000, 10000, 13000, 15000, 20000, 30000, 50000, 100000]:
    t = base_ours.copy()
    t['Flow Duration'] = dur_us
    dur_s = dur_us / 1e6
    t['Fwd Pkts/s'] = 3 / dur_s if dur_s > 0 else 1e7
    t['Bwd Pkts/s'] = 1 / dur_s if dur_s > 0 else 1e7
    t['Flow Pkts/s'] = 4 / dur_s if dur_s > 0 else 1e7
    t['Flow IAT Mean'] = dur_us / 3
    t['Flow IAT Max'] = dur_us * 0.8
    t['Flow IAT Min'] = dur_us * 0.1
    ps, lbl = pred(t)
    dos = [p for c,p in ps if c=='DoS'][0]
    ben = [p for c,p in ps if c=='Benign'][0]
    marker = ' <<<' if lbl == 'RED' else ''
    print(f'  dur={dur_us:>7}us  Fwd/s={t["Fwd Pkts/s"]:>10.0f}  DoS={dos:.1%}  Benign={ben:.1%}  => {lbl}{marker}')

print()
print('=== BEST COMBO: dur + RST flag test ===')
for dur in [8000, 10000, 13000, 15000, 20000, 30000, 40000]:
    t = base_ours.copy()
    t['Flow Duration'] = dur
    t['Fwd Pkts/s'] = 3 / (dur/1e6)
    t['Bwd Pkts/s'] = 1 / (dur/1e6)
    t['Flow Pkts/s'] = 4 / (dur/1e6)
    t['Flow IAT Mean'] = dur / 3
    t['Flow IAT Max'] = dur * 0.8
    t['Flow IAT Min'] = 100
    t['Flow IAT Std'] = dur * 0.4
    # RST=1
    t['RST Flag Cnt'] = 1
    ps1, lbl1 = pred(t)
    dos1 = [p for c,p in ps1 if c=='DoS'][0]
    ben1 = [p for c,p in ps1 if c=='Benign'][0]
    # RST=0
    t2 = t.copy(); t2['RST Flag Cnt'] = 0
    ps2, lbl2 = pred(t2)
    dos2 = [p for c,p in ps2 if c=='DoS'][0]
    ben2 = [p for c,p in ps2 if c=='Benign'][0]
    print(f'  dur={dur:>6}: RST=1 DoS={dos1:.1%} Ben={ben1:.1%} {lbl1:6s} | RST=0 DoS={dos2:.1%} Ben={ben2:.1%} {lbl2}')

print()
print('=== VERIFY: Init Fwd Win Byts with dur=13000 ===')
for fw in [225, 2304, 4608, 14600, 29200]:
    t = base_ours.copy()
    t['Init Fwd Win Byts'] = fw
    t['Flow Duration'] = 13000
    t['Fwd Pkts/s'] = 231; t['Bwd Pkts/s'] = 77; t['Flow Pkts/s'] = 308
    t['Flow IAT Mean'] = 4333; t['Flow IAT Max'] = 11000; t['Flow IAT Min'] = 100
    ps, lbl = pred(t)
    dos = [p for c,p in ps if c=='DoS'][0]
    ben = [p for c,p in ps if c=='Benign'][0]
    print(f'  fwdwin={fw:>6}: DoS={dos:.1%} Ben={ben:.1%} => {lbl}')

print()
print('=== ALSO: What does GoldenEye look like in training? ===')
df = pd.read_csv('data/raw/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv', low_memory=False)
df = df[df['Label'] != 'Label']
ge = df[df['Label'] == 'DoS attacks-GoldenEye']
print(f'GoldenEye training flows: {len(ge)}')
for feat in ['Tot Fwd Pkts','Tot Bwd Pkts','TotLen Fwd Pkts','Init Fwd Win Byts',
             'Init Bwd Win Byts','Flow Duration','Fwd Pkts/s','Bwd Pkt Len Max',
             'Bwd Pkt Len Mean','RST Flag Cnt','PSH Flag Cnt','ACK Flag Cnt','Down/Up Ratio']:
    vals = pd.to_numeric(ge[feat], errors='coerce').dropna()
    if len(vals) > 0:
        print(f'  {feat:<25}: median={vals.median():>12.1f}  p25={vals.quantile(0.25):>10.1f}  p75={vals.quantile(0.75):>10.1f}')
