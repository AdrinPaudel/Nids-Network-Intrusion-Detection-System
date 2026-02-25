"""Temporary script to extract per-class feature statistics from training data."""
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')

key_features = [
    'Fwd Seg Size Min', 'Dst Port', 'TotLen Fwd Pkts', 'Init Fwd Win Byts',
    'Pkt Len Max', 'Tot Bwd Pkts', 'Tot Fwd Pkts', 'Bwd Pkt Len Max',
    'Bwd Pkt Len Std', 'Fwd Pkt Len Std', 'Fwd Pkt Len Max', 'Fwd Pkt Len Mean',
    'Flow Duration', 'RST Flag Cnt', 'ACK Flag Cnt', 'PSH Flag Cnt',
    'Protocol', 'Down/Up Ratio', 'Fwd Pkts/s', 'Flow Pkts/s',
    'Bwd Pkts/s', 'Flow Byts/s', 'Init Bwd Win Byts',
    'Flow IAT Mean', 'Flow IAT Max', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Flow IAT Min', 'Idle Min', 'Idle Mean',
    'Bwd IAT Min', 'Bwd IAT Tot', 'Pkt Len Mean', 'Pkt Len Std',
    'Bwd Pkt Len Mean',
]

files = [
    ('data/raw/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv', 'DoS day'),
    ('data/raw/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv', 'DDoS day'),
    ('data/raw/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv', 'BF day'),
    ('data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv', 'Bot day'),
]

dfs = []
for fpath, desc in files:
    print(f'Reading {desc} ({fpath})...')
    df = pd.read_csv(fpath, nrows=500000)
    df.columns = df.columns.str.strip()
    dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
df['Label'] = df['Label'].str.strip()
print(f'\nTotal rows: {len(df)}')
print('Labels:')
for label, count in df['Label'].value_counts().items():
    print(f'  {label}: {count}')

for col in df.select_dtypes(include=[np.number]).columns:
    df[col] = df[col].replace([np.inf, -np.inf], np.nan)

# Map labels to 5-class scheme
label_map = {
    'Benign': 'Benign',
    'Bot': 'Botnet',
    'FTP-BruteForce': 'Brute Force',
    'SSH-Bruteforce': 'Brute Force',
    'DoS attacks-Hulk': 'DoS',
    'DoS attacks-SlowHTTPTest': 'DoS',
    'DoS attacks-Slowloris': 'DoS',
    'DoS attacks-GoldenEye': 'DoS',
    'DDoS attacks-LOIC-HTTP': 'DDoS',
    'DDOS attack-LOIC-UDP': 'DDoS',
    'DDOS attack-HOIC': 'DDoS',
    'DDoS attack-LOIC-UDP': 'DDoS',
    'DDoS attack-HOIC': 'DDoS',
}
df['Class'] = df['Label'].map(label_map)
df = df[df['Class'].notna()]

print('\n5-class distribution:')
for cls, cnt in df['Class'].value_counts().items():
    print(f'  {cls}: {cnt}')

print('\n' + '=' * 130)
for feat in key_features:
    if feat not in df.columns:
        continue
    df[feat] = pd.to_numeric(df[feat], errors='coerce')
    print(f'\n--- {feat} ---')
    for label in ['Benign', 'DoS', 'DDoS', 'Brute Force', 'Botnet']:
        subset = df[df['Class'] == label][feat].dropna()
        if len(subset) == 0:
            continue
        print(f'  {label:<15} median={subset.median():>14.1f}  mean={subset.mean():>14.1f}  std={subset.std():>14.1f}  p25={subset.quantile(0.25):>14.1f}  p75={subset.quantile(0.75):>14.1f}')

# Also show sub-labels for DoS and DDoS
print('\n' + '=' * 130)
print('\nSUB-LABEL DETAILS (DoS/DDoS tool-specific):')
dos_ddos_labels = [l for l in df['Label'].unique() if 'DoS' in l or 'DDoS' in l or 'DDOS' in l or 'LOIC' in l or 'HOIC' in l]
important_feats = ['Fwd Seg Size Min', 'Dst Port', 'Init Fwd Win Byts', 'TotLen Fwd Pkts', 
                    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Fwd Pkt Len Mean', 'Pkt Len Max',
                    'Flow Duration', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
                    'Protocol', 'Fwd Pkts/s', 'Down/Up Ratio', 'Init Bwd Win Byts']
for feat in important_feats:
    if feat not in df.columns:
        continue
    print(f'\n--- {feat} (sub-labels) ---')
    for label in sorted(dos_ddos_labels):
        subset = df[df['Label'] == label][feat].dropna()
        if len(subset) == 0:
            continue
        print(f'  {label:<30} n={len(subset):>6}  median={subset.median():>14.1f}  mean={subset.mean():>14.1f}  p5={subset.quantile(0.05):>14.1f}  p95={subset.quantile(0.95):>14.1f}')
