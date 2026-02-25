import pandas as pd

df = pd.read_csv('data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv')
tcp = df[df['Protocol'] == 6]

print("\n=== TRAINING DATA ANALYSIS ===\n")
print(f"TCP Init Fwd Win Byts:")
print(f"  Mean: {tcp['Init Fwd Win Byts'].mean():.0f}")
print(f"  Median: {tcp['Init Fwd Win Byts'].median():.0f}")
print(f"  Mode: {tcp['Init Fwd Win Byts'].mode().values[0]:.0f}")
print(f"  Q1-Q3: {tcp['Init Fwd Win Byts'].quantile(0.25):.0f} - {tcp['Init Fwd Win Byts'].quantile(0.75):.0f}")
print(f"  Min: {tcp['Init Fwd Win Byts'].min():.0f}")
print(f"  Max: {tcp['Init Fwd Win Byts'].max():.0f}")

print(f"\nTop window sizes (frequency):")
top_wins = tcp['Init Fwd Win Byts'].value_counts().head(10)
for win, count in top_wins.items():
    pct = (count / len(tcp)) * 100
    print(f"  {win:>6.0f}: {count:>6} flows ({pct:>5.1f}%)")
