import pandas as pd
import joblib

# Load captured flows
flows_df = pd.read_csv('temp/flow_capture2.csv')
print("Captured flow columns:", len(flows_df.columns))

# Load selected features
selected_features = joblib.load('trained_model/selected_features.joblib')
print(f"Selected features needed: {len(selected_features)}")

# Add Protocol one-hot encoding
flows_df['Protocol_6'] = (flows_df['Protocol'] == 6).astype(int)
flows_df['Protocol_0'] = (flows_df['Protocol'] == 0).astype(int)

# Check which features are missing
print("\nMissing features:")
missing = []
for feat in selected_features:
    if feat not in flows_df.columns:
        missing.append(feat)
        print(f"  - {feat}")

if not missing:
    print("  None - all features present!")

# Check data types and sample values for a few key features
print("\nSample values:")
for feat in ['Fwd Seg Size Min', 'Init Fwd Win Byts', 'Protocol_6', 'Protocol_0']:
    if feat in flows_df.columns:
        print(f"  {feat}: {flows_df[feat].dtype} - min={flows_df[feat].min()}, max={flows_df[feat].max()}, null={flows_df[feat].isna().sum()}")

# Try to extract and see if scaler is the issue
print("\nTrying to access training data for comparison...")
test_df = pd.read_parquet('data/preprocessed/test_final.parquet')
print(f"Test data features: {test_df.shape[1]}")
print(f"Sample test data columns: {test_df.columns.tolist()[:5]}")
