#!/usr/bin/env python3
"""
Flow Comparison Tool - Compare captured attack flows with dataset
Helps identify why classification differs.

Usage:
    python compare_flows.py temp/flows_attack.csv data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
"""

import sys
import csv
import argparse
import pandas as pd
from pathlib import Path
from collections import defaultdict

def load_flows(csv_file):
    """Load flows from CSV."""
    try:
        df = pd.read_csv(csv_file)
        return df
    except Exception as e:
        print(f"[ERROR] Cannot load {csv_file}: {e}")
        return None

def get_numeric_column(df, col_name):
    """Get numeric values from column, handling various formats."""
    if col_name not in df.columns:
        return None
    try:
        return pd.to_numeric(df[col_name], errors='coerce')
    except:
        return None

def compare_flows(attack_csv, dataset_csv):
    """Compare flows between attack and dataset."""
    
    print(f"\n[*] Flow Comparison Tool")
    print(f"[*] Attack flows:  {attack_csv}")
    print(f"[*] Dataset flows: {dataset_csv}")
    print(f"\n")
    
    # Load files
    attack_df = load_flows(attack_csv)
    dataset_df = load_flows(dataset_csv)
    
    if attack_df is None or dataset_df is None:
        return False
    
    print(f"[+] Attack flows loaded:  {len(attack_df)} flows")
    print(f"[+] Dataset flows loaded: {len(dataset_df)} flows")
    print(f"\n" + "="*80)
    
    # Compare key features
    features_to_compare = [
        'Fwd Seg Size Min',
        'Fwd Pkt Len Min',
        'Fwd Pkt Len Mean',
        'Tot Fwd Pkts',
        'Init Fwd Win Byts',
        'Tot Bwd Pkts',
        'TotLen Fwd Pkts',
        'Duration',
        'PSH Flag Cnt',
        'ACK Flag Cnt',
    ]
    
    print(f"\n[*] FEATURE COMPARISON\n")
    print(f"{'Feature':<25} | {'Attack':>12} | {'Dataset':>12} | {'Diff':>12}")
    print(f"{'-'*25}-+-{'-'*12}-+-{'-'*12}-+-{'-'*12}")
    
    for feature in features_to_compare:
        attack_vals = get_numeric_column(attack_df, feature)
        dataset_vals = get_numeric_column(dataset_df, feature)
        
        if attack_vals is not None and dataset_vals is not None:
            attack_mean = attack_vals.mean()
            dataset_mean = dataset_vals.mean()
            diff = abs(attack_mean - dataset_mean)
            diff_pct = (diff / max(abs(dataset_mean), 1)) * 100 if dataset_mean != 0 else 0
            
            status = "⚠️ " if diff_pct > 20 else "✓ "
            print(f"{feature:<25} | {attack_mean:>12.1f} | {dataset_mean:>12.1f} | {diff_pct:>11.1f}%")
        else:
            print(f"{feature:<25} | {'N/A':>12} | {'N/A':>12} | {'N/A':>12}")
    
    print(f"\n" + "="*80)
    print(f"\n[*] DETAILED STATISTICS\n")
    
    # Detailed stats for key fields
    key_fields = ['Fwd Seg Size Min', 'Tot Fwd Pkts', 'Init Fwd Win Byts']
    
    for field in key_fields:
        attack_vals = get_numeric_column(attack_df, field)
        dataset_vals = get_numeric_column(dataset_df, field)
        
        if attack_vals is not None and dataset_vals is not None:
            print(f"[{field}]")
            print(f"  Attack:")
            print(f"    Mean: {attack_vals.mean():.1f}")
            print(f"    Median: {attack_vals.median():.1f}")
            print(f"    Min: {attack_vals.min():.1f}")
            print(f"    Max: {attack_vals.max():.1f}")
            print(f"    Std: {attack_vals.std():.1f}")
            print(f"  Dataset:")
            print(f"    Mean: {dataset_vals.mean():.1f}")
            print(f"    Median: {dataset_vals.median():.1f}")
            print(f"    Min: {dataset_vals.min():.1f}")
            print(f"    Max: {dataset_vals.max():.1f}")
            print(f"    Std: {dataset_vals.std():.1f}")
            print()
    
    print(f"="*80)
    print(f"\n[*] RECOMMENDATIONS:\n")
    
    attack_fwd_seg = get_numeric_column(attack_df, 'Fwd Seg Size Min')
    if attack_fwd_seg is not None:
        if (attack_fwd_seg == 20).any():
            print(f"  ⚠️  FWF Seg Size Min = 20 detected → TCP timestamps may be disabled")
            print(f"      Check: cat /proc/sys/net/ipv4/tcp_timestamps")
        elif (attack_fwd_seg == 32).all():
            print(f"  ✓ FWF Seg Size Min = 32 (correct for Linux with timestamps)")
        else:
            print(f"  ⚠️  FWF Seg Size Min varies: {sorted(attack_fwd_seg.unique())}")
    
    attack_tot_fwd = get_numeric_column(attack_df, 'Tot Fwd Pkts')
    dataset_tot_fwd = get_numeric_column(dataset_df, 'Tot Fwd Pkts')
    if attack_tot_fwd is not None and dataset_tot_fwd is not None:
        if attack_tot_fwd.mean() < dataset_tot_fwd.mean() * 0.5:
            print(f"  ⚠️  Tot Fwd Pkts too low → Attack intensity may be too low")
            print(f"      Consider increasing threads or attack duration")
        else:
            print(f"  ✓ Tot Fwd Pkts similar to dataset")
    
    print()
    return True

def main():
    parser = argparse.ArgumentParser(
        description="Compare captured attack flows with dataset flows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python compare_flows.py temp/flows_attack.csv data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
  
  # Or find a DoS sample from the dataset:
  python compare_flows.py temp/flows_attack.csv data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
        """
    )
    
    parser.add_argument('attack_csv', help='Captured attack flows CSV')
    parser.add_argument('dataset_csv', help='Dataset flows CSV to compare against')
    
    args = parser.parse_args()
    
    # Check files exist
    if not Path(args.attack_csv).exists():
        print(f"[ERROR] Attack CSV not found: {args.attack_csv}")
        sys.exit(1)
    
    if not Path(args.dataset_csv).exists():
        print(f"[ERROR] Dataset CSV not found: {args.dataset_csv}")
        sys.exit(1)
    
    # Compare
    success = compare_flows(args.attack_csv, args.dataset_csv)
    
    if success:
        print(f"[OK] Comparison complete\n")
        sys.exit(0)
    else:
        print(f"[ERROR] Comparison failed\n")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
