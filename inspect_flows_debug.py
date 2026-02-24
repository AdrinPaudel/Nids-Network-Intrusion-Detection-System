"""
Temporary Debug Flow Inspector
Reads captured flows CSV and shows feature statistics and diagnostics.

Usage:
  python inspect_flows_debug.py  # Or specify explicit file
  python inspect_flows_debug.py temp_flows/flows_1234567890.csv
"""

import os
import sys
import pandas as pd
import argparse
from pathlib import Path

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import COLOR_CYAN, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_RESET

TEMP_DIR = os.path.join(PROJECT_ROOT, "temp_flows")

def get_critical_features():
    """Returns the #1 most critical features for attack classification."""
    return {
        "Fwd Seg Size Min": "Feature #1: TCP header size (should be 32 for Linux training, 20=Windows)",
        "Init Fwd Win Byts": "Feature #2: TCP window size (SO_RCVBUF-related)",
        "Tot Fwd Pkts": "Feature #3: Total forward packets (training shows short flows: 1-4 pkts)",
        "TotLen Fwd Pkts": "Total payload size forward",
        "Dst Port": "Destination port (80/8080 for HTTP attacks, 22 for SSH)",
        "Protocol": "Protocol (6=TCP, 17=UDP)",
    }

def select_csv_file():
    """Select or list CSV files in temp folder."""
    if not os.path.exists(TEMP_DIR):
        print(f"{COLOR_RED}[ERROR] Temp folder not found: {TEMP_DIR}{COLOR_RESET}")
        return None
    
    csvs = sorted([f for f in os.listdir(TEMP_DIR) if f.endswith('.csv')])
    if not csvs:
        print(f"{COLOR_RED}[ERROR] No CSV files in {TEMP_DIR}{COLOR_RESET}")
        return None
    
    if len(csvs) == 1:
        return os.path.join(TEMP_DIR, csvs[0])
    
    print(f"\n{COLOR_CYAN}Available CSV files:{COLOR_RESET}")
    for i, csv_file in enumerate(csvs, 1):
        size_mb = os.path.getsize(os.path.join(TEMP_DIR, csv_file)) / (1024*1024)
        print(f"  {i}. {csv_file} ({size_mb:.2f} MB)")
    
    choice = input(f"\n{COLOR_CYAN}Select file (number, blank=latest): {COLOR_RESET}").strip()
    if not choice:
        choice = "1"
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(csvs):
            return os.path.join(TEMP_DIR, csvs[idx])
    except ValueError:
        pass
    
    return None

def analyze_flow_csv(csv_path):
    """Load and analyze captured flows CSV."""
    print(f"\n{COLOR_CYAN}{'='*80}{COLOR_RESET}")
    print(f"{COLOR_CYAN}Flow Analysis: {os.path.basename(csv_path)}{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*80}{COLOR_RESET}\n")
    
    try:
        df = pd.read_csv(csv_path)
        print(f"{COLOR_GREEN}Loaded {len(df)} flows, {len(df.columns)} columns{COLOR_RESET}\n")
        
        # Show key columns
        print(f"{COLOR_CYAN}CRITICAL FEATURES FOR ATTACK DETECTION:{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        critical = get_critical_features()
        for col, desc in critical.items():
            if col in df.columns:
                val_min = df[col].min()
                val_max = df[col].max()
                val_mean = df[col].mean()
                print(f"  {col}")
                print(f"    {desc}")
                print(f"    Min={val_min}, Max={val_max}, Mean={val_mean:.2f}")
        
        # Show identifiers
        print(f"\n{COLOR_CYAN}FLOW IDENTIFIERS (Sample):{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        id_cols = ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"]
        for col in id_cols:
            if col in df.columns:
                unique = df[col].nunique()
                print(f"  {col}: {unique} unique values")
                print(f"    Examples: {df[col].unique()[:5]}")
        
        # Fwd Seg Size Min diagnosis
        print(f"\n{COLOR_CYAN}FWD SEG SIZE MIN DIAGNOSIS (Critical!):{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        if "Fwd Seg Size Min" in df.columns:
            fsm_vals = df["Fwd Seg Size Min"].unique()
            fsm_vals = sorted([v for v in fsm_vals if pd.notna(v)])
            print(f"  Unique values: {fsm_vals}")
            print(f"  Expected (Linux training): 20, 32, 40, 60")
            print(f"  If mostly 20: TCP timestamps NOT enabled (PROBLEM)")
            print(f"  If mostly 32: TCP timestamps enabled (GOOD)")
            
            val_20 = (df["Fwd Seg Size Min"] == 20).sum()
            val_32 = (df["Fwd Seg Size Min"] == 32).sum()
            print(f"\n  Flows with Fwd Seg Size Min = 20: {val_20} ({100*val_20/len(df):.1f}%)")
            print(f"  Flows with Fwd Seg Size Min = 32: {val_32} ({100*val_32/len(df):.1f}%)")
            
            if val_20 > val_32:
                print(f"\n  {COLOR_RED}⚠ WARNING: Mostly 20 → TCP timestamps likely NOT enabled{COLOR_RESET}")
                print(f"  {COLOR_RED}    Run on Windows attacker as admin:{COLOR_RESET}")
                print(f"  {COLOR_RED}    netsh int tcp set global timestamps=enabled{COLOR_RESET}")
        
        # Tot Fwd Pkts diagnosis
        print(f"\n{COLOR_CYAN}TOT FWD PKTS DIAGNOSIS (Flow profile):{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        if "Tot Fwd Pkts" in df.columns:
            mean_pkts = df["Tot Fwd Pkts"].mean()
            median_pkts = df["Tot Fwd Pkts"].median()
            max_pkts = df["Tot Fwd Pkts"].max()
            print(f"  Mean packets per flow: {mean_pkts:.2f}")
            print(f"  Median packets per flow: {median_pkts:.1f}")
            print(f"  Max packets: {max_pkts:.0f}")
            print(f"  Expected (DoS training): 2.5-7 pkts/flow")
            if mean_pkts > 50:
                print(f"\n  {COLOR_RED}⚠ WARNING: Very high packet count → flows not matching training{COLOR_RESET}")
                print(f"  {COLOR_RED}    Attacks may be using keep-alive (training had new-connection-per-request){COLOR_RESET}")
        
        # Dst Port diagnosis
        print(f"\n{COLOR_CYAN}DESTINATION PORT DIAGNOSIS:{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        if "Dst Port" in df.columns:
            port_dist = df["Dst Port"].value_counts().head(10)
            print(f"  Top ports:")
            for port, count in port_dist.items():
                pct = 100 * count / len(df)
                service = {80: "HTTP", 8080: "HTTP-alt", 22: "SSH", 21: "FTP", 443: "HTTPS"}.get(int(port), "?")
                print(f"    Port {port:5} ({service:8}): {count:5} flows ({pct:5.1f}%)")
        
        # Row details
        print(f"\n{COLOR_CYAN}FIRST 5 FLOWS (Details):{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        for i in range(min(5, len(df))):
            print(f"\n  Flow {i+1}:")
            for col in ["Flow ID", "Src IP", "Dst IP", "Dst Port", "Protocol", 
                       "Tot Fwd Pkts", "Fwd Seg Size Min", "Init Fwd Win Byts"]:
                if col in df.columns:
                    print(f"    {col}: {df.iloc[i][col]}")
        
        # CSV preview
        print(f"\n{COLOR_CYAN}RAW CSV PREVIEW (first 3 rows):{COLOR_RESET}")
        print(f"{COLOR_CYAN}{'─'*80}{COLOR_RESET}")
        print(df.head(3).to_string())
        
        print(f"\n{COLOR_GREEN}Analysis complete! CSV: {csv_path}{COLOR_RESET}")
        
    except Exception as e:
        print(f"{COLOR_RED}[ERROR] Failed to analyze: {e}{COLOR_RESET}")
        import traceback
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Inspect captured flows CSV")
    parser.add_argument("csv_file", nargs="?", help="Explicit CSV file path")
    args = parser.parse_args()
    
    csv_path = args.csv_file
    if not csv_path:
        csv_path = select_csv_file()
    
    if csv_path:
        analyze_flow_csv(csv_path)
    else:
        print(f"{COLOR_RED}[ERROR] No CSV file selected{COLOR_RESET}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{COLOR_RED}[ERROR] {e}{COLOR_RESET}")
        import traceback
        traceback.print_exc()
