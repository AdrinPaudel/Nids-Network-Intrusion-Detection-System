#!/usr/bin/env python3
"""
Quick Flow Analysis Tool - Analyze captured flows
Run on Windows to compare with dataset features.

Usage:
    python analyze_flows.py temp/flow_capture.csv
"""

import sys
import csv
import pandas as pd
from pathlib import Path
from collections import defaultdict

def analyze_flows(csv_file):
    """Analyze flows from CSV."""
    
    print(f"\n[*] Flow Analysis Tool")
    print(f"[*] File: {csv_file}\n")
    
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"[ERROR] Cannot load {csv_file}: {e}")
        return False
    
    print(f"[+] Total flows: {len(df)}")
    print(f"[+] Columns: {len(df.columns)}\n")
    
    # ========== KEY METRICS ==========
    print("="*80)
    print("KEY METRICS")
    print("="*80 + "\n")
    
    # 1. Port distribution
    print("[*] DESTINATION PORTS (where attack is going):")
    port_counts = df['Dst Port'].value_counts().head(10)
    for port, count in port_counts.items():
        print(f"    Port {port:>5}: {count:>4} flows")
    print()
    
    # 2. Protocol distribution
    print("[*] PROTOCOLS:")
    proto_counts = df['Protocol'].value_counts()
    proto_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    for proto, count in proto_counts.items():
        proto_name = proto_names.get(proto, f'Unknown({proto})')
        print(f"    {proto_name:<10}: {count:>4} flows")
    print()
    
    # 3. Fwd Seg Size Min (CRITICAL for classification)
    print("[*] FWD SEG SIZE MIN (Critical Feature):")
    fwd_seg_min = df['Fwd Seg Size Min']
    print(f"    Mean:     {fwd_seg_min.mean():.1f}")
    print(f"    Median:   {fwd_seg_min.median():.1f}")
    print(f"    Min:      {fwd_seg_min.min():.1f}")
    print(f"    Max:      {fwd_seg_min.max():.1f}")
    print(f"    Unique values: {sorted(fwd_seg_min.unique())}")
    
    if (fwd_seg_min == 20).any():
        print(f"    ⚠️  ISSUE: FWF = 20 detected (no TCP timestamps)")
    elif (fwd_seg_min == 32).any():
        print(f"    ✓ FWF = 32 detected (correct for Linux)")
    elif (fwd_seg_min == 40).any():
        print(f"    ⚠️  FWF = 40 (non-standard, might be with TCP options)")
    print()
    
    # 4. Total Forward Packets
    print("[*] TOT FWD PKTS (Attack Intensity):")
    tot_fwd = df['Tot Fwd Pkts']
    print(f"    Mean:     {tot_fwd.mean():.1f}")
    print(f"    Median:   {tot_fwd.median():.1f}")
    print(f"    Min:      {tot_fwd.min():.1f}")
    print(f"    Max:      {tot_fwd.max():.1f}")
    print(f"    Distribution:")
    pkt_dist = tot_fwd.value_counts().sort_index()
    for pkt_count, freq in pkt_dist.items():
        print(f"      {pkt_count:>3} pkts: {freq:>4} flows")
    print()
    
    # 5. Init Fwd Win Byts (TCP window size)
    print("[*] INIT FWD WIN BYTS (TCP Window Size):")
    init_fwd_win = df[df['Protocol'] == 6]['Init Fwd Win Byts']  # Only TCP
    if len(init_fwd_win) > 0:
        print(f"    Mean:     {init_fwd_win.mean():.0f}")
        print(f"    Median:   {init_fwd_win.median():.0f}")
        print(f"    Unique:   {sorted(init_fwd_win.unique())}")
    else:
        print(f"    (No TCP flows)")
    print()
    
    # 6. Flow duration
    print("[*] FLOW DURATION (seconds):")
    dur = df['Flow Duration']
    print(f"    Mean:     {dur.mean():.3f}s")
    print(f"    Median:   {dur.median():.3f}s")
    print(f"    Min:      {dur.min():.3f}s")
    print(f"    Max:      {dur.max():.3f}s")
    print()
    
    # 7. Source ports (should be dynamic/random for attacks)
    print("[*] SOURCE PORT RANDOMNESS:")
    src_ports = df['Src Port'].nunique()
    print(f"    Unique source ports: {src_ports}/{len(df)}")
    if src_ports > len(df) * 0.5:
        print(f"    ✓ Good: Source ports are randomized")
    else:
        print(f"    ⚠️  Source ports are reused (might be benign)")
    print()
    
    # ========== TCP vs UDP ==========
    print("="*80)
    print("TCP vs UDP FLOWS")
    print("="*80 + "\n")
    
    tcp_flows = df[df['Protocol'] == 6]
    udp_flows = df[df['Protocol'] == 17]
    
    print(f"[*] TCP Flows: {len(tcp_flows)}")
    if len(tcp_flows) > 0:
        print(f"    Avg packets/flow: {tcp_flows['Tot Fwd Pkts'].mean():.1f}")
        print(f"    Top ports: {tcp_flows['Dst Port'].value_counts().head(3).to_dict()}")
        
        # Check for SYN floods or unusual flag patterns
        syn_cnt = (tcp_flows['SYN Flag Cnt'] > 0).sum()
        fin_cnt = (tcp_flows['FIN Flag Cnt'] > 0).sum()
        print(f"    Flows with SYN: {syn_cnt}/{len(tcp_flows)}")
        print(f"    Flows with FIN: {fin_cnt}/{len(tcp_flows)}")
    print()
    
    print(f"[*] UDP Flows: {len(udp_flows)}")
    if len(udp_flows) > 0:
        print(f"    Avg packets/flow: {udp_flows['Tot Fwd Pkts'].mean():.1f}")
        print(f"    Top ports: {udp_flows['Dst Port'].value_counts().head(3).to_dict()}")
    print()
    
    # ========== RECOMMENDATIONS ==========
    print("="*80)
    print("RECOMMENDATIONS")
    print("="*80 + "\n")
    
    issues = []
    
    if (fwd_seg_min == 20).any():
        issues.append("✗ FWF Seg Size Min = 20: TCP timestamps NOT enabled on attacker")
        issues.append("  → Run: sudo sysctl -w net.ipv4.tcp_timestamps=1")
    
    if len(tcp_flows) == 0 or len(tcp_flows) < len(df) * 0.3:
        issues.append("✗ Too few TCP flows: Attack should primarily use TCP port 80")
        issues.append("  → Make sure you selected port 80 when prompted for HTTP port")
    
    if tcp_flows['Tot Fwd Pkts'].mean() < 2:
        issues.append("✗ Average packets per flow too low")
        issues.append("  → HULK should generate 2-3 packets per flow")
    
    if len(df) < 50:
        issues.append("✗ Too few flows captured")
        issues.append("  → Run attack longer (120+ seconds)")
    else:
        issues.append("✓ Good number of flows captured")
    
    if src_ports > len(df) * 0.5:
        issues.append("✓ Source ports are randomized")
    
    if issues:
        for issue in issues:
            print(f"  {issue}")
    
    print()
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_flows.py <csv_file>")
        print("Example: python analyze_flows.py temp/flow_capture.csv")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    if not Path(csv_file).exists():
        print(f"[ERROR] File not found: {csv_file}")
        sys.exit(1)
    
    success = analyze_flows(csv_file)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
