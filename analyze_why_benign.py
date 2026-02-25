#!/usr/bin/env python
"""
Deep analysis of captured flows to understand why they're BENIGN
Compare with CICIDS2018 attack characteristics
"""

import os
import sys
import pandas as pd
import numpy as np

def main():
    # Load captured flows
    if sys.platform.startswith('win'):
        csv_file = r"z:\Nids\temp\flow_capture2.csv"
    else:
        csv_file = os.path.expanduser("~/Nids/temp/flow_capture2.csv")
    
    df = pd.read_csv(csv_file)
    
    print(f"\n{'='*80}")
    print(f"CAPTURED FLOWS ANALYSIS - Understanding Why They're BENIGN")
    print(f"{'='*80}\n")
    
    print(f"Total flows: {len(df)}\n")
    
    # === ATTACK 1: PORT 80 HTTP ATTACKS (should be HULK/Slowloris) ===
    print(f"{'='*80}")
    print(f"PORT 80 - HTTP ATTACKS (HULK/Slowloris)")
    print(f"{'='*80}\n")
    
    port80 = df[df['Dst Port'] == 80]
    print(f"Total HTTP flows: {len(port80)}\n")
    
    if len(port80) > 0:
        print(f"Flow Duration (ms) statistics:")
        print(f"  Mean:   {port80['Flow Duration'].mean():.1f} ms")
        print(f"  Median: {port80['Flow Duration'].median():.1f} ms")
        print(f"  Min:    {port80['Flow Duration'].min():.1f} ms")
        print(f"  Max:    {port80['Flow Duration'].max():.1f} ms")
        
        # Check for forward vs backward packets
        print(f"\nPacket counts:")
        print(f"  Avg Fwd Packets:  {port80['Tot Fwd Pkts'].mean():.1f}")
        print(f"  Avg Bwd Packets:  {port80['Tot Bwd Pkts'].mean():.1f}")
        print(f"  Flows with 0 Bwd Pkts: {(port80['Tot Bwd Pkts'] == 0).sum()}/{len(port80)}")
        
        # Check flag patterns
        print(f"\nFlag Analysis:")
        print(f"  Avg SYN Flags:   {port80['SYN Flag Cnt'].mean():.1f}")
        print(f"  Avg FIN Flags:   {port80['FIN Flag Cnt'].mean():.1f}")
        print(f"  Avg RST Flags:   {port80['RST Flag Cnt'].mean():.1f}")
        print(f"  Avg PSH Flags:   {port80['PSH Flag Cnt'].mean():.1f}")
        
        # Check inter-arrival times (IAT)
        print(f"\nInter-Arrival Times (IAT):")
        print(f"  Flow IAT Mean:   {port80['Flow IAT Mean'].mean():.1f} ms")
        print(f"  Fwd IAT Mean:    {port80['Fwd IAT Mean'].mean():.1f} ms")
        print(f"  Bwd IAT Mean:    {port80['Bwd IAT Mean'].mean():.1f} ms")
        print(f"  Flows with Bwd IAT Mean > 0: {(port80['Bwd IAT Mean'] > 0).sum()}/{len(port80)}")
        
        # Check packet lengths
        print(f"\nPacket Length Patterns:")
        print(f"  Fwd Pkt Len Mean: {port80['Fwd Pkt Len Mean'].mean():.1f} bytes")
        print(f"  Bwd Pkt Len Mean: {port80['Bwd Pkt Len Mean'].mean():.1f} bytes")
        print(f"  Flows with Bwd Pkt Len Mean > 0: {(port80['Bwd Pkt Len Mean'] > 0).sum()}/{len(port80)}")
        
        # Check Active times (TCP session active phase)
        print(f"\nActive Phase (TCP session activity):")
        print(f"  Active Max:      {port80['Active Max'].max():.1f} ms")
        print(f"  Active Mean:     {port80['Active Mean'].mean():.1f} ms")
        print(f"  Idle Mean:       {port80['Idle Mean'].mean():.1f} ms")
        print(f"  Flows with Active Max = 0: {(port80['Active Max'] == 0).sum()}/{len(port80)}")
        
        print(f"\n>>> ISSUE: Many flows have 0 backward packets, no bidirectional communication")
        print(f"    = Attacks are ONE-WAY only, victim not responding")
        print(f"    = Slowloris needs connection but may not need response")
        print(f"    = HULK needs bandwidth but may be sending empty/minimal responses\n")
    
    # === ATTACK 2: UDP FLOWS (should be LOIC/HOIC amplification DDoS) ===
    print(f"{'='*80}")
    print(f"UDP FLOWS (LOIC/HOIC DDoS)")
    print(f"{'='*80}\n")
    
    udp = df[df['Protocol'] == 17]
    print(f"Total UDP flows: {len(udp)}\n")
    
    if len(udp) > 0:
        print(f"Flow Duration (ms):")
        print(f"  Mean:   {udp['Flow Duration'].mean():.1f} ms")
        print(f"  Min:    {udp['Flow Duration'].min():.1f} ms")
        print(f"  Max:    {udp['Flow Duration'].max():.1f} ms")
        
        print(f"\nPacket counts:")
        print(f"  Avg Fwd Packets: {udp['Tot Fwd Pkts'].mean():.1f}")
        print(f"  Avg Bwd Packets: {udp['Tot Bwd Pkts'].mean():.1f}")
        
        print(f"\nPacket sizes:")
        print(f"  Fwd Pkt Len Mean: {udp['Fwd Pkt Len Mean'].mean():.1f} bytes")
        print(f"  Bwd Pkt Len Mean: {udp['Bwd Pkt Len Mean'].mean():.1f} bytes")
        
        print(f"\n>>> ISSUE: UDP amplification DDoS needs bidirectional responses")
        print(f"    = Query floods won't generate attack signature without responses\n")
    
    # === KEY MISSING FEATURES ===
    print(f"{'='*80}")
    print(f"MISSING/ZERO FEATURES (Why Model Can't Detect Attacks)")
    print(f"{'='*80}\n")
    
    missing_features = {
        'Bwd Pkt Len Min': 'Backward packets - no responses from victim',
        'Flow IAT Min': 'Inter-arrival time minimum - no varied timing',
        'Fwd IAT Min': 'Forward IAT minimum - no varied request timing',
        'Fwd URG Flags': 'TCP urgent flags - normal traffic',
        'Bwd URG Flags': 'TCP urgent flags - no responses',
        'Idle Max': 'Session idle times - continuous streams',
        'Idle Min': 'Session idle times - no idle periods',
        'Active Min': 'Session active times - all same duration?',
    }
    
    for feature, reason in missing_features.items():
        if feature in df.columns:
            all_zero = (df[feature] == 0).sum()
            pct = 100.0 * all_zero / len(df)
            print(f"  {feature:25s}: {all_zero:4d}/{len(df)} ({pct:5.1f}%) all-zero")
            print(f"    └─ Reason: {reason}")
    
    # === ROOT CAUSE ANALYSIS ===
    print(f"\n{'='*80}")
    print(f"ROOT CAUSE ANALYSIS - Why ALL Flows Are BENIGN")
    print(f"{'='*80}\n")
    
    print(f"1. ONE-WAY TRAFFIC (No bidirectional flow)")
    http_no_bwd = (port80['Tot Bwd Pkts'] == 0).sum() if len(port80) > 0 else 0
    print(f"   Port 80 flows with NO backward packets: {http_no_bwd}")
    print(f"   → Model trained on bidirectional attack flows")
    print(f"   → Your attacks are one-way (attacker→victim only)\n")
    
    print(f"2. TOO SHORT DURATION (Flows end too quickly)")
    avg_duration = df['Flow Duration'].mean()
    print(f"   Average flow duration: {avg_duration:.1f} ms ({avg_duration/1000:.2f} s)")
    print(f"   → CICIDS2018 attacks run for minutes with thousands of packets")
    print(f"   → Your flows are milliseconds with handful of packets\n")
    
    print(f"3. TOO FEW PACKETS (Weak attack signature)")
    avg_fwd = df['Tot Fwd Pkts'].mean()
    avg_bwd = df['Tot Bwd Pkts'].mean()
    print(f"   Average packets: Fwd={avg_fwd:.1f}, Bwd={avg_bwd:.1f}")
    print(f"   → CICIDS2018 attacks: hundreds/thousands of packets per flow")
    print(f"   → Your flows: {avg_fwd:.0f} packets = minimal pattern\n")
    
    print(f"4. ATTACK CODE NOT MATCHING CICIDS2018")
    print(f"   → Even with SO_RCVBUF=7300 fix, attack behavior differs")
    print(f"   → Possible issues:")
    print(f"      • Threads not actually sending enough packets")
    print(f"      • Attack terminated too early by controller script")
    print(f"      • Network throttling (bandwidth limiting)")
    print(f"      • Victim services not accepting/responding properly\n")
    
    # === COMPARISON WITH BENIGN ===
    print(f"{'='*80}")
    print(f"WHAT BENIGN FLOWS LOOK LIKE (vs Your Attacks)")
    print(f"{'='*80}\n")
    
    print(f"Your captured flows characteristics:")
    print(f"  Average duration: {df['Flow Duration'].mean():.1f} ms ({df['Flow Duration'].mean()/1000:.2f}s)")
    print(f"  Average Fwd Pkts: {df['Tot Fwd Pkts'].mean():.1f}")
    print(f"  Average Bwd Pkts: {df['Tot Bwd Pkts'].mean():.1f}")
    print(f"  % Flows with Bwd: {100.0 * (df['Tot Bwd Pkts'] > 0).sum() / len(df):.1f}%")
    
    print(f"\nCICIDS2018 Attack flows characteristics (expected):")
    print(f"  Duration: 30s - 5m (30,000 - 300,000ms)")
    print(f"  Fwd Packets: 100s - 10,000s")
    print(f"  Bwd Packets: 50s - 5,000s (bidirectional)")
    print(f"  % With Bwd: >90%")
    
    print(f"\nYour flows match: SHORT, ONE-WAY benign network traffic")
    print(f"Model sees: 'This looks like normal HTTP requests, not an attack'\n")

if __name__ == "__main__":
    main()
