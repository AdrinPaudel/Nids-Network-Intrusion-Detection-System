#!/usr/bin/env python3
"""
Simple Flow Capture Utility - No Classification
Captures network flows and saves to temp folder for comparison with dataset.

Usage:
    python capture_flows.py --interface enp0s3 --duration 60 --output flows_attack.csv
    
Then compare with dataset:
    ls -lh temp/
"""

import os
import sys
import argparse
import time
import csv
from pathlib import Path
from datetime import datetime

# Check if cicflowmeter is available
try:
    from cicflowmeter.flow_session import FlowSession
except ImportError:
    print("[ERROR] cicflowmeter not installed. Run: pip install cicflowmeter")
    sys.exit(1)

def create_temp_folder():
    """Create temp folder if not exists."""
    temp_dir = Path("temp")
    temp_dir.mkdir(exist_ok=True)
    return temp_dir

def capture_flows(interface, duration, output_file):
    """Capture flows from network interface."""
    
    print(f"\n[*] Flow Capture Tool")
    print(f"[*] Interface:  {interface}")
    print(f"[*] Duration:   {duration}s")
    print(f"[*] Output:     {output_file}")
    print(f"[*] Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n[*] Capturing flows... Press Ctrl+C to stop early\n")
    
    temp_dir = create_temp_folder()
    output_path = temp_dir / output_file
    
    flows_captured = 0
    start_time = time.time()
    
    try:
        # Initialize flow session
        flow_session = FlowSession()
        
        # Start packet capture
        flow_session.start(interface, packet_count=0)
        
        # Capture for specified duration
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                # Process packets
                time.sleep(0.1)  # Small delay to batch packets
            except KeyboardInterrupt:
                print("\n[*] Capture interrupted by user")
                break
        
        # Stop capture
        flow_session.stop()
        
        # Get flows
        flows = list(flow_session.get_flow_iterator())
        flows_captured = len(flows)
        
        # Save flows to CSV
        if flows_captured > 0:
            # Extract flow features
            flow_data = []
            for flow in flows:
                # Get all flow metrics
                flow_dict = {
                    'Src IP': flow.src_ip,
                    'Src Port': flow.src_port,
                    'Dst IP': flow.dest_ip,
                    'Dst Port': flow.dest_port,
                    'Protocol': flow.protocol,
                    'Timestamp': flow.timestamp,
                    'Duration': flow.duration,
                    'Tot Fwd Pkts': flow.fwd_pkt_count,
                    'Tot Bwd Pkts': flow.bwd_pkt_count,
                    'TotLen Fwd Pkts': flow.fwd_byte_count,
                    'TotLen Bwd Pkts': flow.bwd_byte_count,
                    'Fwd Pkt Len Max': flow.fwd_pkt_len_max,
                    'Fwd Pkt Len Min': flow.fwd_pkt_len_min,
                    'Fwd Pkt Len Mean': flow.fwd_pkt_len_mean,
                    'Fwd Seg Size Min': flow.fwd_seg_size_min,
                    'Fwd Seg Size Max': getattr(flow, 'fwd_seg_size_max', 0),
                    'Init Fwd Win Byts': flow.fwd_init_win_byts,
                    'Init Bwd Win Byts': flow.bwd_init_win_byts,
                    'Bwd Seg Size Min': getattr(flow, 'bwd_seg_size_min', 0),
                    'PSH Flag Cnt': getattr(flow, 'psh_flag_count', 0),
                    'ACK Flag Cnt': getattr(flow, 'ack_flag_count', 0),
                    'SYN Flag Cnt': getattr(flow, 'syn_flag_count', 0),
                    'FIN Flag Cnt': getattr(flow, 'fin_flag_count', 0),
                }
                flow_data.append(flow_dict)
            
            # Write CSV
            if flow_data:
                keys = flow_data[0].keys()
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(flow_data)
                
                elapsed = time.time() - start_time
                print(f"\n[+] Capture complete!")
                print(f"[+] Flows captured: {flows_captured}")
                print(f"[+] Duration: {elapsed:.1f}s")
                print(f"[+] Saved to: {output_path}")
                print(f"\n[*] To compare with dataset:")
                print(f"    head -5 {output_path}")
                print(f"    wc -l {output_path}")
                
                return output_path
        else:
            print(f"[!] No flows captured")
            return None
            
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Simple Flow Capture Tool - No Classification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python capture_flows.py --interface enp0s3 --duration 60
  python capture_flows.py --interface eth0 --duration 30 --output flows_test.csv
  
Output files are saved to: temp/
        """
    )
    
    parser.add_argument('--interface', required=True, help='Network interface to capture from (e.g., enp0s3, eth0)')
    parser.add_argument('--duration', type=int, default=60, help='Capture duration in seconds (default: 60)')
    parser.add_argument('--output', default='flows_capture.csv', help='Output filename (default: flows_capture.csv)')
    
    args = parser.parse_args()
    
    # Check if interface exists
    import socket
    try:
        socket.if_nametoindex(args.interface)
    except OSError:
        print(f"[ERROR] Interface '{args.interface}' not found")
        print("[*] Available interfaces can be checked with: ip link show")
        sys.exit(1)
    
    # Capture flows
    output_file = capture_flows(args.interface, args.duration, args.output)
    
    if output_file:
        print(f"\n[OK] Flow capture saved successfully")
        sys.exit(0)
    else:
        print(f"\n[ERROR] Flow capture failed")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Aborted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
