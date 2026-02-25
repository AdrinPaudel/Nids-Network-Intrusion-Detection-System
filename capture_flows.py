#!/usr/bin/env python3
"""
Simple Flow Capture Utility - No Classification
Captures network flows and saves to temp folder for comparison with dataset.

Usage:
    python capture_flows.py --interface enp0s3 --duration 60 --output flows_attack.csv
    
Then compare with dataset:
    python compare_flows.py temp/flows_attack.csv data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
"""

import os
import sys
import argparse
import time
import csv
from pathlib import Path
from datetime import datetime

# Add project root to path so we can import classification modules
sys.path.insert(0, str(Path(__file__).parent))

from classification.flowmeter_source import FlowMeterSource

def create_temp_folder():
    """Create temp folder if not exists."""
    temp_dir = Path("temp")
    temp_dir.mkdir(exist_ok=True)
    return temp_dir

def capture_flows(interface, duration, output_file):
    """Capture flows from network interface."""
    
    print(f"\n[*] Flow Capture Tool (Using CICFlowMeter)")
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
        # Initialize flow meter using the same working code as classification
        flow_meter = FlowMeterSource(interface=interface)
        
        # Start capture
        flow_meter.start()
        
        # Collect flows for specified duration
        end_time = time.time() + duration
        all_flows = []
        
        print(f"[*] Scanning for flows...")
        
        while time.time() < end_time:
            try:
                # Get available flows
                flows = flow_meter.get_flows()
                if flows:
                    all_flows.extend(flows)
                    flows_captured = len(all_flows)
                    print(f"\r[*] Flows captured: {flows_captured}", end="", flush=True)
                time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n[*] Capture interrupted by user")
                break
            except Exception as e:
                print(f"\r[!] Error: {e}", flush=True)
        
        # Stop capture
        flow_meter.stop()
        
        # Get any remaining flows
        remaining_flows = flow_meter.get_flows()
        if remaining_flows:
            all_flows.extend(remaining_flows)
            flows_captured = len(all_flows)
        
        print(f"\n[*] Stops capture and processing flows...")
        
        # Save flows to CSV
        if all_flows:
            # Write CSV with all flows and their features
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                # Write header
                if isinstance(all_flows[0], dict):
                    writer = csv.DictWriter(f, fieldnames=all_flows[0].keys())
                    writer.writeheader()
                    writer.writerows(all_flows)
                else:
                    # If flows are objects, extract attributes
                    first_flow = all_flows[0]
                    keys = [attr for attr in dir(first_flow) if not attr.startswith('_')]
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for flow in all_flows:
                        flow_dict = {key: getattr(flow, key, None) for key in keys}
                        writer.writerow(flow_dict)
            
            elapsed = time.time() - start_time
            print(f"\n[+] Capture complete!")
            print(f"[+] Flows captured: {flows_captured}")
            print(f"[+] Duration: {elapsed:.1f}s")
            print(f"[+] Saved to: {output_path}")
            print(f"[+] File size: {output_path.stat().st_size / 1024:.1f} KB")
            print(f"\n[*] To examine the flows:")
            print(f"    head -10 {output_path} | cut -d',' -f1-10")
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
  sudo python capture_flows.py --interface enp0s3 --duration 60
  sudo python capture_flows.py --interface eth0 --duration 30 --output flows_test.csv
  
Output files are saved to: temp/
        """
    )
    
    parser.add_argument('--interface', required=True, help='Network interface to capture from (e.g., enp0s3, eth0)')
    parser.add_argument('--duration', type=int, default=60, help='Capture duration in seconds (default: 60)')
    parser.add_argument('--output', default='flows_capture.csv', help='Output filename (default: flows_capture.csv)')
    
    args = parser.parse_args()
    
    # Capture flows
    output_file = capture_flows(args.interface, args.duration, args.output)
    
    if output_file:
        print(f"\n[OK] Flow capture saved successfully\n")
        sys.exit(0)
    else:
        print(f"\n[ERROR] Flow capture failed\n")
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
        # Initialize flow session with proper parameters
        # output_mode can be 'csv', 'flow', or other formats
        flow_session = FlowSession(output_mode='flow', output=str(output_path))
        
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
