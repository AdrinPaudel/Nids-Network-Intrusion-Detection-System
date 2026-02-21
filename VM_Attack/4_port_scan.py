#!/usr/bin/env python
"""
Port Scan - Reconnaissance Attack
Performs port scanning to discover open services
Should be detected as 'Infilteration' or port scan activity by your NIDS
"""

import sys
import time
from scapy.all import IP, TCP, send, RandShort
import socket

def port_scan(target_ip, start_port=1, end_port=1024, timeout=1):
    """
    Simple port scan - SYN scan style
    Sends SYN packets to many ports to detect open services
    
    Args:
        target_ip: Target IP address
        start_port: Starting port
        end_port: Ending port
        timeout: Socket timeout
    """
    print(f"\n{'='*60}")
    print(f"Port Scan - Reconnaissance")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"\n[!] Starting port scan...")
    print(f"[!] Your NIDS should detect scanning activity")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    open_ports = []
    scanned_ports = 0
    
    try:
        for port in range(start_port, end_port + 1):
            scanned_ports += 1
            
            try:
                # Try TCP connect (simpler, no raw sockets needed on some systems)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((target_ip, port))
                s.close()
                
                if result == 0:
                    print(f"[+] Port {port:5d}: OPEN ✓")
                    open_ports.append(port)
                else:
                    if port % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = scanned_ports / elapsed if elapsed > 0 else 0
                        print(f"[*] Scanned {scanned_ports} ports ({rate:.1f} p/s)...")
            
            except socket.timeout:
                pass
            except Exception as e:
                pass
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[✓] Port Scan complete!")
        print(f"    Ports scanned: {scanned_ports}")
        print(f"    Open ports found: {len(open_ports)}")
        if open_ports:
            print(f"    Open ports: {', '.join(map(str, open_ports))}")
        print(f"    Time elapsed: {elapsed:.2f}s")
        print(f"    Scan rate: {scanned_ports/elapsed:.1f} ports/sec")
        print(f"{'='*60}\n")


def syn_scan(target_ip, start_port=1, end_port=1024, timeout_check=3):
    """
    SYN scan style - uses raw sockets
    Better simulation of actual port scanner
    """
    print(f"\n{'='*60}")
    print(f"SYN Port Scan - Advanced Reconnaissance")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Port range: {start_port}-{end_port}")
    print(f"\n[!] Starting SYN port scan...")
    print(f"[!] This is more realistic scanning behavior")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    scanned_count = 0
    
    try:
        for port in range(start_port, end_port + 1):
            scanned_count += 1
            
            # Create SYN packet
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S", sport=RandShort())
            
            # Send silently
            send(pkt, verbose=0)
            
            if scanned_count % 50 == 0:
                elapsed = time.time() - start_time
                rate = scanned_count / elapsed if elapsed > 0 else 0
                print(f"[*] Sent {scanned_count} SYN packets ({rate:.1f} p/s)...")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[✓] SYN Scan complete!")
        print(f"    SYN packets sent: {scanned_count}")
        print(f"    Time elapsed: {elapsed:.2f}s")
        print(f"    Scan rate: {scanned_count/elapsed:.1f} packets/sec")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 4_port_scan.py <TARGET_IP>")
        print("Example: python 4_port_scan.py 192.168.56.101")
        print("\nOptions:")
        print("  python 4_port_scan.py <IP> --tcp-connect     # Regular TCP connect scan")
        print("  python 4_port_scan.py <IP> --syn             # SYN scan (raw packets)")
        print("  python 4_port_scan.py <IP> --range 1 65535  # Scan different port range")
        print("\nExamples:")
        print("  python 4_port_scan.py 192.168.56.101 --tcp-connect")
        print("  python 4_port_scan.py 192.168.56.101 --syn")
        print("  python 4_port_scan.py 192.168.56.101 --range 1 5000")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    start_port = 1
    end_port = 1024
    scan_type = "tcp"
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--tcp-connect":
            scan_type = "tcp"
            i += 1
        elif sys.argv[i] == "--syn":
            scan_type = "syn"
            i += 1
        elif sys.argv[i] == "--range" and i + 2 < len(sys.argv):
            start_port = int(sys.argv[i + 1])
            end_port = int(sys.argv[i + 2])
            i += 3
        else:
            i += 1
    
    if scan_type == "tcp":
        port_scan(target_ip, start_port, end_port)
    else:
        syn_scan(target_ip, start_port, end_port)
