#!/usr/bin/env python
"""
Botnet Behavior Simulation - C&C Beaconing
Simulates periodic bot communication with command & control server
Should be detected as 'Botnet' by your NIDS
"""

import sys
import time
import socket
import random
import threading
from datetime import datetime

def botnet_beacon(target_ip, target_ports=None, beacon_interval=2, duration=60, payload_size=64):
    """
    Simulate botnet C&C beaconing - periodic connection attempts
    
    Args:
        target_ip: Target IP (C&C server)
        target_ports: Ports to beacon on (default: common C&C ports)
        beacon_interval: Seconds between beacons
        duration: How long to run (seconds)
        payload_size: Size of beacon payload
    """
    
    if target_ports is None:
        target_ports = [443, 8080, 8443, 5555, 9999]
    
    print(f"\n{'='*60}")
    print(f"Botnet Behavior - C&C Beaconing")
    print(f"{'='*60}")
    print(f"Target (C&C): {target_ip}")
    print(f"Beacon ports: {target_ports}")
    print(f"Beacon interval: {beacon_interval}s")
    print(f"Duration: {duration}s")
    print(f"\n[!] Starting C&C beaconing simulation...")
    print(f"[!] Your NIDS should show 'Botnet' traffic")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    beacon_count = 0
    successful_beacons = 0
    
    try:
        while time.time() - start_time < duration:
            # Select random port from the beacon ports
            port = random.choice(target_ports)
            beacon_count += 1
            
            # Create beacon timestamp
            beacon_data = f"BOT_BEACON_{random.randint(1000,9999)}_{int(time.time())}".encode()
            beacon_data = beacon_data + b'\x00' * (payload_size - len(beacon_data))
            
            try:
                # Attempt TCP connection to C&C
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                
                print(f"[*] Beacon {beacon_count}: Connecting to {target_ip}:{port}...", end=" ", flush=True)
                s.connect((target_ip, port))
                
                # Send beacon payload
                s.send(beacon_data)
                print("✓ (connected & sent)")
                successful_beacons += 1
                s.close()
            
            except socket.timeout:
                print("✗ (timeout)")
            except ConnectionRefused:
                print("✗ (refused)")
            except Exception as e:
                print(f"✗ (error)")
            
            # Wait before next beacon
            time.sleep(beacon_interval)
    
    except KeyboardInterrupt:
        print("\n\n[!] Beaconing interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[✓] Botnet Simulation complete!")
        print(f"    Total beacons: {beacon_count}")
        print(f"    Successful: {successful_beacons}")
        print(f"    Time elapsed: {elapsed:.2f}s")
        print(f"    Beacon frequency: {beacon_count/elapsed:.2f} beacons/sec")
        print(f"{'='*60}\n")


def data_exfiltration(target_ip, target_port=443, duration=30, burst_size=1024):
    """
    Simulate data exfiltration - continuous data transfer
    Bot sending stolen data to C&C
    """
    print(f"\n{'='*60}")
    print(f"Data Exfiltration Simulation")
    print(f"{'='*60}")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration}s")
    print(f"Burst size: {burst_size} bytes")
    print(f"\n[!] Starting data exfiltration simulation...")
    print(f"[!] Your NIDS should detect abnormal traffic patterns")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    total_bytes_sent = 0
    connection_attempts = 0
    
    try:
        while time.time() - start_time < duration:
            connection_attempts += 1
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                
                print(f"[*] Connection {connection_attempts}: Exfiltrating data...", end=" ", flush=True)
                s.connect((target_ip, target_port))
                
                # Send multiple bursts of data
                for burst in range(10):
                    data = bytes([random.randint(0, 255) for _ in range(burst_size)])
                    try:
                        s.send(data)
                        total_bytes_sent += len(data)
                    except:
                        break
                
                print(f"✓ ({total_bytes_sent} bytes sent total)")
                s.close()
            
            except Exception as e:
                print("✗ (failed)")
            
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[✓] Exfiltration Simulation complete!")
        print(f"    Connections: {connection_attempts}")
        print(f"    Total data sent: {total_bytes_sent} bytes ({total_bytes_sent/1024:.2f} KB)")
        print(f"    Average rate: {total_bytes_sent/elapsed/1024:.2f} KB/s")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 5_botnet_behavior.py <TARGET_IP>")
        print("Example: python 5_botnet_behavior.py 192.168.56.101")
        print("\nOptions:")
        print("  python 5_botnet_behavior.py <IP> --beacon           # C&C beaconing")
        print("  python 5_botnet_behavior.py <IP> --exfil            # Data exfiltration")
        print("  python 5_botnet_behavior.py <IP> --duration <SEC>   # Run duration")
        print("  python 5_botnet_behavior.py <IP> --interval <SEC>   # Beacon interval")
        print("\nExamples:")
        print("  python 5_botnet_behavior.py 192.168.56.101 --beacon --duration 120")
        print("  python 5_botnet_behavior.py 192.168.56.101 --exfil --duration 60")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    mode = "beacon"
    duration = 60
    interval = 2
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--beacon":
            mode = "beacon"
            i += 1
        elif sys.argv[i] == "--exfil":
            mode = "exfil"
            i += 1
        elif sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--interval" and i + 1 < len(sys.argv):
            interval = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    if mode == "beacon":
        botnet_beacon(target_ip, beacon_interval=interval, duration=duration)
    else:
        data_exfiltration(target_ip, duration=duration)
