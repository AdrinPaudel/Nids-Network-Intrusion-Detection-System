"""
Quick VM Discovery and Config Save
Scans network for VMs and saves to config
Self-contained - no external imports needed
"""

import sys
import os
import socket
import ipaddress
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Network ranges to scan - prioritized order
IP_RANGES = [
    "192.168.1.0/24",     # Common home network (PRIORITY)
    "192.168.56.0/24",    # VirtualBox Host-Only Adapter
    "10.0.2.0/24",        # VirtualBox NAT Adapter
]

found_vms = []
lock = threading.Lock()
scan_count = [0]  # Mutable counter for progress tracking

def check_ports(ip, ports=[22, 80, 21], timeout=1):
    """Check which ports are open on the IP"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass
    return open_ports

def is_gateway_or_router(ip_str):
    """Skip obvious gateways (.0, .1 which are usually routers/gateways)"""
    last_octet = int(ip_str.split('.')[-1])
    # Skip .0 (network) and .1 (usually gateway)
    if last_octet <= 1:
        return True
    return False

def scan_ip_worker(ip):
    """Worker thread to scan a single IP"""
    if is_gateway_or_router(str(ip)):
        return
    
    open_ports = check_ports(str(ip), timeout=1)
    
    with lock:
        scan_count[0] += 1
        if scan_count[0] % 20 == 0:
            print(f"[*] Scanned {scan_count[0]} IPs... ({len(found_vms)} found so far)")
    
    if open_ports:
        with lock:
            found_vms.append({"ip": str(ip), "ports": open_ports})

def discover_vms(num_threads=50):
    """Discover VMs on configured IP ranges. Returns ALL candidates (prioritized)"""
    global found_vms
    
    found_vms = []
    scan_count[0] = 0
    
    print(f"[*] Scanning IP ranges...")
    print(f"[*] Looking for hosts with ports 22/80/21 open...")
    print(f"[*] Press Ctrl+C to skip discovery and use --ip flag instead\n")
    
    threads = []
    start_time = time.time()
    
    try:
        # Generate all IPs from configured ranges (in priority order)
        for ip_range in IP_RANGES:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in network.hosts():
                    # Limit concurrent threads
                    while len(threads) >= num_threads:
                        # Remove finished threads
                        threads = [t for t in threads if t.is_alive()]
                        time.sleep(0.01)
                    
                    t = threading.Thread(target=scan_ip_worker, args=(str(ip),), daemon=True)
                    t.start()
                    threads.append(t)
            except Exception as e:
                print(f"[!] Error scanning range {ip_range}: {e}")
        
        # Wait for all threads with timeout
        print(f"[*] Network scan in progress...")
        timeout = time.time() + 30  # 30 second timeout for entire scan
        
        for t in threads:
            remaining = timeout - time.time()
            if remaining > 0:
                t.join(timeout=remaining)
        
        elapsed = time.time() - start_time
        print(f"\n[+] Scan completed in {elapsed:.1f}s. Scanned {scan_count[0]} IPs.\n")
        
    except KeyboardInterrupt:
        print(f"\n[!] Scan interrupted by user")
        return []
    
    # Remove duplicates and sort by network priority (192.168.1.x first)
    unique_vms = {}
    for vm in found_vms:
        unique_vms[vm["ip"]] = vm
    
    found_vms = sorted(unique_vms.values(), 
                       key=lambda x: (not x["ip"].startswith("192.168.1."), x["ip"]))
    
    return found_vms

def save_to_config(target_ip, detected_ports):
    """Save discovered values to config.py"""
    config_path = os.path.join(os.path.dirname(__file__), "config.py")
    
    with open(config_path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    for line in lines:
        if line.startswith('TARGET_VM_IP = '):
            new_lines.append(f'TARGET_VM_IP = "{target_ip}"\n')
        elif line.startswith('DETECTED_PORTS = '):
            new_lines.append(f'DETECTED_PORTS = {detected_ports}\n')
        else:
            new_lines.append(line)
    
    with open(config_path, 'w') as f:
        f.writelines(new_lines)
    
    print(f"[+] Config saved!")
    print(f"    TARGET_VM_IP = {target_ip}")
    print(f"    DETECTED_PORTS = {detected_ports}")

if __name__ == "__main__":
    try:
        print("[*] Discovering VMs on local network...\n")
        
        vms = discover_vms()
        
        if vms:
            print(f"[+] Found {len(vms)} candidate(s):\n")
            for i, vm in enumerate(vms, 1):
                services = ", ".join([
                    "SSH" if 22 in vm["ports"] else "",
                    "HTTP" if 80 in vm["ports"] else "",
                    "FTP" if 21 in vm["ports"] else "",
                ]).replace(", , ", ", ").strip(", ")
                print(f"    [{i}] {vm['ip']} — Ports: {vm['ports']} ({services})")
            
            print()
            
            # Auto-select best candidate (prioritize 192.168.1.x)
            selected_vm = vms[0]
            print(f"[+] Selected (first match): {selected_vm['ip']}")
            print(f"[!] If this is wrong, manually override with: --ip <correct_ip>\n")
            
            save_to_config(selected_vm["ip"], selected_vm["ports"])
            print(f"\n[+] Ready! Run:")
            print(f"    python device_attack.py")
        else:
            print("[-] No VMs found on local network.")
            print("[!] If victim is on a different network, use:")
            print("    python device_attack.py --ip <victim_ip>")
    except KeyboardInterrupt:
        print(f"\n[!] Discovery cancelled by user")
        print("[!] You can still attack with manual IP:")
        print("    python device_attack.py --ip <victim_ip>")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
