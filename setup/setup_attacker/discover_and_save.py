"""
Quick VM Discovery and Config Save
Scans network for VMs and saves first found to config
Self-contained - no external imports needed
"""

import sys
import os
import socket
import ipaddress
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Network ranges to scan
IP_RANGES = [
    "192.168.56.0/24",    # VirtualBox Host-Only Adapter
    "10.0.2.0/24",        # VirtualBox NAT Adapter
    "192.168.1.0/24",     # Common home network
    "172.16.0.0/12",      # Private network range
]

found_vms = []
lock = threading.Lock()
found_first = False

def check_ports(ip, ports=[22, 80, 21], timeout=0.5):
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

def scan_ip_worker(ip):
    """Worker thread to scan a single IP"""
    global found_first
    
    if found_first:
        return
    
    open_ports = check_ports(ip)
    if open_ports:
        with lock:
            if not found_first:
                found_vms.append({"ip": ip, "ports": open_ports})
                found_first = True
                services = ", ".join([
                    "SSH" if 22 in open_ports else "",
                    "HTTP" if 80 in open_ports else "",
                    "FTP" if 21 in open_ports else "",
                ]).replace(", , ", ", ").strip(", ")
                print(f"[+] Found VM: {ip} — Ports: {open_ports} ({services})")

def discover_vms(num_threads=20):
    """Discover VMs on configured IP ranges"""
    global found_vms, found_first
    
    found_vms = []
    found_first = False
    
    print(f"[*] Scanning IP ranges...")
    print(f"[*] Looking for hosts with ports 22/80/21 open...\n")
    
    threads = []
    
    # Generate all IPs from configured ranges
    for ip_range in IP_RANGES:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in network.hosts():
                if found_first:
                    break
                
                # Limit concurrent threads
                if len(threads) >= num_threads:
                    threads[0].join(timeout=0.5)
                    threads.pop(0)
                
                t = threading.Thread(target=scan_ip_worker, args=(str(ip),), daemon=True)
                t.start()
                threads.append(t)
        except:
            pass
    
    # Wait for all threads
    for t in threads:
        t.join(timeout=0.5)
        if found_first:
            break
    
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
    
    print(f"\n[+] Config saved!")
    print(f"    TARGET_VM_IP = {target_ip}")
    print(f"    DETECTED_PORTS = {detected_ports}")

if __name__ == "__main__":
    print("[*] Discovering VMs on local network...\n")
    
    vms = discover_vms()
    
    if vms:
        vm = vms[0]
        save_to_config(vm["ip"], vm["ports"])
        print(f"\n[+] Ready! Run:")
        print(f"    python device_attack.py")
    else:
        print("[-] No VMs found. Check network connectivity.")
        sys.exit(1)
