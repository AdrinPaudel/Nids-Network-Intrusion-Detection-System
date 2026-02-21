#!/usr/bin/env python
"""
Get VM IP - Helper to find your Linux VM's IP address
Run this from Windows to scan the network
"""

import sys
import subprocess
import socket
import ipaddress
import time

def get_local_ip():
    """Get local machine IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None


def scan_network_windows(network_prefix):
    """Scan network on Windows using ping"""
    print(f"\n[*] Scanning {network_prefix}/24 network for active hosts...")
    print(f"    This may take a minute or two...\n")
    
    active_hosts = []
    base_ip = network_prefix
    
    for i in range(1, 255):
        target = f"{base_ip[: base_ip.rfind('.') + 1]}{i}"
        
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '100', target],
                capture_output=True,
                timeout=1
            )
            if result.returncode == 0:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(target)[0]
                except:
                    hostname = "Unknown"
                
                active_hosts.append((target, hostname))
                print(f"  ✓ {target:20} {hostname}")
        except:
            pass
    
    return active_hosts


def scan_network_linux(network_prefix):
    """Scan network on Linux using ping"""
    print(f"\n[*] Scanning {network_prefix}/24 network for active hosts...")
    print(f"    This may take a minute or two...\n")
    
    active_hosts = []
    base_ip = network_prefix
    
    for i in range(1, 255):
        target = f"{base_ip[: base_ip.rfind('.') + 1]}{i}"
        
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '100', target],
                capture_output=True,
                timeout=1
            )
            if result.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(target)[0]
                except:
                    hostname = "Unknown"
                
                active_hosts.append((target, hostname))
                print(f"  ✓ {target:20} {hostname}")
        except:
            pass
    
    return active_hosts


def guess_vm_ip(active_hosts):
    """Try to identify which host is the VM"""
    print(f"\n[*] Analysis:")
    print(f"    Found {len(active_hosts)} active hosts\n")
    
    for ip, hostname in active_hosts:
        is_vm = False
        reason = ""
        
        if "virtualbox" in hostname.lower() or "vbox" in hostname.lower():
            is_vm = True
            reason = "(VirtualBox VM)"
        elif "kali" in hostname.lower() or "ubuntu" in hostname.lower() or "debian" in hostname.lower():
            is_vm = True
            reason = "(Likely Linux VM)"
        elif ip.endswith(".1") or ip.endswith(".2"):
            reason = "(Probably gateway/host)"
        
        if is_vm:
            print(f"  → {ip:20} {hostname:30} {reason}")
        elif reason:
            print(f"    {ip:20} {hostname:30} {reason}")
        else:
            print(f"    {ip:20} {hostname}")


def main():
    print(f"\n{'='*70}")
    print(f"VM IP DISCOVERY - Find Your Linux VM")
    print(f"{'='*70}\n")
    
    print("[*] Getting your local IP address...")
    local_ip = get_local_ip()
    
    if not local_ip:
        print("✗ Could not determine local IP")
        print("\nManual steps:")
        print("1. On your Linux VM, run:  ip addr show")
        print("2. Look for the IP on the Host-Only adapter (e.g., 192.168.56.x)")
        print("3. Use that IP with attack scripts")
        return
    
    print(f"  Your local IP: {local_ip}\n")
    
    # Extract network prefix
    parts = local_ip.split('.')
    network_prefix = '.'.join(parts[:3])
    
    print(f"[*] Your network: {network_prefix}.0/24")
    print(f"    (Host-Only adapter typically uses 192.168.56.x or 10.0.2.x)")
    
    # Ask user if they want to scan
    try:
        response = input(f"\n[?] Scan {network_prefix}.0/24 for active hosts? [y/n]: ").strip().lower()
    except:
        response = 'y'
    
    if response == 'y':
        # Determine OS and scan
        if sys.platform.startswith('win'):
            active_hosts = scan_network_windows(network_prefix)
        else:
            active_hosts = scan_network_linux(network_prefix)
        
        if active_hosts:
            guess_vm_ip(active_hosts)
            
            print(f"\n[*] Tips for identifying your VM:")
            print(f"    • Look for a VirtualBox or Linux hostname")
            print(f"    • If unsure, try: python verify_attack_setup.py <IP>")
            print(f"    • Or just try to ping it: ping 192.168.56.101")
        else:
            print("✗ No active hosts found")
            print("\nTroubleshooting:")
            print("  1. Make sure VirtualBox network is Host-Only or Bridged")
            print("  2. Make sure VM is powered on")
            print("  3. Check Windows Firewall settings")
    
    print(f"\n[*] Once you find your VM IP, use it with attack scripts:")
    print(f"    python run_all_attacks.py <VM_IP>")
    print(f"    python 1_dos_attack.py <VM_IP>")
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()
