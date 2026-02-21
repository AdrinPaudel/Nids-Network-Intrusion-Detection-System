#!/usr/bin/env python
"""
Attack Setup Verification - Check everything is ready
Verifies network connectivity, required packages, and setup
"""

import sys
import subprocess
import socket
import os

def check_package(package, import_name=None):
    """Check if a Python package is installed"""
    if import_name is None:
        import_name = package
    
    try:
        __import__(import_name)
        print(f"  ✓ {package:20} Installed")
        return True
    except ImportError:
        print(f"  ✗ {package:20} NOT installed")
        return False


def check_connectivity(target_ip, port=22, timeout=2):
    """Check if target is reachable"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target_ip, port))
        s.close()
        return result == 0
    except Exception as e:
        return False


def ping_target(target_ip):
    """Ping target IP"""
    try:
        if sys.platform.startswith('win'):
            output = subprocess.run(
                ['ping', '-n', '1', target_ip],
                capture_output=True,
                timeout=5
            )
        else:
            output = subprocess.run(
                ['ping', '-c', '1', target_ip],
                capture_output=True,
                timeout=5
            )
        return output.returncode == 0
    except Exception:
        return False


def verify_setup(target_ip):
    """Verify complete attack setup"""
    print(f"\n{'='*70}")
    print(f"ATTACK ENVIRONMENT VERIFICATION")
    print(f"{'='*70}\n")
    
    all_good = True
    
    # Check Python packages
    print("[*] Checking Python packages...")
    packages = [
        ("scapy", "scapy"),
        ("paramiko", "paramiko"),
        ("requests", "requests"),
    ]
    
    for pkg_name, import_name in packages:
        if not check_package(pkg_name, import_name):
            all_good = False
    
    # Check network connectivity
    print(f"\n[*] Checking network connectivity to {target_ip}...")
    
    if ping_target(target_ip):
        print(f"  ✓ Ping to {target_ip}: SUCCESS")
    else:
        print(f"  ✗ Ping to {target_ip}: FAILED")
        print(f"    Make sure:")
        print(f"      1. VM is powered on")
        print(f"      2. Network adapter is set to Host-Only or Bridged")
        print(f"      3. VM IP is correct")
        all_good = False
    
    # Check SSH
    if check_connectivity(target_ip, 22):
        print(f"  ✓ SSH port 22: OPEN")
    else:
        print(f"  ✗ SSH port 22: CLOSED/TIMEOUT")
        print(f"    This is OK for DoS/DDoS tests, but needed for SSH brute force")
    
    # Check common web ports
    for port in [80, 443, 8080, 8443]:
        if check_connectivity(target_ip, port):
            print(f"  ✓ Port {port}: OPEN")
    
    # Check attack scripts
    print(f"\n[*] Checking attack scripts...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = [
        "1_dos_attack.py",
        "2_ddos_simulation.py",
        "3_brute_force_ssh.py",
        "4_port_scan.py",
        "5_botnet_behavior.py",
        "6_mixed_intrusion.py",
        "run_all_attacks.py"
    ]
    
    for script in scripts:
        script_path = os.path.join(script_dir, script)
        if os.path.exists(script_path):
            print(f"  ✓ {script:30} Found")
        else:
            print(f"  ✗ {script:30} NOT FOUND")
            all_good = False
    
    # Summary
    print(f"\n{'='*70}")
    if all_good:
        print(f"✓ SETUP VERIFIED - Ready to attack!")
        print(f"\nYou can now run:")
        print(f"  python run_all_attacks.py {target_ip}")
        print(f"or individual attacks:")
        print(f"  python 1_dos_attack.py {target_ip}")
    else:
        print(f"✗ SETUP INCOMPLETE - Please fix issues above")
        print(f"\nTo install missing packages:")
        print(f"  pip install scapy paramiko requests")
        print(f"or:")
        print(f"  python setup_attack_env.py")
    print(f"{'='*70}\n")
    
    return all_good


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_attack_setup.py <TARGET_IP>")
        print("Example: python verify_attack_setup.py 192.168.56.101")
        print("\nThis checks if everything is ready to run attacks.")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    success = verify_setup(target_ip)
    sys.exit(0 if success else 1)
