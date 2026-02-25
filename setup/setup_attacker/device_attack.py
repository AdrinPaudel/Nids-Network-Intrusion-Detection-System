#!/usr/bin/env python
"""
Unified Device Attack CLI - Interactive Mode
Asks for IP, port, and attack type at runtime

NIDS Classes (5-class Default model):
  - DoS          (HTTP-layer: Hulk, Slowloris, GoldenEye, SlowHTTP)
  - DDoS         (Multi-threaded: LOIC-HTTP, LOIC-UDP, HOIC)
  - Brute Force  (SSH + FTP credential attacks)
  - Botnet       (Ares/Zeus C2 beaconing, exfil, keylog)

Extra (6-class 'All' model):
  - Infiltration (Nmap-style port scanning)

Usage:
    python device_attack.py                    # Interactive mode, prompts for all info
    python device_attack.py --dos              # DoS attack, prompts for IP + port
    python device_attack.py --duration 300     # 5 minute attack, prompts for details
    python device_attack.py --dos --ddos       # DoS + DDoS, prompts for target info
    python device_attack.py --help             # Show all options
"""

import sys
import os
import time
import random
import argparse
import socket

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Default settings (no config file needed)
DEFAULTS = {"duration": 300}

from _1_dos_attack import run_dos
from _2_ddos_simulation import run_ddos
from _3_brute_force_ssh import run_brute_force
from _5_botnet_behavior import run_botnet
from _4_infiltration import run_infiltration

def import_attacks():
    """Rename imports to avoid module name conflicts"""
    global run_dos, run_ddos, run_brute_force, run_botnet, run_infiltration
    
    # Import as dynamically named modules
    import importlib.util
    
    attacks_mapping = {
        "_1_dos_attack": "run_dos",
        "_2_ddos_simulation": "run_ddos",
        "_3_brute_force_ssh": "run_brute_force",
        "_4_infiltration": "run_infiltration",
        "_5_botnet_behavior": "run_botnet",
    }
    
    attack_functions = {}
    for module_name, func_name in attacks_mapping.items():
        try:
            spec = importlib.util.spec_from_file_location(module_name, os.path.join(os.path.dirname(__file__), f"{module_name}.py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            attack_functions[module_name] = getattr(module, func_name)
        except Exception as e:
            print(f"[!] Failed to import {module_name}: {e}")
    
    return attack_functions

def prompt_for_ip():
    """Prompt user for target IP address"""
    while True:
        ip = input("\n[?] Enter target IP address: ").strip()
        
        # Basic IP validation
        if not ip:
            print("[-] IP cannot be empty")
            continue
        
        # Check if it's a valid IP format
        try:
            socket.inet_aton(ip)
            return ip
        except socket.error:
            print("[-] Invalid IP address format")

def prompt_for_ports():
    """Prompt user for all target ports (SSH, HTTP, FTP)"""
    ports = {}
    port_names = ["SSH", "HTTP", "FTP"]
    port_defaults = {"SSH": 22, "HTTP": 80, "FTP": 21}
    
    print("\n[*] Enter target ports:")
    
    for port_name in port_names:
        while True:
            port_str = input(f"[?] Enter {port_name} port (default {port_defaults[port_name]}): ").strip()
            
            if not port_str:
                ports[port_name] = port_defaults[port_name]
                print(f"    -> Using default {port_name} port: {port_defaults[port_name]}")
                break
            
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    ports[port_name] = port
                    print(f"    -> {port_name} port set to: {port}")
                    break
                else:
                    print("[-] Port must be between 1 and 65535")
            except ValueError:
                print("[-] Invalid port number")
    
    return ports

def run_attack_sequence(target_ip, target_ports, attacks_to_run, total_duration, shuffle=True):
    """
    Run attacks in sequence
    
    Args:
        target_ip: Target IP address
        target_ports: Dictionary of ports {"SSH": 22, "HTTP": 80, "FTP": 21}
        attacks_to_run: List of attack names ["dos", "ddos", "brute_force", "botnet", "infiltration"]
        total_duration: Total duration across all attacks (seconds)
        shuffle: Whether to shuffle attack order
    """
    if shuffle:
        random.shuffle(attacks_to_run)
    
    duration_per_attack = total_duration // len(attacks_to_run)
    
    print(f"\n[*] Attack sequence:")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Ports - SSH: {target_ports['SSH']}, HTTP: {target_ports['HTTP']}, FTP: {target_ports['FTP']}")
    print(f"[*] Total duration: {total_duration}s")
    print(f"[*] Attacks: {', '.join(attacks_to_run)}")
    print(f"[*] Time per attack: {duration_per_attack}s")
    print(f"[*] Shuffled: {shuffle}")
    print(f"\n[*] Press Ctrl+C to stop\n")
    
    attack_functions = import_attacks()
    
    attack_mapping = {
        "dos": ("_1_dos_attack", run_dos, target_ports["HTTP"]),
        "ddos": ("_2_ddos_simulation", run_ddos, target_ports["HTTP"]),
        "brute_force": ("_3_brute_force_ssh", run_brute_force, target_ports["SSH"]),
        "infiltration": ("_4_infiltration", run_infiltration, target_ports["SSH"]),
        "botnet": ("_5_botnet_behavior", run_botnet, target_ports["HTTP"]),
    }
    
    for i, attack_name in enumerate(attacks_to_run, 1):
        if attack_name not in attack_mapping:
            print(f"[!] Unknown attack: {attack_name}")
            continue
        
        module_name, default_func, port = attack_mapping[attack_name]
        
        # Thread counts from CICIDS2018 specifications
        threads_for_attack = 10 if attack_name in ["ddos", "infiltration"] else 5
        
        print(f"\n[>>> Attack {i}/{len(attacks_to_run)}] Starting {attack_name.upper()}")
        print(f"[>>>] Target: {target_ip}:{port}")
        print(f"[>>>] Duration: {duration_per_attack}s")
        print(f"[>>>] Threads: {threads_for_attack} (matching CICIDS2018 intensity)")
        
        try:
            if port:
                default_func(target_ip, target_port=port, duration=duration_per_attack, threads=threads_for_attack)
            else:
                default_func(target_ip, duration=duration_per_attack, threads=threads_for_attack)
        except Exception as e:
            print(f"[!] Error running {attack_name}: {e}")
        
        if i < len(attacks_to_run):
            print(f"[*] Waiting 5s before next attack...")
            time.sleep(5)
    
    print(f"\n[+] All attacks completed!")

def parse_args():
    parser = argparse.ArgumentParser(
        description="NIDS Device Attack Generator - Interactive Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--duration", type=int, default=DEFAULTS["duration"], help=f"Attack duration in seconds (default: {DEFAULTS['duration']})")
    
    # Attack type selection
    parser.add_argument("--default", action="store_true", help="Run 5-class attacks (exclude Infiltration)")
    parser.add_argument("--all", action="store_true", help="Run all 6 attacks (include Infiltration)")
    parser.add_argument("--dos", action="store_true", help="Run DoS attack")
    parser.add_argument("--ddos", action="store_true", help="Run DDoS attack")
    parser.add_argument("--brute-force", action="store_true", dest="brute_force", help="Run Brute Force attack")
    parser.add_argument("--botnet", action="store_true", help="Run Botnet attack")
    parser.add_argument("--infiltration", action="store_true", help="Run Infiltration attack")
    
    # Utility options
    parser.add_argument("--no-shuffle", action="store_true", dest="no_shuffle", help="Don't shuffle attack order")
    
    return parser.parse_args()

def main():
    print("[*] NIDS Attack Generator - Interactive Mode\n")
    
    args = parse_args()
    
    # Prompt for target information
    print("[*] Enter target information:")
    target_ip = prompt_for_ip()
    target_ports = prompt_for_ports()
    
    # Determine which attacks to run
    attacks_to_run = []
    
    if args.all:
        attacks_to_run = ["dos", "ddos", "brute_force", "botnet", "infiltration"]
    elif args.default or not (args.dos or args.ddos or args.brute_force or args.botnet or args.infiltration):
        # Default mode (no individual attacks specified)
        attacks_to_run = ["dos", "ddos", "brute_force", "botnet"]
    else:
        # Individual attacks specified
        if args.dos:
            attacks_to_run.append("dos")
        if args.ddos:
            attacks_to_run.append("ddos")
        if args.brute_force:
            attacks_to_run.append("brute_force")
        if args.botnet:
            attacks_to_run.append("botnet")
        if args.infiltration:
            attacks_to_run.append("infiltration")
    
    if not attacks_to_run:
        print("[-] No attacks selected!")
        sys.exit(1)
    
    # Run attacks
    try:
        run_attack_sequence(
            target_ip,
            target_ports,
            attacks_to_run,
            args.duration,
            shuffle=not args.no_shuffle
        )
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
