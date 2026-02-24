#!/usr/bin/env python
"""
Unified Device Attack CLI
Single entry point for all NIDS attack types with auto IP discovery and mixed attack modes.

NIDS Classes (5-class Default model):
  - DoS          (HTTP-layer: Hulk, Slowloris, GoldenEye, SlowHTTP)
  - DDoS         (Multi-threaded: LOIC-HTTP, LOIC-UDP, HOIC)
  - Brute Force  (SSH + FTP credential attacks)
  - Botnet       (Ares/Zeus C2 beaconing, exfil, keylog)

Extra (6-class 'All' model):
  - Infiltration (Nmap-style port scanning)

Usage:
    python device_attack.py              # Auto-discover IP, run --default attacks, 120s
    python device_attack.py --help       # Show all options
    
    # Auto-discover + specific attack types
    python device_attack.py --default --duration 300       # 5-class attacks shuffled for 300s
    python device_attack.py --all --duration 600           # All 6 attacks for 600s total
    python device_attack.py --dos --duration 120           # Only DoS for 120s
    
    # Explicit IP
    python device_attack.py --ip 192.168.56.104 --default --duration 180
    python device_attack.py --ip 192.168.56.104 --ddos --dos --botnet --duration 240
    
    # Utilities
    python device_attack.py --discover-ip   # Just find the target, don't attack
"""

import sys
import os
import time
import random
import argparse

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULTS, PORTS, TARGET_VM_IP, DETECTED_PORTS
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

def run_attack_sequence(target_ip, attacks_to_run, total_duration, shuffle=True):
    """
    Run attacks in sequence
    
    Args:
        target_ip: Target IP address
        attacks_to_run: List of attack names ["dos", "ddos", "brute_force", "botnet", "infiltration"]
        total_duration: Total duration across all attacks (seconds)
        shuffle: Whether to shuffle attack order
    """
    if shuffle:
        random.shuffle(attacks_to_run)
    
    duration_per_attack = total_duration // len(attacks_to_run)
    
    print(f"\n[*] Attack sequence:")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Total duration: {total_duration}s")
    print(f"[*] Attacks: {', '.join(attacks_to_run)}")
    print(f"[*] Time per attack: {duration_per_attack}s")
    print(f"[*] Shuffled: {shuffle}")
    print(f"\n[*] Press Ctrl+C to stop\n")
    
    attack_functions = import_attacks()
    
    attack_mapping = {
        "dos": ("_1_dos_attack", run_dos, PORTS["web"]),
        "ddos": ("_2_ddos_simulation", run_ddos, PORTS["web"]),
        "brute_force": ("_3_brute_force_ssh", run_brute_force, None),
        "infiltration": ("_4_infiltration", run_infiltration, None),
        "botnet": ("_5_botnet_behavior", run_botnet, None),
    }
    
    for i, attack_name in enumerate(attacks_to_run, 1):
        if attack_name not in attack_mapping:
            print(f"[!] Unknown attack: {attack_name}")
            continue
        
        module_name, default_func, port = attack_mapping[attack_name]
        
        print(f"\n[>>> Attack {i}/{len(attacks_to_run)}] Starting {attack_name.upper()}")
        print(f"[>>>] Duration: {duration_per_attack}s")
        
        try:
            if port:
                default_func(target_ip, target_port=port, duration=duration_per_attack, threads=5)
            else:
                default_func(target_ip, duration=duration_per_attack, threads=5)
        except Exception as e:
            print(f"[!] Error running {attack_name}: {e}")
        
        if i < len(attacks_to_run):
            print(f"[*] Waiting 5s before next attack...")
            time.sleep(5)
    
    print(f"\n[+] All attacks completed!")

def parse_args():
    parser = argparse.ArgumentParser(
        description="NIDS Device Attack Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument("--ip", dest="target_ip", help="Target IP address (auto-discover if not provided)")
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
    args = parse_args()
    
    # Get target IP
    if not args.target_ip:
        # First check if we have a saved discovery
        if TARGET_VM_IP:
            args.target_ip = TARGET_VM_IP
            print(f"[+] Using saved target from config: {args.target_ip}")
            if DETECTED_PORTS:
                print(f"[+] Saved open ports: {DETECTED_PORTS}")
        else:
            print("[-] No target IP provided. Specify with --ip or run:")
            print("    python discover_and_save.py")
            sys.exit(1)
    
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
            args.target_ip,
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
    main()
