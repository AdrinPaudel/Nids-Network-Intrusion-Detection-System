#!/usr/bin/env python
"""
Run Attacks - Main Attack Runner
Automatically discovers VM's Host-Only IP and runs attacks

Usage:
    python run_all_attacks.py --attack 1              # Auto-discover VM, run DoS
    python run_all_attacks.py --all                   # Auto-discover VM, all 5 attacks
    python run_all_attacks.py --default               # Auto-discover VM, 4 attacks
    python run_all_attacks.py 192.168.56.102 --all    # Explicit IP, all 5 attacks

Optional:
    --ip <IP>           Explicit target IP (auto-discovers if not provided)
    --duration <SEC>    Override attack duration (default 120s)
"""

import sys
import subprocess
import time
import os
import socket
import ipaddress

# ==========================================================
# Auto-Discovery: Find VM's Host-Only IP
# ==========================================================
def discover_vm_ip():
    """
    Auto-discover the Linux VM's Host-Only IP on Windows
    Scans the Host-Only network and looks for active hosts
    """
    print("\n[*] Auto-discovering VM's Host-Only IP...")
    print("    Scanning network for active hosts (this takes ~30 seconds)...\n")
    
    try:
        # Get local IP to determine Host-Only network
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume Host-Only network is usually 192.168.56.0/24 or 192.168.100.0/24
        # Try scanning 192.168.56.x first (VirtualBox default)
        candidates = [
            "192.168.56",
            "192.168.100",
            "10.0.2",
            ".".join(local_ip.split(".")[:-1])  # Same subnet as local
        ]
        
        found_hosts = {}
        
        for prefix in candidates:
            print(f"[*] Scanning {prefix}.0/24...")
            for i in range(1, 255):
                target = f"{prefix}.{i}"
                try:
                    result = subprocess.run(
                        ['ping', '-n', '1', '-w', '100', target],
                        capture_output=True,
                        timeout=1
                    )
                    if result.returncode == 0:
                        try:
                            hostname = socket.gethostbyaddr(target)[0]
                        except:
                            hostname = "Unknown"
                        found_hosts[target] = hostname
                        print(f"  ✓ {target:20} {hostname}")
                except:
                    pass
        
        if found_hosts:
            print(f"\n[+] Found {len(found_hosts)} active host(s):")
            for ip, hostname in sorted(found_hosts.items()):
                print(f"    {ip:20} {hostname}")
            
            # Pick the one that looks most like a VM (not localhost, not gateway)
            for ip in sorted(found_hosts.keys()):
                if ip.endswith(".1"):
                    continue  # Skip gateway
                if ip.endswith(".101") or ip.endswith(".102") or ip.endswith(".103"):
                    print(f"\n[+] Likely VM IP: {ip}")
                    return ip
            
            # Otherwise pick the first one found
            vm_ip = sorted(found_hosts.keys())[0]
            print(f"\n[+] Using IP: {vm_ip}")
            return vm_ip
        else:
            print("\n[!] No active hosts found")
            return None
            
    except Exception as e:
        print(f"[!] Discovery error: {e}")
        return None


# ==========================================================
# Attack definitions
# ==========================================================
#   Your NIDS has 2 models:
#     Default (5-class): Benign, Botnet, Brute Force, DDoS, DoS
#     All     (6-class): Benign, Botnet, Brute Force, DDoS, DoS, Infilteration
#
#   Attacks 1-4 match the DEFAULT model (no infiltration)
#   Attack 5 (port scan) is INFILTERATION - only relevant for the ALL model
# ==========================================================

ATTACKS = {
    1: {
        "name": "DoS (Hulk/Slowloris/GoldenEye)",
        "script": "1_dos_attack.py",
        "args": "--all-dos --duration 120",
        "class": "DoS",
        "time": "~2 min",
        "infiltration": False,
        "description": "HTTP-layer DoS: Hulk flood + Slowloris + SlowHTTPTest + GoldenEye (CICIDS2018)",
    },
    2: {
        "name": "DDoS (LOIC/HOIC)",
        "script": "2_ddos_simulation.py",
        "args": "--all-ddos --duration 120",
        "class": "DDoS",
        "time": "~2 min",
        "infiltration": False,
        "description": "LOIC HTTP flood + LOIC UDP flood + HOIC POST flood (CICIDS2018)",
    },
    3: {
        "name": "Brute Force (SSH + FTP)",
        "script": "3_brute_force_ssh.py",
        "args": "--all-brute --duration 120",
        "class": "Brute Force",
        "time": "~2 min",
        "infiltration": False,
        "description": "Patator-style SSH + FTP brute force with large wordlist (CICIDS2018)",
    },
    4: {
        "name": "Botnet C2 (Ares/Zeus)",
        "script": "5_botnet_behavior.py",
        "args": "--full-botnet --duration 120 --interval 10",
        "class": "Botnet",
        "time": "~2 min",
        "infiltration": False,
        "description": "Ares-style: C2 beacon + file exfil + screenshots + keylogging (CICIDS2018)",
    },
    5: {
        "name": "Infiltration (Nmap Scan)",
        "script": "4_port_scan.py",
        "args": "--aggressive --duration 120",
        "class": "Infilteration",
        "time": "~2 min",
        "infiltration": True,
        "description": "Nmap-style: TCP connect scan + service detection + banner grab (CICIDS2018)",
    },
}


def run_script(script_path, target_ip, args=""):
    """Run a single attack script"""
    try:
        cmd_parts = [sys.executable, script_path, target_ip]
        if args:
            cmd_parts.extend(args.split())
        result = subprocess.run(cmd_parts, capture_output=False)
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return False


def show_menu(target_ip):
    """Show interactive attack menu"""
    print(f"\n{'='*60}")
    print(f"  NIDS ATTACK RUNNER")
    print(f"{'='*60}")
    print(f"  Target: {target_ip}\n")
    print(f"  Available attacks:\n")

    for num, attack in ATTACKS.items():
        tag = " [INFILTRATION]" if attack["infiltration"] else ""
        print(f"    {num}. {attack['name']:35} → NIDS class: {attack['class']}{tag}")
        if "description" in attack:
            print(f"       {attack['description']}")

    print(f"\n  Run options:\n")
    print(f"    A  = Run ALL 5 attacks        (for 6-class 'all' model)")
    print(f"    D  = Run attacks 1-4 only     (for 5-class 'default' model)")
    print(f"    1-5 = Run specific attack(s)  (comma separated, e.g. 1,3,4)")
    print(f"    Q  = Quit")
    print(f"{'='*60}")

    choice = input("\n  Choose [A/D/1-5/Q]: ").strip().upper()
    return choice


def run_mixed_attacks(target_ip, attack_nums, total_duration=None):
    """
    Run multiple attacks as random FLOWS for one total duration
    Instead of: Attack 1 for 150s, Attack 2 for 150s...
    This does: Randomly pick an attack, run it for random time,
               pick another random attack, run it for random time, etc.
               Until total_duration is reached.
    
    Example with 600s total:
    - Flow 1: Attack 1 for 27s
    - Flow 2: Attack 3 for 45s
    - Flow 3: Attack 2 for 31s
    - Flow 4: Attack 1 for 38s
    - Flow 5: Attack 3 for 29s
    ... continue until 600s total
    """
    import random
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    if total_duration is None:
        total_duration = 600
    
    min_flow_duration = 20  # Each flow runs 20-60 seconds
    max_flow_duration = 60
    
    print(f"\n{'='*60}")
    print(f"  MIXED ATTACK MODE (Random Flows)")
    print(f"  Total duration: {total_duration} seconds")
    print(f"  Attack types: {', '.join([ATTACKS[n]['name'] for n in attack_nums])}")
    print(f"  Each flow: {min_flow_duration}-{max_flow_duration}s (random)")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    flow_count = 0
    results = {num: 0 for num in attack_nums}
    
    print(f"  Starting random flow attacks...\n")
    
    while time.time() - start_time < total_duration:
        # Randomly pick an attack
        attack_num = random.choice(attack_nums)
        attack = ATTACKS[attack_num]
        
        # Randomly pick flow duration
        flow_duration = random.randint(min_flow_duration, max_flow_duration)
        
        # Make sure we don't exceed total duration
        remaining = total_duration - (time.time() - start_time)
        if remaining < 10:
            break
        flow_duration = min(flow_duration, int(remaining))
        
        flow_count += 1
        elapsed_so_far = time.time() - start_time
        print(f"  Flow {flow_count:2d} ({elapsed_so_far:5.0f}s): {attack['name']:30} for {flow_duration}s...", end=" ", flush=True)
        
        script_path = os.path.join(script_dir, attack["script"])
        
        # Set duration for this flow
        args = attack["args"]
        if "--duration" in args:
            parts = args.split()
            new_parts = []
            skip_next = False
            for i, part in enumerate(parts):
                if skip_next:
                    skip_next = False
                    continue
                if part == "--duration":
                    new_parts.append("--duration")
                    new_parts.append(str(flow_duration))
                    skip_next = True
                else:
                    new_parts.append(part)
            args = " ".join(new_parts)
        else:
            args += f" --duration {flow_duration}"
        
        success = run_script(script_path, target_ip, args)
        results[attack_num] += 1
        print("Done")
    
    # Summary
    total_elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  MIXED ATTACK RESULTS")
    print(f"{'='*60}\n")
    
    for num in attack_nums:
        attack = ATTACKS[num]
        flow_count = results[num]
        print(f"    {num}. {attack['name']:30} {flow_count:2d} flows")
    
    print(f"\n  Total time: {total_elapsed:.1f} seconds")
    print(f"  Total flows executed: {sum(results.values())}")
    print(f"\n  Now check your NIDS terminal and reports/ folder!")
    print(f"{'='*60}\n")


def run_attacks(target_ip, attack_nums, custom_duration=None):
    """Run a list of attacks by number"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results = {}
    total = len(attack_nums)
    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"  Running {total} attack(s) against {target_ip}")
    if custom_duration:
        print(f"  Duration: {custom_duration} seconds (custom)")
    print(f"{'='*60}\n")

    for idx, num in enumerate(attack_nums, 1):
        attack = ATTACKS[num]
        print(f"\n{'─'*60}")
        print(f"  [{idx}/{total}] {attack['name']}  ({attack['time']})")
        print(f"  NIDS should detect: {attack['class']}")
        print(f"{'─'*60}")

        script_path = os.path.join(script_dir, attack["script"])
        
        # Override duration if custom duration provided
        args = attack["args"]
        if custom_duration:
            # Replace existing --duration or add it
            if "--duration" in args:
                parts = args.split()
                new_parts = []
                skip_next = False
                for i, part in enumerate(parts):
                    if skip_next:
                        skip_next = False
                        continue
                    if part == "--duration":
                        new_parts.append("--duration")
                        new_parts.append(str(custom_duration))
                        skip_next = True
                    else:
                        new_parts.append(part)
                args = " ".join(new_parts)
            else:
                args += f" --duration {custom_duration}"
        
        success = run_script(script_path, target_ip, args)
        results[num] = success

        # Small gap between attacks so NIDS can separate flows
        if idx < total:
            print(f"\n  [*] Waiting 5 seconds before next attack...")
            time.sleep(5)

    # Summary
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"  ATTACK RESULTS")
    print(f"{'='*60}\n")
    for num in attack_nums:
        attack = ATTACKS[num]
        status = "Done" if results.get(num) else "Error"
        print(f"    {num}. {attack['name']:30} [{status}]  → {attack['class']}")
    print(f"\n  Total time: {elapsed/60:.1f} minutes")
    print(f"\n  Now check your NIDS terminal and reports/ folder!")
    print(f"{'='*60}\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_all_attacks.py [OPTIONS]")
        print()
        print("Auto-discovers VM IP if not specified:")
        print("  python run_all_attacks.py --attack 1")
        print("  python run_all_attacks.py --all")
        print("  python run_all_attacks.py --default")
        print()
        print("Or specify IP explicitly:")
        print("  python run_all_attacks.py 192.168.56.102 --all")
        print("  python run_all_attacks.py 192.168.56.102 --attack 1 --duration 300")
        sys.exit(1)

    # Determine target IP: explicit or auto-discover
    target_ip = None
    
    # Check if first arg is an IP address
    if sys.argv[1][0].isdigit():
        # First argument looks like an IP
        target_ip = sys.argv[1]
        args_start = 2
    elif "--ip" in sys.argv:
        # Explicit IP provided with --ip flag
        try:
            idx = sys.argv.index("--ip")
            target_ip = sys.argv[idx + 1]
            args_start = 2
        except (ValueError, IndexError):
            args_start = 1
    else:
        # Auto-discover
        args_start = 1
        target_ip = discover_vm_ip()
        if not target_ip:
            print("\n[!] Could not auto-discover VM IP")
            print("    Provide it explicitly: python run_all_attacks.py 192.168.56.102 --attack 1")
            sys.exit(1)
    
    print(f"\n[+] Target VM: {target_ip}\n")
    
    # Extract custom duration if provided
    custom_duration = None
    if "--duration" in sys.argv:
        try:
            idx = sys.argv.index("--duration")
            if idx + 1 < len(sys.argv):
                custom_duration = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass
    
    # Check if mixed mode (shuffle attacks together)
    mixed_mode = "--mixed" in sys.argv

    # Parse arguments
    if "--all" in sys.argv:
        attack_nums = [1, 2, 3, 4, 5]
        if mixed_mode:
            run_mixed_attacks(target_ip, attack_nums, custom_duration)
        else:
            run_attacks(target_ip, attack_nums, custom_duration)

    elif "--default" in sys.argv:
        attack_nums = [1, 2, 3, 4]  # No infiltration
        if mixed_mode:
            run_mixed_attacks(target_ip, attack_nums, custom_duration)
        else:
            run_attacks(target_ip, attack_nums, custom_duration)

    elif "--attack" in sys.argv:
        idx = sys.argv.index("--attack")
        nums = []
        for arg in sys.argv[idx + 1:]:
            if arg.startswith("--"):
                break
            try:
                n = int(arg)
                if n in ATTACKS:
                    nums.append(n)
                else:
                    print(f"[!] Invalid attack number: {n} (valid: 1-5)")
            except ValueError:
                break
        if nums:
            if mixed_mode:
                run_mixed_attacks(target_ip, nums, custom_duration)
            else:
                run_attacks(target_ip, nums, custom_duration)
        else:
            print("[!] No valid attack numbers provided")
            sys.exit(1)

    else:
        # Interactive menu
        try:
            while True:
                choice = show_menu(target_ip)

                if choice == 'Q':
                    print("  Bye!")
                    break
                elif choice == 'A':
                    run_attacks(target_ip, [1, 2, 3, 4, 5], custom_duration)
                    break
                elif choice == 'D':
                    run_attacks(target_ip, [1, 2, 3, 4], custom_duration)
                    break
                else:
                    # Parse comma-separated numbers like "1,3,4" or "1 3 4"
                    nums = []
                    for part in choice.replace(",", " ").split():
                        try:
                            n = int(part)
                            if n in ATTACKS:
                                nums.append(n)
                        except ValueError:
                            pass

                    if nums:
                        run_attacks(target_ip, nums, custom_duration)
                        break
                    else:
                        print("  [!] Invalid choice, try again")
        except KeyboardInterrupt:
            print("\n  Bye!")


if __name__ == "__main__":
    main()
