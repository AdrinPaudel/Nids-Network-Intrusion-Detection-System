#!/usr/bin/env python
"""
Run Attacks - Main Attack Runner
Run individual attacks, all attacks, or all without infiltration

Usage:
    python run_all_attacks.py <IP>                    # Interactive menu
    python run_all_attacks.py <IP> --all              # All 5 attacks
    python run_all_attacks.py <IP> --default          # 4 attacks (no infiltration - matches default model)
    python run_all_attacks.py <IP> --attack 1         # Just DoS
    python run_all_attacks.py <IP> --attack 1 2 3     # DoS + DDoS + Brute Force
"""

import sys
import subprocess
import time
import os

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
        "name": "DoS (SYN Flood)",
        "script": "1_dos_attack.py",
        "args": "--duration 30 --count 500",
        "class": "DoS",
        "time": "~30 sec",
        "infiltration": False,
    },
    2: {
        "name": "DDoS (Multi-Source Flood)",
        "script": "2_ddos_simulation.py",
        "args": "--duration 30 --count 500",
        "class": "DDoS",
        "time": "~30 sec",
        "infiltration": False,
    },
    3: {
        "name": "SSH Brute Force",
        "script": "3_brute_force_ssh.py",
        "args": "",
        "class": "Brute Force",
        "time": "~1-2 min",
        "infiltration": False,
    },
    4: {
        "name": "Botnet C&C Beaconing",
        "script": "5_botnet_behavior.py",
        "args": "--beacon --duration 30 --interval 2",
        "class": "Botnet",
        "time": "~30 sec",
        "infiltration": False,
    },
    5: {
        "name": "Port Scan (Infiltration)",
        "script": "4_port_scan.py",
        "args": "--tcp-connect",
        "class": "Infilteration",
        "time": "~1-2 min",
        "infiltration": True,
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
        print(f"    {num}. {attack['name']:30} → NIDS class: {attack['class']}{tag}")

    print(f"\n  Run options:\n")
    print(f"    A  = Run ALL 5 attacks        (for 6-class 'all' model)")
    print(f"    D  = Run attacks 1-4 only     (for 5-class 'default' model)")
    print(f"    1-5 = Run specific attack(s)  (comma separated, e.g. 1,3,4)")
    print(f"    Q  = Quit")
    print(f"{'='*60}")

    choice = input("\n  Choose [A/D/1-5/Q]: ").strip().upper()
    return choice


def run_attacks(target_ip, attack_nums):
    """Run a list of attacks by number"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results = {}
    total = len(attack_nums)
    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"  Running {total} attack(s) against {target_ip}")
    print(f"{'='*60}\n")

    for idx, num in enumerate(attack_nums, 1):
        attack = ATTACKS[num]
        print(f"\n{'─'*60}")
        print(f"  [{idx}/{total}] {attack['name']}  ({attack['time']})")
        print(f"  NIDS should detect: {attack['class']}")
        print(f"{'─'*60}")

        script_path = os.path.join(script_dir, attack["script"])
        success = run_script(script_path, target_ip, attack["args"])
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
        print("Usage: python run_all_attacks.py <TARGET_IP> [OPTIONS]")
        print()
        print("Examples:")
        print("  python run_all_attacks.py 192.168.56.101              # Interactive menu")
        print("  python run_all_attacks.py 192.168.56.101 --all        # All 5 attacks")
        print("  python run_all_attacks.py 192.168.56.101 --default    # 4 attacks (no infiltration)")
        print("  python run_all_attacks.py 192.168.56.101 --attack 1   # Just DoS")
        print("  python run_all_attacks.py 192.168.56.101 --attack 1 3 # DoS + Brute Force")
        sys.exit(1)

    target_ip = sys.argv[1]

    # Parse arguments
    if "--all" in sys.argv:
        attack_nums = [1, 2, 3, 4, 5]
        run_attacks(target_ip, attack_nums)

    elif "--default" in sys.argv:
        attack_nums = [1, 2, 3, 4]  # No infiltration
        run_attacks(target_ip, attack_nums)

    elif "--attack" in sys.argv:
        idx = sys.argv.index("--attack")
        nums = []
        for arg in sys.argv[idx + 1:]:
            try:
                n = int(arg)
                if n in ATTACKS:
                    nums.append(n)
                else:
                    print(f"[!] Invalid attack number: {n} (valid: 1-5)")
            except ValueError:
                break
        if nums:
            run_attacks(target_ip, nums)
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
                    run_attacks(target_ip, [1, 2, 3, 4, 5])
                    break
                elif choice == 'D':
                    run_attacks(target_ip, [1, 2, 3, 4])
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
                        run_attacks(target_ip, nums)
                        break
                    else:
                        print("  [!] Invalid choice, try again")
        except KeyboardInterrupt:
            print("\n  Bye!")


if __name__ == "__main__":
    main()
