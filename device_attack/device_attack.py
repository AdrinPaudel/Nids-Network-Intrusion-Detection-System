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
    python device_attack.py              # Auto-discover IP, run --all attacks, 120s
    python device_attack.py --help       # Show all options
    
    # Auto-discover + specific attack types
    python device_attack.py --default --duration 300       # 5-class attacks shuffled for 300s
    python device_attack.py --all --duration 600           # All 6 attacks for 600s total
    python device_attack.py --dos --duration 120           # Only DoS for 120s
    
    # Explicit IP
    python device_attack.py 192.168.56.103 --default --duration 180
    python device_attack.py 192.168.56.103 --ddos --dos --botnet --duration 240
    
    # Utilities
    python device_attack.py --discover-ip   # Just find the target, don't attack
    python device_attack.py --verify        # Verify dependencies are installed
"""

import sys
import os
import time
import random
import socket
import subprocess
import importlib.util

# Add device_attack directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Add parent directory (z:\Nids) to path for attack_report
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import attack report
try:
    from attack_report import log_attack, generate_attack_reports
except ImportError:
    def log_attack(*args, **kwargs): pass
    def generate_attack_reports(*args, **kwargs): pass

# Import attack functions using importlib (files start with numbers)
def load_module(filename, module_name):
    """Load a module from a file with numeric prefix"""
    filepath = os.path.join(os.path.dirname(__file__), filename)
    spec = importlib.util.spec_from_file_location(module_name, filepath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Import DoS attack functions
dos_module = load_module("1_dos_attack.py", "dos_attack")
hulk_attack = dos_module.hulk_attack
slowloris_attack = dos_module.slowloris_attack
slow_post_attack = dos_module.slow_post_attack
goldeneye_attack = dos_module.goldeneye_attack

# Import DDoS attack functions
ddos_module = load_module("2_ddos_simulation.py", "ddos_simulation")
loic_http = ddos_module.loic_http
loic_udp = ddos_module.loic_udp
hoic_attack = ddos_module.hoic_attack

# Import Brute Force attack functions
brute_module = load_module("3_brute_force_ssh.py", "brute_force_ssh")
ssh_brute_force = brute_module.ssh_brute_force
ftp_brute_force = brute_module.ftp_brute_force

# Import Infiltration attack functions
infil_module = load_module("4_infiltration.py", "infiltration")
tcp_connect_scan = infil_module.tcp_connect_scan
full_port_scan = infil_module.full_port_scan
aggressive_scan = infil_module.aggressive_scan
COMMON_PORTS = getattr(infil_module, 'COMMON_PORTS', [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5432, 5984, 8080, 8443, 9200])

# Import Botnet attack functions
botnet_module = load_module("5_botnet_behavior.py", "botnet_behavior")
c2_beacon = botnet_module.c2_beacon
file_exfiltration = botnet_module.file_exfiltration
screenshot_keylog = botnet_module.screenshot_keylog
full_botnet = botnet_module.full_botnet


# ============================================================
# Auto-Discovery: Find target device IP (from run_all_attacks.py)
# ============================================================
def discover_vm_ip():
    """
    Auto-discover the target device's IP on the network.
    Works for both VMs (Host-Only adapter) and physical servers.
    Tries common networks: 192.168.56.x, 192.168.100.x, 10.0.2.x
    """
    print("\n[*] Auto-discovering target device IP...")
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
            
            # Pick the one that looks most like a target (not localhost, not gateway)
            for ip in sorted(found_hosts.keys()):
                if ip.endswith(".1"):
                    continue  # Skip gateway
                if ip.endswith(".101") or ip.endswith(".102") or ip.endswith(".103"):
                    print(f"\n[+] Likely target IP: {ip}")
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


def verify_dependencies():
    """Check if all required packages are installed"""
    print("\n[*] Verifying dependencies...\n")
    
    dependencies = {
        "paramiko": "SSH brute force attacks",
        "socket": "Built-in (always available)",
        "threading": "Built-in (always available)",
        "json": "Built-in (always available)",
    }
    
    missing = []
    for pkg, desc in dependencies.items():
        try:
            __import__(pkg)
            print(f"  [+] {pkg:20} {desc}")
        except ImportError:
            print(f"  [-] {pkg:20} {desc}  [MISSING]")
            missing.append(pkg)
    
    if missing:
        print(f"\n[!] Missing dependencies: {', '.join(missing)}")
        print(f"\n[*] Install with:")
        print(f"    python install_dependencies.py")
        return False
    else:
        print(f"\n[+] All dependencies installed!")
        return True


# ============================================================
# Attack Definitions
# ============================================================
ATTACKS = {
    "dos": {
        "name": "DoS (HTTP-layer)",
        "nids_class": "DoS",
        "description": "Hulk, Slowloris, GoldenEye, SlowHTTPTest",
    },
    "ddos": {
        "name": "DDoS (Multi-threaded)",
        "nids_class": "DDoS",
        "description": "LOIC-HTTP, LOIC-UDP, HOIC",
    },
    "brute-force": {
        "name": "Brute Force",
        "nids_class": "Brute Force",
        "description": "SSH + FTP credential attacks",
    },
    "botnet": {
        "name": "Botnet (C2)",
        "nids_class": "Botnet",
        "description": "Ares/Zeus: beaconing, exfil, keylog",
    },
    "infiltration": {
        "name": "Infiltration (Nmap)",
        "nids_class": "Infilteration",
        "description": "Port scanning, service detection",
    },
}


def run_attack(attack_type, target_ip, port=80, duration=30):
    """
    Run a single attack type for the specified duration.
    Randomly picks a sub-attack variant for variety.
    """
    # Log attack start
    log_attack(attack_type, target_ip, duration, status="started")
    
    try:
        if attack_type == "dos":
            # Randomly pick a DoS variant
            variant = random.choice(["hulk", "slowloris", "goldeneye", "slowpost"])
            print(f"  > {variant.upper()} DoS ({duration}s)...", end=" ", flush=True)
            if variant == "hulk":
                hulk_attack(target_ip, port, duration)
            elif variant == "slowloris":
                slowloris_attack(target_ip, port, duration)
            elif variant == "goldeneye":
                goldeneye_attack(target_ip, port, duration, threads=5)
            elif variant == "slowpost":
                slow_post_attack(target_ip, port, duration, socket_count=50)
            print("Done")
            
        elif attack_type == "ddos":
            # Randomly pick a DDoS variant
            variant = random.choice(["loic-http", "loic-udp", "hoic"])
            print(f"  > {variant.upper()} DDoS ({duration}s)...", end=" ", flush=True)
            if variant == "loic-http":
                loic_http(target_ip, port, duration, threads=15)
            elif variant == "loic-udp":
                loic_udp(target_ip, port, duration, threads=8)
            elif variant == "hoic":
                hoic_attack(target_ip, port, duration, threads=15)
            print("Done")
            
        elif attack_type == "brute-force":
            # Randomly pick SSH or FTP
            variant = random.choice(["ssh", "ftp"])
            print(f"  > {variant.upper()} Brute Force ({duration}s)...", end=" ", flush=True)
            ssh_port = 22
            ftp_port = 21
            if variant == "ssh":
                ssh_brute_force(target_ip, ssh_port, duration, threads=3)
            else:
                ftp_brute_force(target_ip, ftp_port, duration, threads=3)
            print("Done")
            
        elif attack_type == "botnet":
            # Randomly pick a botnet behavior
            variant = random.choice(["beacon", "exfil", "keylog", "full"])
            print(f"  > Botnet {variant.upper()} ({duration}s)...", end=" ", flush=True)
            if variant == "beacon":
                c2_beacon(target_ip, port, duration, beacon_interval=5)
            elif variant == "exfil":
                file_exfiltration(target_ip, port, duration)
            elif variant == "keylog":
                screenshot_keylog(target_ip, port, duration, screenshot_interval=15)
            else:
                full_botnet(target_ip, port, duration, beacon_interval=5)
            print("Done")
            
        elif attack_type == "infiltration":
            # Randomly pick scan type
            variant = random.choice(["common", "aggressive"])
            print(f"  > {variant.upper()} Port Scan ({duration}s)...", end=" ", flush=True)
            if variant == "aggressive":
                aggressive_scan(target_ip, duration, threads=8)
            else:
                tcp_connect_scan(target_ip, COMMON_PORTS, duration, threads=8)
            print("Done")
        
        # Log attack completion
        log_attack(attack_type, target_ip, duration, status="completed")
        return True
        
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        log_attack(attack_type, target_ip, duration, status="interrupted")
        return False
    except Exception as e:
        print(f"Error: {e}")
        log_attack(attack_type, target_ip, duration, status="failed")
        return False


def run_mixed_attacks(target_ip, attack_types, total_duration):
    """
    Run attacks in shuffled/mixed mode for total duration.
    Randomly selects attacks and runs each for random time.
    """
    print(f"\n{'='*70}")
    print(f"MIXED ATTACK MODE - Shuffled attacks for {total_duration}s total")
    print(f"{'='*70}\n")
    
    attack_names = [ATTACKS[a]["name"] for a in attack_types]
    print(f"[*] Attack types: {', '.join(attack_names)}\n")
    
    start_time = time.time()
    attack_num = 0
    min_duration = 20
    max_duration = 60
    
    try:
        while time.time() - start_time < total_duration:
            # Randomly pick an attack
            attack_type = random.choice(attack_types)
            
            # Random duration for this attack
            remaining = total_duration - (time.time() - start_time)
            if remaining < 10:
                break
            
            attack_duration = min(random.randint(min_duration, max_duration), int(remaining) - 5)
            
            attack_num += 1
            elapsed = time.time() - start_time
            
            print(f"[{attack_num:2d}] ({elapsed:5.0f}s) {ATTACKS[attack_type]['name']:25s} for {attack_duration:2d}s...", end=" ", flush=True)
            
            run_attack(attack_type, target_ip, port=80, duration=attack_duration)
            
            # Small gap between attacks
            time.sleep(1)
        
    except KeyboardInterrupt:
        print("\n\n[!] Attack sequence interrupted by user")
    
    total_elapsed = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"[+] Attack sequence complete!")
    print(f"    Total attacks: {attack_num}")
    print(f"    Total time: {total_elapsed:.1f}s / {total_duration}s")
    print(f"{'='*70}\n")


# ============================================================
# Main CLI
# ============================================================
def show_help():
    """Show help message"""
    print(f"""
{'='*70}
DEVICE ATTACK CLI - Network Intrusion Detection System (NIDS) Testing
{'='*70}

USAGE:
    python device_attack.py [TARGET_IP] [OPTIONS]

TARGET:
    TARGET_IP       Explicit IP address (auto-discovers if omitted)
    
ATTACK TYPES:
    --all           All 6 attacks (Default + Infiltration): DoS, DDoS, Brute Force, Botnet, Infiltration
    --default       5-class attacks only (no Infiltration): DoS, DDoS, Brute Force, Botnet
    --dos           DoS only
    --ddos          DDoS only
    --brute-force   Brute Force only
    --botnet        Botnet only
    --infiltration  Infiltration (port scan) only

COMBINED ATTACKS:
    --dos --ddos --botnet          Multiple specific attacks combined

OPTIONS:
    --duration SEC  Total duration in seconds (default: 120)
                    For SINGLE attack: runs that attack continuously for SEC seconds
                    For MULTIPLE attacks (--all, --default, or combined): 
                      shuffles attacks, total time is SEC seconds
    
UTILITIES:
    --discover-ip   Just discover target IP, don't attack
    --verify        Verify all dependencies are installed
    --help          Show this help message

EXAMPLES:

    # Single attack: DoS ONLY for 500 seconds (not shuffled)
    python device_attack.py 192.168.56.103 --dos --duration 500
    
    # Single attack: DDoS ONLY for 60 seconds
    python device_attack.py 192.168.56.103 --ddos --duration 60
    
    # Multiple attacks: shuffled for 5 minutes total
    python device_attack.py --all --duration 300
    
    # Multiple attacks: DoS+DDoS+Botnet shuffled for 3 minutes
    python device_attack.py --dos --ddos --botnet --duration 180
    
    # 5-class attacks (no infiltration) shuffled for 2 minutes
    python device_attack.py --default --duration 120
    
    # Just discover the target device IP (no attack)
    python device_attack.py --discover-ip
    
    # Check dependencies
    python device_attack.py --verify

DURATION BEHAVIOR:
    SINGLE ATTACK (e.g., --dos):
    > Runs ONLY DoS for the full duration (non-stop)
    
    MULTIPLE ATTACKS (e.g., --all or combined):
    > Shuffles/mixes attacks, runs total for the full duration
    > Each attack runs 20-60 seconds before switching to another

NIDS CLASSES DETECTED:
    Default Model (5-class):
      - DoS
      - DDoS
      - Brute Force
      - Botnet
    
    All Model (6-class):
      - DoS
      - DDoS
      - Brute Force
      - Botnet
      - Infilteration (port scanning)

{'='*70}
""")


def main():
    if not sys.argv[1:]:
        # No arguments - use defaults (--all, 120s duration)
        target_ip = discover_vm_ip()
        if not target_ip:
            print("\n[!] Could not auto-discover target. Provide explicit IP:")
            print("    python device_attack.py 192.168.56.103 --all --duration 120")
            sys.exit(1)
        
        print(f"\n[+] Using discovered IP: {target_ip}")
        attack_types = list(ATTACKS.keys())  # --all default
        total_duration = 120
        
        print(f"[+] Attack types: {', '.join([ATTACKS[a]['name'] for a in attack_types])}")
        print(f"[+] Total duration: {total_duration}s (shuffled - no attack type specified)\n")
        run_mixed_attacks(target_ip, attack_types, total_duration)
        return
    
    # Parse arguments
    target_ip = None
    attack_types = []
    total_duration = 120
    
    for arg in sys.argv[1:]:
        if arg in ("--help", "-h"):
            show_help()
            return
        elif arg == "--discover-ip":
            ip = discover_vm_ip()
            if ip:
                print(f"\n[+] Target IP: {ip}\n")
            else:
                print("\n[!] Could not discover target IP\n")
            return
        elif arg == "--verify":
            verify_dependencies()
            return
        elif arg == "--all":
            attack_types = list(ATTACKS.keys())
        elif arg == "--default":
            attack_types = ["dos", "ddos", "brute-force", "botnet"]  # No infiltration
        elif arg in ATTACKS.keys():
            attack_types.append(arg)
        elif arg == "--duration" or (arg.startswith("--") and "=" not in arg):
            # Handle --duration in next iteration
            pass
        elif arg.startswith("--duration"):
            if "=" in arg:
                total_duration = int(arg.split("=")[1])
            continue
        elif not arg.startswith("--") and not target_ip:
            # Assume it's the IP address if it looks like one
            if arg.count(".") == 3:
                target_ip = arg
    
    # Parse duration
    if "--duration" in sys.argv:
        idx = sys.argv.index("--duration")
        if idx + 1 < len(sys.argv):
            try:
                total_duration = int(sys.argv[idx + 1])
            except ValueError:
                pass
    
    # Default to --all if no attack type specified
    if not attack_types:
        attack_types = list(ATTACKS.keys())
    
    # Auto-discover if no IP provided
    if not target_ip:
        target_ip = discover_vm_ip()
        if not target_ip:
            print("\n[!] Could not auto-discover target. Provide explicit IP:")
            print("    python device_attack.py 192.168.56.103 --all --duration 120")
            sys.exit(1)
    
    print(f"\n[+] Target: {target_ip}")
    print(f"[+] Attack types: {', '.join([ATTACKS[a]['name'] for a in attack_types])}")
    
    # LOGIC: Single attack runs continuously; multiple attacks run shuffled
    if len(attack_types) == 1:
        # Single attack type specified - run it continuously for full duration
        print(f"[+] Total duration: {total_duration}s (continuous)\n")
        run_attack(attack_types[0], target_ip, port=80, duration=total_duration)
    else:
        # Multiple attacks OR --all OR --default - run shuffled/mixed for total duration
        print(f"[+] Total duration: {total_duration}s (shuffled)\n")
        run_mixed_attacks(target_ip, attack_types, total_duration)
    
    # Generate attack report
    print(f"\n[*] Generating attack report...")
    generate_attack_reports()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
