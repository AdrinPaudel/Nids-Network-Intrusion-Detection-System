"""
Attacker VM Setup — Run this ON the attacker Ubuntu VM.

Installs all attack tools used in the CICIDS2018 dataset:
  - Patator (SSH/FTP brute-force — Python, multi-threaded)
  - Slowloris (DoS — slow headers)
  - GoldenEye (DoS — HTTP Keep-Alive flood)
  - Hulk (DoS — randomized HTTP flood)
  - SlowHTTPTest (DoS — slow POST/headers/read)
  - hping3 (DDoS — TCP/UDP/ICMP flood)
  - Network tuning (TCP stack + latency to match dataset)

Usage:
  sudo python3 attacker_setup.py --all              # Full setup
  sudo python3 attacker_setup.py --install           # Install tools only
  sudo python3 attacker_setup.py --tune-network      # Network tuning only
  sudo python3 attacker_setup.py --status            # Check tool availability
  sudo python3 attacker_setup.py --set-ip 172.31.70.4 # Set static IP
"""

import subprocess
import sys
import os
import argparse


# ============================================================
# CONFIGURATION
# ============================================================

ATTACKER_IP = "172.31.70.4"
ATTACKER_SUBNET = "24"
VICTIM_SUBNET = "172.31.69.0/24"

# Tools install dir
TOOLS_DIR = os.path.expanduser("~/nids_attack_tools")

# Network tuning (match dataset conditions)
SYSCTL_SETTINGS = {
    "net.ipv4.tcp_timestamps": "1",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_congestion_control": "cubic",
    "net.core.rmem_default": "212992",
    "net.core.wmem_default": "212992",
}

LATENCY_MS = "1ms"
LATENCY_JITTER = "0.3ms"
PACKET_LOSS = "0.1%"
MTU = 1500


# ============================================================
# HELPERS
# ============================================================

def run(cmd, check=True, capture=False):
    """Run shell command."""
    print(f"  [RUN] {cmd}")
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture, text=True)


def check_root():
    euid_fn = getattr(os, 'geteuid', None)
    if euid_fn is not None and euid_fn() != 0:
        print("[ERROR] This script must be run as root (sudo).")
        sys.exit(1)


def detect_interface():
    result = run("ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1",
                  capture=True, check=False)
    iface = result.stdout.strip()
    return iface if iface else "enp0s3"


# ============================================================
# INSTALLATION
# ============================================================

def install_tools():
    """Install all attack tools."""
    print("\n" + "=" * 60)
    print("  INSTALLING ATTACK TOOLS")
    print("=" * 60)

    run("apt-get update -y")

    # System dependencies
    print("\n--- System dependencies ---")
    run("apt-get install -y python3 python3-pip python3-venv git curl "
        "net-tools iproute2 hping3 nmap")

    # Python packages for attacks
    print("\n--- Python attack packages ---")
    run("pip3 install patator 2>/dev/null || pip3 install patator --break-system-packages",
        check=False)
    run("pip3 install requests 2>/dev/null || pip3 install requests --break-system-packages",
        check=False)

    # SlowHTTPTest (C++ tool from package manager)
    print("\n--- SlowHTTPTest ---")
    run("apt-get install -y slowhttptest", check=False)

    # Create tools directory
    os.makedirs(TOOLS_DIR, exist_ok=True)

    # GoldenEye (Python DoS tool)
    print("\n--- GoldenEye ---")
    goldeneye_dir = os.path.join(TOOLS_DIR, "GoldenEye")
    if not os.path.exists(goldeneye_dir):
        run(f"git clone https://github.com/jseidl/GoldenEye.git {goldeneye_dir}",
            check=False)
    else:
        print("  GoldenEye already cloned.")

    # Slowloris (Python)
    print("\n--- Slowloris ---")
    run("pip3 install slowloris 2>/dev/null || pip3 install slowloris --break-system-packages",
        check=False)

    # Create a small wordlist for brute-force testing
    print("\n--- Creating test wordlists ---")
    wordlist_dir = os.path.join(TOOLS_DIR, "wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    # Username list
    users_file = os.path.join(wordlist_dir, "users.txt")
    with open(users_file, 'w') as f:
        users = ["admin", "root", "user", "test", "testuser", "guest",
                 "administrator", "www", "ftp", "nobody", "daemon",
                 "operator", "nagios", "backup", "postgres"]
        f.write("\n".join(users) + "\n")

    # Password list (small for testing — real dataset used 90M)
    passwords_file = os.path.join(wordlist_dir, "passwords.txt")
    with open(passwords_file, 'w') as f:
        passwords = [
            "password", "123456", "password123", "admin", "root",
            "letmein", "welcome", "monkey", "dragon", "master",
            "qwerty", "login", "abc123", "starwars", "trustno1",
            "iloveyou", "shadow", "12345", "1234567890", "passw0rd",
            "football", "access", "hello", "charlie", "batman",
            "superman", "michael", "696969", "123123", "654321",
            "hottie", "loveme", "andrea", "nicole", "hunter",
            "sunshine", "princess", "ashley", "whatever", "baseball",
            "!!@@##", "test", "test123", "p@ssword", "Pass1234",
            "letmein1", "Pa$$w0rd", "server", "changeme", "secret",
            "password1", "pass123", "admin123", "root123", "user123",
            "qwerty123", "welcome1", "shadow1", "123qwe", "123abc",
        ]
        f.write("\n".join(passwords) + "\n")

    print(f"  Users: {users_file} ({len(users)} entries)")
    print(f"  Passwords: {passwords_file} ({len(passwords)} entries)")

    print(f"\n[OK] All tools installed. Tools dir: {TOOLS_DIR}")


# ============================================================
# NETWORK TUNING
# ============================================================

def tune_network():
    """Apply TCP/network tuning to match dataset conditions."""
    print("\n" + "=" * 60)
    print("  NETWORK TUNING (match dataset conditions)")
    print("=" * 60)

    iface = detect_interface()
    print(f"\n  Detected interface: {iface}")

    # sysctl
    print("\n--- Applying sysctl TCP settings ---")
    for key, value in SYSCTL_SETTINGS.items():
        run(f"sysctl -w {key}={value}")

    # MTU
    print(f"\n--- Setting MTU to {MTU} ---")
    run(f"ip link set {iface} mtu {MTU}")

    # Latency
    print(f"\n--- Adding artificial latency: {LATENCY_MS} ±{LATENCY_JITTER} ---")
    run(f"tc qdisc del dev {iface} root", check=False)
    run(f"tc qdisc add dev {iface} root netem delay {LATENCY_MS} {LATENCY_JITTER} "
        f"distribution normal loss {PACKET_LOSS}")

    # Persist
    sysctl_conf = "/etc/sysctl.conf"
    with open(sysctl_conf, 'r') as f:
        existing = f.read()
    for key, value in SYSCTL_SETTINGS.items():
        entry = f"{key}={value}"
        if entry not in existing:
            with open(sysctl_conf, 'a') as f:
                f.write(f"\n{entry}")
    run("sysctl -p", check=False)

    print(f"\n[OK] Network tuned.")


# ============================================================
# STATIC IP
# ============================================================

def set_static_ip(ip_address):
    """Set static IP for VirtualBox Internal Network / Host-Only."""
    print("\n" + "=" * 60)
    print(f"  SETTING STATIC IP: {ip_address}/{ATTACKER_SUBNET}")
    print("=" * 60)

    iface = detect_interface()
    run(f"ip addr flush dev {iface}")
    run(f"ip addr add {ip_address}/{ATTACKER_SUBNET} dev {iface}")
    run(f"ip link set {iface} up")
    run(f"ip route add {VICTIM_SUBNET} dev {iface}", check=False)

    print(f"\n[OK] Static IP set: {ip_address}/{ATTACKER_SUBNET} on {iface}")


# ============================================================
# STATUS CHECK
# ============================================================

def check_status():
    """Check all tools are available."""
    print("\n" + "=" * 60)
    print("  ATTACKER VM STATUS CHECK")
    print("=" * 60)

    iface = detect_interface()

    # Network
    print(f"\n--- Network ({iface}) ---")
    run(f"ip addr show {iface}", check=False)
    run(f"tc qdisc show dev {iface}", check=False)

    # Tools availability
    tools = [
        ("patator", "patator --help 2>/dev/null | head -1"),
        ("slowloris", "python3 -c 'import slowloris; print(\"OK\")' 2>/dev/null"),
        ("slowhttptest", "which slowhttptest"),
        ("hping3", "which hping3"),
        ("nmap", "nmap --version | head -1"),
        ("python3", "python3 --version"),
        ("GoldenEye", f"test -d {os.path.join(TOOLS_DIR, 'GoldenEye')} && echo 'OK' || echo 'NOT FOUND'"),
    ]

    print("\n--- Tool Availability ---")
    for name, cmd in tools:
        result = run(cmd, check=False, capture=True)
        status = "OK" if result.returncode == 0 and result.stdout.strip() else "MISSING"
        out = result.stdout.strip()[:60] if result.stdout else ""
        print(f"  {name:20s}: {status:8s} {out}")

    # Wordlists
    print(f"\n--- Wordlists ---")
    wl_dir = os.path.join(TOOLS_DIR, "wordlists")
    for f in ["users.txt", "passwords.txt"]:
        path = os.path.join(wl_dir, f)
        if os.path.exists(path):
            lines = sum(1 for _ in open(path))
            print(f"  {f}: {lines} entries")
        else:
            print(f"  {f}: NOT FOUND")

    print("\n[OK] Status check complete.")


# ============================================================
# UNDO
# ============================================================

def undo_network():
    """Remove artificial latency."""
    iface = detect_interface()
    run(f"tc qdisc del dev {iface} root", check=False)
    print(f"\n[OK] Removed tc qdisc from {iface}.")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Attacker VM Setup — Install attack tools for NIDS testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 attacker_setup.py --all
  sudo python3 attacker_setup.py --install
  sudo python3 attacker_setup.py --tune-network
  sudo python3 attacker_setup.py --status
  sudo python3 attacker_setup.py --set-ip 172.31.70.4
        """
    )

    parser.add_argument("--all", action="store_true", help="Full setup: install + tune")
    parser.add_argument("--install", action="store_true", help="Install attack tools")
    parser.add_argument("--tune-network", action="store_true", help="Apply network tuning")
    parser.add_argument("--status", action="store_true", help="Check tool availability")
    parser.add_argument("--set-ip", type=str, default=None, help="Set static IP")
    parser.add_argument("--undo-network", action="store_true", help="Remove latency/loss")

    args = parser.parse_args()

    if not any([args.all, args.install, args.tune_network, args.status,
                args.set_ip, args.undo_network]):
        parser.print_help()
        return

    if not args.status:
        check_root()

    if args.all:
        install_tools()
        tune_network()
        check_status()
    else:
        if args.install:
            install_tools()
        if args.set_ip:
            set_static_ip(args.set_ip)
        if args.tune_network:
            tune_network()
        if args.undo_network:
            undo_network()
        if args.status:
            check_status()


if __name__ == "__main__":
    main()
