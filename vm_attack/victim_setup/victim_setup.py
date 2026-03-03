"""
Victim VM Setup — Run this ON the victim Ubuntu VM (defender).

Installs and configures:
  - Apache2 (HTTP server on port 80) — target for DoS/DDoS/Web attacks
  - OpenSSH server (port 22) — target for SSH brute-force
  - vsftpd (FTP server on port 21) — target for FTP brute-force
  - Network tuning (TCP stack params to match AWS/dataset conditions)
  - Firewall rules (open required ports)
  - Artificial latency (tc netem) to simulate real LAN

Usage:
  sudo python3 victim_setup.py --all                # Full setup (install + config + tune)
  sudo python3 victim_setup.py --install             # Install services only
  sudo python3 victim_setup.py --configure           # Configure services only
  sudo python3 victim_setup.py --tune-network        # Network tuning only
  sudo python3 victim_setup.py --status              # Check status of all services
  sudo python3 victim_setup.py --set-ip 172.31.69.25 # Set static IP (for Internal Network mode)
"""

import subprocess
import sys
import os
import argparse
import time


# ============================================================
# CONFIGURATION — Match dataset conditions
# ============================================================

# IP addresses (matching CICIDS2018 subnet scheme)
VICTIM_IP = "172.31.69.25"
VICTIM_SUBNET = "24"
ATTACKER_SUBNET = "172.31.70.0/24"

# Services to install
SERVICES = {
    "apache2": {"port": 80, "protocol": "tcp", "description": "Apache HTTP Server (DoS/DDoS target)"},
    "ssh":     {"port": 22, "protocol": "tcp", "description": "OpenSSH Server (brute-force target)"},
    "vsftpd":  {"port": 21, "protocol": "tcp", "description": "vsftpd FTP Server (brute-force target)"},
}

# Test user for brute-force targets (weak credentials on purpose)
TEST_USER = "testuser"
TEST_PASSWORD = "password123"

# Network tuning (match AWS Ubuntu 16.04 TCP defaults)
SYSCTL_SETTINGS = {
    "net.ipv4.tcp_timestamps": "1",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_congestion_control": "cubic",
    "net.core.rmem_default": "212992",
    "net.core.wmem_default": "212992",
    "net.core.rmem_max": "212992",
    "net.core.wmem_max": "212992",
}

# Artificial latency to simulate real network (tc netem)
LATENCY_MS = "1ms"
LATENCY_JITTER = "0.3ms"
PACKET_LOSS = "0.1%"
MTU = 1500


# ============================================================
# HELPERS
# ============================================================

def run(cmd, check=True, capture=False):
    """Run a shell command."""
    print(f"  [RUN] {cmd}")
    result = subprocess.run(
        cmd, shell=True, check=check,
        capture_output=capture, text=True
    )
    return result


def check_root():
    """Ensure running as root."""
    euid_fn = getattr(os, 'geteuid', None)
    if euid_fn is not None and euid_fn() != 0:
        print("[ERROR] This script must be run as root (sudo).")
        sys.exit(1)


def detect_interface():
    """Detect the primary network interface (not loopback)."""
    result = run("ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1",
                  capture=True, check=False)
    iface = result.stdout.strip()
    if not iface:
        # Fallback
        iface = "enp0s3"
    return iface


# ============================================================
# INSTALLATION
# ============================================================

def install_services():
    """Install Apache2, OpenSSH, and vsftpd."""
    print("\n" + "=" * 60)
    print("  INSTALLING SERVICES")
    print("=" * 60)

    run("apt-get update -y")

    # Apache2
    print("\n--- Installing Apache2 ---")
    run("apt-get install -y apache2")
    run("systemctl enable apache2")
    run("systemctl start apache2")

    # OpenSSH
    print("\n--- Installing OpenSSH Server ---")
    run("apt-get install -y openssh-server")
    run("systemctl enable ssh")
    run("systemctl start ssh")

    # vsftpd
    print("\n--- Installing vsftpd (FTP) ---")
    run("apt-get install -y vsftpd")
    run("systemctl enable vsftpd")

    # Install net-tools and iproute2 for network config
    print("\n--- Installing network tools ---")
    run("apt-get install -y net-tools iproute2")

    print("\n[OK] All services installed.")


# ============================================================
# CONFIGURATION
# ============================================================

def configure_services():
    """Configure services for attack testing."""
    print("\n" + "=" * 60)
    print("  CONFIGURING SERVICES")
    print("=" * 60)

    # --- Create test user for brute-force ---
    print(f"\n--- Creating test user '{TEST_USER}' ---")
    result = run(f"id {TEST_USER}", check=False, capture=True)
    if result.returncode != 0:
        run(f"useradd -m -s /bin/bash {TEST_USER}")
        run(f"echo '{TEST_USER}:{TEST_PASSWORD}' | chpasswd")
        print(f"  Created user '{TEST_USER}' with password '{TEST_PASSWORD}'")
    else:
        run(f"echo '{TEST_USER}:{TEST_PASSWORD}' | chpasswd")
        print(f"  User '{TEST_USER}' already exists — password reset.")

    # --- Configure SSH to allow password auth ---
    print("\n--- Configuring SSH for password authentication ---")
    sshd_config = "/etc/ssh/sshd_config"

    # Read current config
    with open(sshd_config, 'r') as f:
        config_text = f.read()

    # Ensure PasswordAuthentication yes
    changes = {
        "PasswordAuthentication": "yes",
        "PermitRootLogin": "no",
        "MaxAuthTries": "100",      # Allow many attempts (for brute-force testing)
        "LoginGraceTime": "120",
        "MaxStartups": "100:30:200",  # Allow many concurrent auth attempts
    }

    for key, value in changes.items():
        # Remove any existing line (commented or not)
        import re
        config_text = re.sub(
            rf'^#?\s*{key}\s+.*$',
            f'{key} {value}',
            config_text,
            flags=re.MULTILINE
        )
        # If not found, append
        if key not in config_text:
            config_text += f"\n{key} {value}\n"

    with open(sshd_config, 'w') as f:
        f.write(config_text)

    run("systemctl restart ssh")
    print("  SSH configured: PasswordAuthentication=yes, MaxAuthTries=100")

    # --- Configure vsftpd for local user login ---
    print("\n--- Configuring vsftpd (FTP) ---")
    vsftpd_config = "/etc/vsftpd.conf"

    vsftpd_content = """# vsftpd config for NIDS brute-force testing
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
pam_service_name=vsftpd
userlist_enable=NO
# Allow many login attempts
max_login_fails=1000
"""

    with open(vsftpd_config, 'w') as f:
        f.write(vsftpd_content)

    run("systemctl restart vsftpd")
    print("  vsftpd configured: local_enable=YES, anonymous=NO")

    # --- Configure Apache ---
    print("\n--- Ensuring Apache is running ---")
    run("systemctl restart apache2")

    # --- Open firewall ports ---
    print("\n--- Configuring firewall ---")
    result = run("which ufw", check=False, capture=True)
    if result.returncode == 0:
        run("ufw allow 80/tcp")
        run("ufw allow 22/tcp")
        run("ufw allow 21/tcp")
        run("ufw allow 443/tcp")
        # Allow all from attacker subnet
        run(f"ufw allow from {ATTACKER_SUBNET}")
        run("ufw --force enable", check=False)
        print("  Firewall: ports 80, 22, 21, 443 open.")
    else:
        print("  ufw not installed — no firewall rules needed.")

    print("\n[OK] All services configured.")


# ============================================================
# NETWORK TUNING
# ============================================================

def tune_network():
    """Apply TCP stack tuning and artificial latency to match dataset conditions."""
    print("\n" + "=" * 60)
    print("  NETWORK TUNING (match AWS/dataset conditions)")
    print("=" * 60)

    iface = detect_interface()
    print(f"\n  Detected interface: {iface}")

    # --- sysctl TCP stack parameters ---
    print("\n--- Applying sysctl TCP settings ---")
    for key, value in SYSCTL_SETTINGS.items():
        run(f"sysctl -w {key}={value}")
    print("  TCP timestamps=ON, window_scaling=ON, congestion=cubic")

    # --- MTU ---
    print(f"\n--- Setting MTU to {MTU} ---")
    run(f"ip link set {iface} mtu {MTU}")

    # --- Artificial latency ---
    print(f"\n--- Adding artificial latency: {LATENCY_MS} ±{LATENCY_JITTER}, loss={PACKET_LOSS} ---")
    # Remove any existing qdisc first
    run(f"tc qdisc del dev {iface} root", check=False)
    run(f"tc qdisc add dev {iface} root netem delay {LATENCY_MS} {LATENCY_JITTER} "
        f"distribution normal loss {PACKET_LOSS}")

    # --- Persist sysctl ---
    print("\n--- Persisting sysctl settings ---")
    sysctl_conf = "/etc/sysctl.conf"
    with open(sysctl_conf, 'r') as f:
        existing = f.read()

    for key, value in SYSCTL_SETTINGS.items():
        entry = f"{key}={value}"
        if entry not in existing:
            with open(sysctl_conf, 'a') as f:
                f.write(f"\n{entry}")

    run("sysctl -p", check=False)

    print(f"\n[OK] Network tuned: MTU={MTU}, latency={LATENCY_MS}, TCP stack matched.")


# ============================================================
# STATIC IP ASSIGNMENT
# ============================================================

def set_static_ip(ip_address):
    """Set a static IP address for VirtualBox Internal Network / Host-Only mode."""
    print("\n" + "=" * 60)
    print(f"  SETTING STATIC IP: {ip_address}/{VICTIM_SUBNET}")
    print("=" * 60)

    iface = detect_interface()
    print(f"\n  Detected interface: {iface}")

    # Flush existing IPs
    run(f"ip addr flush dev {iface}")
    # Set new IP
    run(f"ip addr add {ip_address}/{VICTIM_SUBNET} dev {iface}")
    run(f"ip link set {iface} up")

    # Add route to attacker subnet
    run(f"ip route add {ATTACKER_SUBNET} dev {iface}", check=False)

    print(f"\n[OK] Static IP set: {ip_address}/{VICTIM_SUBNET} on {iface}")
    print(f"     Route added: {ATTACKER_SUBNET} via {iface}")


# ============================================================
# STATUS CHECK
# ============================================================

def check_status():
    """Check status of all services and network config."""
    print("\n" + "=" * 60)
    print("  VICTIM VM STATUS CHECK")
    print("=" * 60)

    iface = detect_interface()

    # IP address
    print(f"\n--- Network ({iface}) ---")
    run(f"ip addr show {iface}", check=False)

    # MTU
    print(f"\n--- MTU ---")
    run(f"ip link show {iface} | grep mtu", check=False)

    # tc qdisc (latency)
    print(f"\n--- Traffic Control (latency/loss) ---")
    run(f"tc qdisc show dev {iface}", check=False)

    # Services
    for service, info in SERVICES.items():
        print(f"\n--- {info['description']} (port {info['port']}) ---")
        run(f"systemctl is-active {service}", check=False)

    # Open ports
    print(f"\n--- Listening ports ---")
    run("ss -tlnp | grep -E ':(80|22|21|443) '", check=False)

    # sysctl
    print(f"\n--- TCP stack settings ---")
    for key in SYSCTL_SETTINGS:
        run(f"sysctl {key}", check=False)

    # Test user
    print(f"\n--- Test user ---")
    run(f"id {TEST_USER}", check=False)

    print("\n[OK] Status check complete.")


# ============================================================
# UNDO — Remove latency and reset
# ============================================================

def undo_network():
    """Remove artificial latency and reset network tuning."""
    print("\n" + "=" * 60)
    print("  REMOVING NETWORK TUNING")
    print("=" * 60)

    iface = detect_interface()
    run(f"tc qdisc del dev {iface} root", check=False)
    print(f"\n[OK] Removed tc qdisc from {iface}. Latency/loss reset.")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Victim VM Setup — Install and configure services for NIDS attack testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 victim_setup.py --all
  sudo python3 victim_setup.py --install
  sudo python3 victim_setup.py --tune-network
  sudo python3 victim_setup.py --status
  sudo python3 victim_setup.py --set-ip 172.31.69.25
  sudo python3 victim_setup.py --undo-network
        """
    )

    parser.add_argument("--all", action="store_true",
                        help="Full setup: install + configure + network tune")
    parser.add_argument("--install", action="store_true",
                        help="Install Apache2, SSH, FTP")
    parser.add_argument("--configure", action="store_true",
                        help="Configure services (users, firewall, SSH settings)")
    parser.add_argument("--tune-network", action="store_true",
                        help="Apply TCP tuning + artificial latency")
    parser.add_argument("--status", action="store_true",
                        help="Check status of all services and network")
    parser.add_argument("--set-ip", type=str, default=None,
                        help="Set static IP (e.g., 172.31.69.25)")
    parser.add_argument("--undo-network", action="store_true",
                        help="Remove artificial latency and reset tc qdisc")

    args = parser.parse_args()

    # If no args, print help
    if not any([args.all, args.install, args.configure, args.tune_network,
                args.status, args.set_ip, args.undo_network]):
        parser.print_help()
        return

    # Check root for everything except --status
    if not args.status:
        check_root()

    if args.all:
        install_services()
        configure_services()
        tune_network()
        check_status()
    else:
        if args.install:
            install_services()
        if args.configure:
            configure_services()
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
