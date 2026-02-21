#!/usr/bin/env python
"""
VM Attack Setup Check - Cross-Platform
Checks if the VM is ready to receive attacks. Asks before changing anything.

Usage:
    Linux:   sudo python setup_vm.py
    Windows: python setup_vm.py  (run as Administrator)

What it checks:
    1. Network interfaces and VM IP
    2. SSH server (installed? running?) — asks before installing/starting
    3. Firewall rules (Windows) — asks before adding
    4. libpcap / Npcap — tells you if missing
    5. NIDS project, venv, trained models
    6. Packet capture permissions (Linux) — asks before granting
"""

import sys
import os
import subprocess
import socket
import platform


def is_admin():
    """Check if running with admin/root privileges"""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def run_cmd(cmd, shell=True, check=False):
    """Run a command and return (success, output)"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout.strip()
    except Exception as e:
        return False, str(e)


def ask_yes_no(prompt):
    """Ask user a yes/no question, return True if yes"""
    try:
        answer = input(f"  {prompt} [y/n]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def get_all_ips():
    """Get all local IP addresses"""
    ips = []
    try:
        if sys.platform == "win32":
            ok, out = run_cmd("ipconfig")
            if ok:
                for line in out.splitlines():
                    if "IPv4" in line and ":" in line:
                        ip = line.split(":")[-1].strip()
                        if ip and not ip.startswith("127."):
                            ips.append(ip)
        else:
            ok, out = run_cmd("ip -4 addr show")
            if ok:
                for line in out.splitlines():
                    if "inet " in line and "127.0.0" not in line:
                        ip = line.strip().split()[1].split("/")[0]
                        ips.append(ip)
    except:
        pass

    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except:
            pass

    return ips


def find_nids_dir():
    """Find the NIDS project directory"""
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Nids"),
        os.path.join(home, "nids"),
        os.path.join(home, "NIDS"),
        os.path.join(home, "Nids-Network-Intrusion-Detection-System"),
        os.path.join(home, "nids-network-intrusion-detection-system"),
        os.path.join(home, "Desktop", "Nids"),
        os.path.join(home, "Desktop", "Nids-Network-Intrusion-Detection-System"),
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ]
    for path in candidates:
        if os.path.isfile(os.path.join(path, "classification.py")):
            return path
    return None


# ==================================================================
# Linux Setup
# ==================================================================
def setup_linux():
    issues = 0

    # --- SSH Server ---
    print("  [1] Checking SSH Server (needed for Brute Force attack)...")
    print()

    ssh_installed = False
    ssh_running = False

    # Check installed
    ok1, _ = run_cmd("dpkg -l openssh-server 2>/dev/null | grep -q '^ii'")
    ok2, _ = run_cmd("rpm -q openssh-server 2>/dev/null")
    ok3, _ = run_cmd("command -v sshd")

    if ok1 or ok2 or ok3:
        ssh_installed = True
        print("      [OK] openssh-server is installed")
    else:
        print("      [!] openssh-server is NOT installed")
        print("          Needed for the Brute Force attack.")
        print()
        if ask_yes_no("Install openssh-server?"):
            print("      Installing...")
            if os.path.exists("/usr/bin/apt-get"):
                run_cmd("apt-get update -qq")
                ok, _ = run_cmd("apt-get install -y -qq openssh-server")
            elif os.path.exists("/usr/bin/dnf"):
                ok, _ = run_cmd("dnf install -y openssh-server")
            elif os.path.exists("/usr/bin/yum"):
                ok, _ = run_cmd("yum install -y openssh-server")
            elif os.path.exists("/usr/bin/pacman"):
                ok, _ = run_cmd("pacman -S --noconfirm openssh")
            else:
                ok = False
                print("      [!] Unknown package manager")

            ok_check, _ = run_cmd("command -v sshd")
            if ok_check:
                ssh_installed = True
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
                issues += 1
        else:
            print("      [SKIP] Not installing")
            print("      To install manually: sudo apt install openssh-server")
            issues += 1

    # Check running
    if ssh_installed:
        ok1, _ = run_cmd("systemctl is-active --quiet ssh")
        ok2, _ = run_cmd("systemctl is-active --quiet sshd")
        if ok1 or ok2:
            ssh_running = True
            print("      [OK] SSH service is running")
        else:
            print("      [!] SSH is installed but NOT running")
            print()
            if ask_yes_no("Start SSH service?"):
                run_cmd("systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null")
                run_cmd("systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null")
                ok1, _ = run_cmd("systemctl is-active --quiet ssh")
                ok2, _ = run_cmd("systemctl is-active --quiet sshd")
                if ok1 or ok2:
                    print("      [OK] SSH started")
                else:
                    print("      [!] Failed to start SSH")
                    issues += 1
            else:
                print("      [SKIP] SSH not started")
                print("      To start manually: sudo systemctl start ssh")
                issues += 1

    print()

    # --- libpcap ---
    print("  [2] Checking libpcap (needed by NIDS for packet capture)...")
    print()

    libpcap_found = False
    ok, out = run_cmd("ldconfig -p 2>/dev/null | grep libpcap")
    if ok and "libpcap" in out:
        libpcap_found = True
    else:
        for path in [
            "/usr/lib/x86_64-linux-gnu/libpcap.so",
            "/usr/lib/x86_64-linux-gnu/libpcap.so.1",
            "/usr/lib/libpcap.so",
            "/usr/lib/libpcap.so.1",
        ]:
            if os.path.exists(path):
                libpcap_found = True
                break

    if libpcap_found:
        print("      [OK] libpcap found")
    else:
        print("      [!] libpcap NOT found — NIDS packet capture won't work")
        print("      To install: sudo apt install libpcap-dev")
        issues += 1

    print()

    # --- net-tools ---
    print("  [3] Checking network tools...")
    print()
    ok, _ = run_cmd("command -v ifconfig")
    if ok:
        print("      [OK] net-tools installed")
    else:
        print("      [-] net-tools not installed (optional)")
        print("      To install: sudo apt install net-tools")

    print()

    # --- Packet capture permissions ---
    print("  [4] Checking packet capture permissions...")
    print()

    nids_dir = find_nids_dir()
    if nids_dir and os.path.isdir(os.path.join(nids_dir, "venv")):
        venv_python = os.path.join(nids_dir, "venv", "bin", "python3")
        if not os.path.exists(venv_python):
            venv_python = os.path.join(nids_dir, "venv", "bin", "python")

        if os.path.exists(venv_python):
            ok, real_path = run_cmd(f"readlink -f {venv_python}")
            if ok and real_path:
                ok_cap, caps = run_cmd(f"getcap {real_path}")
                if ok_cap and "cap_net_raw" in caps:
                    print(f"      [OK] cap_net_raw already set on: {real_path}")
                    print("      (Can run classification.py without sudo)")
                else:
                    print(f"      [!] cap_net_raw NOT set on: {real_path}")
                    print("          Without this you must use sudo to run NIDS.")
                    print()
                    if ask_yes_no("Grant packet capture permission?"):
                        run_cmd(f"setcap cap_net_raw,cap_net_admin=eip {real_path}")
                        ok_v, caps_v = run_cmd(f"getcap {real_path}")
                        if ok_v and "cap_net_raw" in caps_v:
                            print("      [OK] Granted")
                        else:
                            print("      [!] Failed — use sudo to run NIDS instead")
                    else:
                        print("      [SKIP] Not granting")
                        print(f"      To do manually: sudo setcap cap_net_raw,cap_net_admin=eip {real_path}")
                        print("      Or use: sudo ./venv/bin/python classification.py")
            else:
                print("      [!] Could not resolve python path")
                print("      Use: sudo ./venv/bin/python classification.py")
        else:
            print("      [!] venv python binary not found — run setup.sh first")
    else:
        print("      [SKIP] No NIDS venv found")
        print("      Use: sudo ./venv/bin/python classification.py")

    print()
    return issues


# ==================================================================
# Windows Setup
# ==================================================================
def setup_windows():
    issues = 0

    # --- SSH Server ---
    print("  [1] Checking SSH Server (needed for Brute Force attack)...")
    print()

    ok, _ = run_cmd("sc query sshd")
    if ok:
        # Installed — check running
        ok_run, out = run_cmd('sc query sshd | findstr "RUNNING"')
        if ok_run:
            print("      [OK] OpenSSH Server is installed and running")
        else:
            print("      [!] OpenSSH Server is installed but NOT running")
            print()
            if ask_yes_no("Start SSH service?"):
                run_cmd("sc config sshd start= auto")
                run_cmd("net start sshd")
                ok_run2, _ = run_cmd('sc query sshd | findstr "RUNNING"')
                if ok_run2:
                    print("      [OK] SSH started")
                else:
                    print("      [!] Failed to start SSH")
                    issues += 1
            else:
                print("      [SKIP] SSH not started")
                print("      To start manually:")
                print("        sc config sshd start= auto")
                print("        net start sshd")
                issues += 1
    else:
        print("      [!] OpenSSH Server is NOT installed")
        print("          Needed for the Brute Force attack.")
        print()
        if ask_yes_no("Install OpenSSH Server?"):
            print("      Installing...")
            ok_inst, _ = run_cmd('powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"')
            if ok_inst:
                print("      [OK] Installed")
                print()
                if ask_yes_no("Start SSH now?"):
                    run_cmd("sc config sshd start= auto")
                    run_cmd("net start sshd")
                    print("      [OK] SSH started")
                else:
                    print("      [SKIP] SSH not started")
                    print("      To start: net start sshd")
            else:
                print("      [!] Failed to install")
                print("      Install manually:")
                print("        Settings > Apps > Optional Features > Add a feature > OpenSSH Server")
                issues += 1
        else:
            print("      [SKIP] Not installing SSH")
            print("      To install manually:")
            print("        Settings > Apps > Optional Features > Add a feature > OpenSSH Server")
            issues += 1

    print()

    # --- Firewall ---
    print("  [2] Checking Firewall rules...")
    print()

    rules = {
        "NIDS-SSH": ("tcp", "22"),
        "NIDS-Ping": ("icmpv4", None),
        "NIDS-Port-80": ("tcp", "80"),
        "NIDS-Port-443": ("tcp", "443"),
        "NIDS-Port-8080": ("tcp", "8080"),
        "NIDS-Port-8443": ("tcp", "8443"),
    }

    missing_rules = []
    for name, (proto, port) in rules.items():
        ok, _ = run_cmd(f'netsh advfirewall firewall show rule name="{name}"')
        if ok:
            label = f"port {port}" if port else proto
            print(f"      [OK] {name} ({label})")
        else:
            label = f"port {port}" if port else proto
            print(f"      [!] {name} ({label}) — missing")
            missing_rules.append((name, proto, port))

    if missing_rules:
        print()
        print(f"      {len(missing_rules)} firewall rule(s) missing.")
        if ask_yes_no("Add missing firewall rules?"):
            for name, proto, port in missing_rules:
                if port:
                    run_cmd(f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow protocol={proto} localport={port}')
                else:
                    run_cmd(f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow protocol={proto}')
                print(f"      [OK] Added: {name}")
        else:
            print("      [SKIP] Not adding rules")
            print("      To add manually:")
            for name, proto, port in missing_rules:
                if port:
                    print(f"        netsh advfirewall firewall add rule name=\"{name}\" dir=in action=allow protocol={proto} localport={port}")
                else:
                    print(f"        netsh advfirewall firewall add rule name=\"{name}\" dir=in action=allow protocol={proto}")
            issues += 1

    print()

    # --- Npcap ---
    print("  [3] Checking Npcap (needed by NIDS for packet capture)...")
    print()

    npcap_paths = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll"),
    ]
    npcap_found = any(os.path.exists(p) for p in npcap_paths)

    if npcap_found:
        print("      [OK] Npcap found")
    else:
        print("      [!] Npcap NOT found — NIDS packet capture won't work")
        print('      Download from: https://npcap.com')
        print('      Check "Install Npcap in WinPcap API-compatible Mode" during install')
        issues += 1

    print()
    return issues


# ==================================================================
# Common: Check NIDS project
# ==================================================================
def check_nids_project():
    issues = 0
    nids_dir = find_nids_dir()

    if nids_dir:
        print(f"      [OK] Found at: {nids_dir}")

        if os.path.isdir(os.path.join(nids_dir, "venv")):
            print("      [OK] Virtual environment exists")
        else:
            print("      [!] No venv — run setup.sh / setup.bat first")
            issues += 1

        if os.path.isfile(os.path.join(nids_dir, "trained_model", "random_forest_model.joblib")):
            print("      [OK] Default model (5-class: Benign, Botnet, Brute Force, DDoS, DoS)")
        else:
            print("      [!] No default model found")
            issues += 1

        if os.path.isfile(os.path.join(nids_dir, "trained_model_all", "random_forest_model.joblib")):
            print("      [OK] All model (6-class: + Infilteration)")
        else:
            print("      [-] No 6-class model (optional)")
    else:
        print("      [!] NIDS project not found")
        print("      Make sure you git cloned and ran the setup script")
        issues += 1

    return nids_dir, issues


# ==================================================================
# Main
# ==================================================================
def main():
    os_name = platform.system()

    print(f"\n{'='*60}")
    print(f"  VM Attack Setup Check — {os_name}")
    print(f"{'='*60}")
    print(f"  Checks if your VM is ready to receive attacks.")
    print(f"  Will NOT change anything without asking first.")
    print(f"{'='*60}\n")

    if not is_admin():
        if os_name == "Linux":
            print("  [ERROR] Run with sudo:  sudo python setup_vm.py")
        else:
            print("  [ERROR] Run as Administrator")
        sys.exit(1)

    print("  [OK] Running with admin privileges\n")

    # Step 1: Show IPs
    print("  [*] Network interfaces:")
    ips = get_all_ips()
    if ips:
        for ip in ips:
            print(f"      -> {ip}")
    else:
        print("      [!] Could not detect IPs")
    print()

    # Platform-specific checks
    if os_name == "Linux":
        issues = setup_linux()
    elif os_name == "Windows":
        issues = setup_windows()
    else:
        print(f"  [!] Untested OS: {os_name} — trying Linux checks")
        issues = setup_linux()

    # NIDS project check (both platforms)
    step_num = 5 if os_name == "Linux" else 4
    print(f"  [{step_num}] Checking NIDS project...")
    print()
    nids_dir, nids_issues = check_nids_project()
    issues += nids_issues
    print()

    # Summary
    print(f"{'='*60}")
    if issues == 0:
        print(f"  ALL CHECKS PASSED — VM is ready for attacks!")
    else:
        print(f"  CHECKS DONE — {issues} issue(s) found (see above)")
    print(f"{'='*60}\n")

    print("  Your VM IP:")
    if ips:
        for ip in ips:
            print(f"    -> {ip}")
    else:
        print("    Run: ip addr show  (Linux) or ipconfig (Windows)")

    print()
    print("  To start NIDS:")
    if nids_dir:
        print(f"    cd {nids_dir}")
    else:
        print("    cd ~/Nids")

    if os_name == "Linux":
        print("    source venv/bin/activate")
        print("    sudo ./venv/bin/python classification.py --duration 600")
    else:
        print("    venv\\Scripts\\activate")
        print("    python classification.py --duration 600")

    print()
    print("  Then from your attacker machine:")
    if ips:
        print(f"    python run_all_attacks.py {ips[0]}")
    else:
        print("    python run_all_attacks.py <VM_IP>")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
