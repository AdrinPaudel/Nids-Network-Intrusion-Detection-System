#!/usr/bin/env python
"""
Device Attack Setup Check - Cross-Platform
Checks if the device (VM or server) is ready to receive attacks.
Asks before changing anything.

Usage:
    Linux:   sudo python setup_device.py
    Windows: python setup_device.py  (run as Administrator)

What it checks:
    1. Network interfaces and device IP
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
    # Check script's parent directory first (most reliable)
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_parent = os.path.dirname(script_dir)
        if os.path.isfile(os.path.join(script_parent, "classification.py")):
            return script_parent
    except:
        pass
    
    # Check home directory variations
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Nids"),
        os.path.join(home, "nids"),
        os.path.join(home, "NIDS"),
        os.path.join(home, "Nids-Network-Intrusion-Detection-System"),
        os.path.join(home, "nids-network-intrusion-detection-system"),
        os.path.join(home, "Desktop", "Nids"),
        os.path.join(home, "Desktop", "Nids-Network-Intrusion-Detection-System"),
        "/root/Nids",
        "/root/nids",
        "/home/Nids",
        "/home/nids",
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

    # --- Web Server (needed for DoS/DDoS HTTP attacks) ---
    print("  [2] Checking Web Server (needed for DoS and DDoS HTTP attacks)...")
    print()

    web_installed = False
    web_running = False
    web_name = ""

    # Check Apache
    ok_apache, _ = run_cmd("dpkg -l apache2 2>/dev/null | grep -q '^ii'")
    ok_httpd, _ = run_cmd("rpm -q httpd 2>/dev/null")
    if ok_apache:
        web_installed = True
        web_name = "apache2"
        print("      [OK] Apache2 is installed")
    elif ok_httpd:
        web_installed = True
        web_name = "httpd"
        print("      [OK] Apache (httpd) is installed")

    # Check Nginx if no Apache
    if not web_installed:
        ok_nginx_deb, _ = run_cmd("dpkg -l nginx 2>/dev/null | grep -q '^ii'")
        ok_nginx_rpm, _ = run_cmd("rpm -q nginx 2>/dev/null")
        if ok_nginx_deb or ok_nginx_rpm:
            web_installed = True
            web_name = "nginx"
            print("      [OK] Nginx is installed")

    if web_installed:
        ok_run, _ = run_cmd(f"systemctl is-active --quiet {web_name}")
        if ok_run:
            web_running = True
            print(f"      [OK] {web_name} service is running")
        else:
            print(f"      [!] {web_name} is installed but NOT running")
            print()
            if ask_yes_no(f"Start {web_name} service?"):
                run_cmd(f"systemctl enable {web_name} 2>/dev/null")
                run_cmd(f"systemctl start {web_name} 2>/dev/null")
                ok_run2, _ = run_cmd(f"systemctl is-active --quiet {web_name}")
                if ok_run2:
                    print(f"      [OK] {web_name} started")
                else:
                    print(f"      [!] Failed to start {web_name}")
                    issues += 1
            else:
                print(f"      [SKIP] {web_name} not started")
                issues += 1
    else:
        print("      [!] No web server installed")
        print("          A web server on port 80 is REQUIRED for DoS and DDoS attacks.")
        print("          (Hulk, Slowloris, GoldenEye, SlowHTTPTest, LOIC, HOIC)")
        print()
        if ask_yes_no("Install Apache2?"):
            print("      Installing...")
            if os.path.exists("/usr/bin/apt-get"):
                run_cmd("apt-get update -qq")
                ok, _ = run_cmd("apt-get install -y -qq apache2")
                web_name = "apache2"
            elif os.path.exists("/usr/bin/dnf"):
                ok, _ = run_cmd("dnf install -y httpd")
                web_name = "httpd"
            elif os.path.exists("/usr/bin/yum"):
                ok, _ = run_cmd("yum install -y httpd")
                web_name = "httpd"
            elif os.path.exists("/usr/bin/pacman"):
                ok, _ = run_cmd("pacman -S --noconfirm apache")
                web_name = "apache"
            else:
                ok = False
                print("      [!] Unknown package manager")

            if web_name:
                ok_check, _ = run_cmd(f"systemctl list-unit-files {web_name}.service 2>/dev/null | grep -q {web_name}")
                ok_check2, _ = run_cmd(f"command -v {web_name}")
                if ok_check or ok_check2 or ok:
                    web_installed = True
                    print("      [OK] Installed")
                    if ask_yes_no(f"Start {web_name} now?"):
                        run_cmd(f"systemctl enable {web_name} 2>/dev/null")
                        run_cmd(f"systemctl start {web_name} 2>/dev/null")
                        print(f"      [OK] {web_name} started")
                else:
                    print("      [!] Installation failed")
                    issues += 1
        else:
            print("      [SKIP] Not installing web server")
            print("      To install manually: sudo apt install apache2 && sudo systemctl start apache2")
            issues += 1

    print()

    # --- FTP Server (needed for FTP Brute Force) ---
    print("  [3] Checking FTP Server (needed for FTP Brute Force attack)...")
    print()

    ftp_installed = False
    ftp_running = False

    ok_ftp_deb, _ = run_cmd("dpkg -l vsftpd 2>/dev/null | grep -q '^ii'")
    ok_ftp_rpm, _ = run_cmd("rpm -q vsftpd 2>/dev/null")

    if ok_ftp_deb or ok_ftp_rpm:
        ftp_installed = True
        print("      [OK] vsftpd is installed")
    else:
        print("      [!] vsftpd FTP server NOT installed")
        print("          Needed for FTP Brute Force attack (CICIDS2018 used Patator on FTP)")
        print()
        if ask_yes_no("Install vsftpd?"):
            print("      Installing...")
            if os.path.exists("/usr/bin/apt-get"):
                run_cmd("apt-get update -qq")
                ok, _ = run_cmd("apt-get install -y -qq vsftpd")
            elif os.path.exists("/usr/bin/dnf"):
                ok, _ = run_cmd("dnf install -y vsftpd")
            elif os.path.exists("/usr/bin/yum"):
                ok, _ = run_cmd("yum install -y vsftpd")
            elif os.path.exists("/usr/bin/pacman"):
                ok, _ = run_cmd("pacman -S --noconfirm vsftpd")
            else:
                ok = False

            ok_check, _ = run_cmd("command -v vsftpd")
            ok_check2, _ = run_cmd("dpkg -l vsftpd 2>/dev/null | grep -q '^ii'")
            if ok_check or ok_check2:
                ftp_installed = True
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
        else:
            print("      [SKIP] Not installing FTP")
            print("      FTP brute force won't work, but SSH brute force will.")

    if ftp_installed:
        ok_run, _ = run_cmd("systemctl is-active --quiet vsftpd")
        if ok_run:
            ftp_running = True
            print("      [OK] vsftpd service is running")
        else:
            print("      [!] vsftpd is installed but NOT running")
            print()
            if ask_yes_no("Start vsftpd service?"):
                run_cmd("systemctl enable vsftpd 2>/dev/null")
                run_cmd("systemctl start vsftpd 2>/dev/null")
                ok_run2, _ = run_cmd("systemctl is-active --quiet vsftpd")
                if ok_run2:
                    print("      [OK] vsftpd started")
                else:
                    print("      [!] Failed to start vsftpd")
            else:
                print("      [SKIP] vsftpd not started")

    print()

    # --- libpcap ---
    print("  [4] Checking libpcap (needed by NIDS for packet capture)...")
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
    print("  [5] Checking network tools...")
    print()
    ok, _ = run_cmd("command -v ifconfig")
    if ok:
        print("      [OK] net-tools installed")
    else:
        print("      [-] net-tools not installed (optional)")
        print("      To install: sudo apt install net-tools")

    print()

    # --- Packet capture permissions ---
    print("  [6] Checking packet capture permissions...")
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

    # --- Web Server (needed for DoS/DDoS) ---
    print("  [2] Checking Web Server (needed for DoS and DDoS attacks)...")
    print()

    # Check if IIS is running or any web server on port 80
    ok_iis, _ = run_cmd('sc query W3SVC 2>NUL | findstr "RUNNING"')
    if ok_iis:
        print("      [OK] IIS Web Server is running")
    else:
        # Check if any process is listening on port 80
        ok_80, out_80 = run_cmd('netstat -an | findstr ":80 "')
        if ok_80 and "LISTEN" in out_80.upper():
            print("      [OK] A web server is listening on port 80")
        else:
            print("      [!] No web server running on port 80")
            print("          DoS/DDoS attacks (Hulk, Slowloris, LOIC, HOIC) need a web server.")
            print()
            print("      Options:")
            print("        1. Install IIS via: Settings > Apps > Optional Features > IIS")
            print("        2. Or install Apache/Nginx manually")
            print("        3. Or use Python:  python -m http.server 80  (simple test server)")
            issues += 1

    print()

    # --- Firewall ---
    print("  [3] Checking Firewall rules...")
    print()

    rules = {
        "NIDS-SSH": ("tcp", "22"),
        "NIDS-FTP": ("tcp", "21"),
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
    print("  [4] Checking Npcap (needed by NIDS for packet capture)...")
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
    warnings = 0
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
            warnings += 1
    else:
        print("      [!] NIDS project not found")
        print("      Make sure you git cloned and ran the setup script")
        issues += 1

    return nids_dir, issues, warnings


# ==================================================================
# Main
# ==================================================================
def main():
    os_name = platform.system()

    print(f"\n{'='*60}")
    print(f"  Device Attack Setup Check — {os_name}")
    print(f"{'='*60}")
    print(f"  Checks if your device (VM or server) is ready to receive attacks.")
    print(f"  Will NOT change anything without asking first.")
    print(f"{'='*60}\n")

    if not is_admin():
        if os_name == "Linux":
            print("  [ERROR] Run with sudo:  sudo python setup_device.py")
        else:
            print("  [ERROR] Run as Administrator")
        sys.exit(1)

    print("  [OK] Running with admin privileges\n")

    # Network interface guidance
    print("  [INFO] Recommended network interface setup:")
    print("    For VMs:     At least 1 Host-Only adapter (attacker-to-target communication)")
    print("                 + 1 Bridged or NAT adapter (internet access)")
    print("    For servers: At least 1 NIC with a reachable IP from your attacker machine")
    print()

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

    warnings = 0  # Initialize warnings tracker

    # NIDS project check (both platforms)
    step_num = 7 if os_name == "Linux" else 5
    print(f"  [{step_num}] Checking NIDS project...")
    print()
    nids_dir, nids_issues, nids_warnings = check_nids_project()
    issues += nids_issues
    warnings += nids_warnings
    print()

    # Summary
    print(f"{'='*60}")
    if issues == 0:
        if warnings == 0:
            print(f"  ✓ ALL CHECKS PASSED — Device is ready for attacks!")
        else:
            print(f"  ✓ CRITICAL CHECKS PASSED — {warnings} optional feature(s) not configured")
    else:
        print(f"  ✗ CHECKS DONE — {issues} critical issue(s), {warnings} warning(s) (see above)")
    print(f"{'='*60}\n")

    print("  Your device IP:")
    if ips:
        for ip in ips:
            print(f"    -> {ip}")
    else:
        print("    Run: ip addr show  (Linux) or ipconfig (Windows)")

    print()
    print("  Required services for attacks:")
    print("    Web server (Apache/IIS) - port 80  -> DoS (Hulk, Slowloris, GoldenEye) + DDoS (LOIC, HOIC)")
    print("    SSH server              - port 22  -> Brute Force SSH")
    print("    FTP server (vsftpd)     - port 21  -> Brute Force FTP")
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
        print("    python run_all_attacks.py <DEVICE_IP>")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
