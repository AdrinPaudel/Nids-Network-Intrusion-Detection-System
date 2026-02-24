#!/usr/bin/env python
"""
Victim Device Setup — Cross-Platform
=====================================
Run this ON THE TARGET DEVICE (VM or server) to check readiness for attack testing.
Checks everything, asks before changing anything.

Usage:
    Linux:   sudo python setup/setup_victim/setup_victim.py
    Windows: python setup/setup_victim/setup_victim.py  (run as Administrator)

What it checks:
    1. Network interfaces and device IP
    2. SSH server (installed? running?) — asks before installing/starting
    3. Web server (Apache/IIS/Nginx) — asks before installing/starting
    4. FTP server (vsftpd) — asks before installing/starting
    5. Firewall rules (Windows) — asks before adding
    6. libpcap / Npcap — tells you if missing
    7. NIDS project, venv, trained models
    8. Packet capture permissions (Linux) — asks before granting
"""

import sys
import os
import subprocess
import socket
import platform
import time


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


def run_cmd(cmd, shell=True, check=False, timeout=30):
    """Run a command and return (success, output)"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
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
    # Check relative to this script (setup/setup_victim/ -> project root)
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        if os.path.isfile(os.path.join(project_root, "classification.py")):
            return project_root
    except:
        pass

    # Check home directory variations
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Nids"),
        os.path.join(home, "nids"),
        os.path.join(home, "NIDS"),
        os.path.join(home, "Desktop", "Nids"),
        os.path.join(home, "Desktop", "NIDS"),
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
                run_cmd("apt-get install -y -qq openssh-server")
            elif os.path.exists("/usr/bin/dnf"):
                run_cmd("dnf install -y openssh-server")
            elif os.path.exists("/usr/bin/yum"):
                run_cmd("yum install -y openssh-server")
            elif os.path.exists("/usr/bin/pacman"):
                run_cmd("pacman -S --noconfirm openssh")
            else:
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
            issues += 1

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
                issues += 1

    print()

    # --- Web Server ---
    print("  [2] Checking Web Server (needed for DoS and DDoS HTTP attacks)...")
    print()

    web_installed = False
    web_running = False
    web_name = ""

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
        print()
        if ask_yes_no("Install Apache2?"):
            print("      Installing...")
            if os.path.exists("/usr/bin/apt-get"):
                run_cmd("apt-get update -qq")
                run_cmd("apt-get install -y -qq apache2")
                web_name = "apache2"
            elif os.path.exists("/usr/bin/dnf"):
                run_cmd("dnf install -y httpd")
                web_name = "httpd"
            elif os.path.exists("/usr/bin/yum"):
                run_cmd("yum install -y httpd")
                web_name = "httpd"
            elif os.path.exists("/usr/bin/pacman"):
                run_cmd("pacman -S --noconfirm apache")
                web_name = "apache"
            else:
                print("      [!] Unknown package manager")

            if web_name:
                ok_check, _ = run_cmd(f"command -v {web_name}")
                if ok_check:
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
            issues += 1

    print()

    # --- FTP Server ---
    print("  [3] Checking FTP Server (needed for FTP Brute Force attack)...")
    print()

    ftp_installed = False

    ok_ftp_deb, _ = run_cmd("dpkg -l vsftpd 2>/dev/null | grep -q '^ii'")
    ok_ftp_rpm, _ = run_cmd("rpm -q vsftpd 2>/dev/null")

    if ok_ftp_deb or ok_ftp_rpm:
        ftp_installed = True
        print("      [OK] vsftpd is installed")
    else:
        print("      [!] vsftpd FTP server NOT installed")
        print()
        if ask_yes_no("Install vsftpd?"):
            print("      Installing...")
            if os.path.exists("/usr/bin/apt-get"):
                run_cmd("apt-get update -qq")
                run_cmd("apt-get install -y -qq vsftpd")
            elif os.path.exists("/usr/bin/dnf"):
                run_cmd("dnf install -y vsftpd")
            elif os.path.exists("/usr/bin/yum"):
                run_cmd("yum install -y vsftpd")
            elif os.path.exists("/usr/bin/pacman"):
                run_cmd("pacman -S --noconfirm vsftpd")
            else:
                print("      [!] Unknown package manager")

            ok_check, _ = run_cmd("command -v vsftpd")
            ok_check2, _ = run_cmd("dpkg -l vsftpd 2>/dev/null | grep -q '^ii'")
            if ok_check or ok_check2:
                ftp_installed = True
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
        else:
            print("      [SKIP] Not installing FTP")

    if ftp_installed:
        ok_run, _ = run_cmd("systemctl is-active --quiet vsftpd")
        if ok_run:
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

    # --- Packet capture permissions ---
    print("  [5] Checking packet capture permissions...")
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
                else:
                    print(f"      [!] cap_net_raw NOT set on: {real_path}")
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
    else:
        print("      [SKIP] No NIDS venv found")

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
    
    # Simple check: Does sshd service exist?
    ok_sshd, _ = run_cmd("sc query sshd")
    
    if ok_sshd:
        print("      [OK] OpenSSH is installed")
        # Check if it's running
        ok_run, _ = run_cmd('sc query sshd | findstr "RUNNING"')
        if ok_run:
            print("      [OK] SSH service is running")
        else:
            print("      [!] SSH is installed but not running")
            if ask_yes_no("Start SSH service?"):
                run_cmd("net start sshd")
                time.sleep(1)
                ok_run2, _ = run_cmd('sc query sshd | findstr "RUNNING"')
                if ok_run2:
                    print("      [OK] SSH service started")
                else:
                    print("      [!] Failed to start SSH")
                    issues += 1
            else:
                issues += 1
    else:
        print("      [!] OpenSSH is NOT installed")
        print()
        if ask_yes_no("Install OpenSSH now?"):
            print("      Installing OpenSSH (this may take 5-10 minutes)...")
            print("      Please wait...")
            ok_install, out_install = run_cmd('powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"', timeout=900)
            
            print(f"      [DEBUG] Installation return code: {ok_install}")
            print(f"      [DEBUG] Output: {out_install[:500]}")  # Show first 500 chars of output
            
            if ok_install or "Success" in out_install or "already" in out_install.lower() or "The requested operation completed successfully" in out_install:
                print("      [OK] OpenSSH installed successfully")
                time.sleep(2)
                # Try to start it
                run_cmd("net start sshd")
                time.sleep(1)
                ok_check, _ = run_cmd('sc query sshd | findstr "RUNNING"')
                if ok_check:
                    print("      [OK] SSH service started and running")
                else:
                    print("      [!] OpenSSH installed but could not start service")
                    print("      Try: net start sshd  (in Admin Command Prompt)")
                    issues += 1
            else:
                print("      [!] Installation failed")
                if "The term 'Add-WindowsCapability' is not recognized" in out_install:
                    print("      Error: PowerShell command not found")
                    print("      Your Windows version may not support this feature")
                    issues += 1
                elif "RestartNeeded" in out_install:
                    print("      A restart may be required - restart Windows and try again")
                    issues += 1
                elif "not currently available" in out_install.lower():
                    print("      Error: OpenSSH is not available in your Windows 10 build")
                    print("      Try: Windows Update > Update Windows to latest version")
                    issues += 1
                else:
                    print(f"      Error details: {out_install}")
                    issues += 1
        else:
            print("      [SKIP] SSH not installed")
            issues += 1

    print()

    # --- Web Server ---
    print("  [2] Checking Web Server (needed for DoS and DDoS attacks)...")
    print()

    ok_iis, _ = run_cmd('sc query W3SVC 2>NUL | findstr "RUNNING"')
    if ok_iis:
        print("      [OK] IIS Web Server is running")
    else:
        ok_80, out_80 = run_cmd('netstat -an | findstr ":80 "')
        if ok_80 and "LISTEN" in out_80.upper():
            print("      [OK] A web server is listening on port 80")
        else:
            print("      [!] No web server running on port 80")
            print("          DoS/DDoS attacks need a web server on port 80.")
            print()
            
            if ask_yes_no("Start a simple Python web server on port 80?"):
                print("      Starting Python HTTP server...")
                print("      WARNING: This will start in background - close this terminal to stop it")
                print()
                
                # Create a simple HTML file in temp directory
                import tempfile
                temp_dir = tempfile.gettempdir()
                index_file = os.path.join(temp_dir, "index.html")
                try:
                    with open(index_file, 'w') as f:
                        f.write("<html><body><h1>NIDS Test Server</h1></body></html>")
                    
                    print("      Starting web server...")
                    
                    # Use subprocess.Popen to start completely detached on Windows
                    import subprocess as sp
                    
                    cmd = [sys.executable, "-m", "http.server", "80", "--directory", temp_dir]
                    
                    # Windows: Start in new console, hidden
                    CREATE_NEW_CONSOLE = 0x00000010
                    si = sp.STARTUPINFO()
                    si.dwFlags |= sp.STARTF_USESHOWWINDOW
                    si.wShowWindow = sp.SW_HIDE
                    
                    # Start the process completely detached from current process
                    proc = sp.Popen(cmd, startupinfo=si, creationflags=CREATE_NEW_CONSOLE, 
                                   stdout=sp.DEVNULL, stderr=sp.DEVNULL)
                    
                    time.sleep(3)
                    
                    # Check if port 80 is listening
                    ok_check, out_check = run_cmd('netstat -an | findstr ":80 "')
                    if ok_check and out_check and "LISTEN" in out_check:
                        print("      [OK] Web server is running on port 80")
                        print("      [OK] Server will keep running even after closing this terminal")
                    elif proc.poll() is None:  # Process is still running
                        print("      [OK] Web server started (may take a few seconds to appear in netstat)")
                        print("      [OK] Server will keep running even after closing this terminal")
                    else:
                        print("      [!] Web server process exited unexpectedly")
                        issues += 1
                except Exception as e:
                    print(f"      [!] Error starting web server: {e}")
                    issues += 1
            else:
                print("      [SKIP] Not starting web server")
                print()
                print("      If you want to test DoS/DDoS, start a web server manually:")
                print("        python -m http.server 80  (in a separate terminal/PowerShell)")
                print()
                print("      Or install IIS: Settings > Apps > Optional Features > IIS")
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
            print("      [!] No venv — run basic setup first")
            issues += 1

        if os.path.isfile(os.path.join(nids_dir, "trained_model", "random_forest_model.joblib")):
            print("      [OK] Default model (5-class)")
        else:
            print("      [!] No default model found")
            issues += 1

        if os.path.isfile(os.path.join(nids_dir, "trained_model_all", "random_forest_model.joblib")):
            print("      [OK] All model (6-class)")
        else:
            print("      [-] No 6-class model (optional)")
            warnings += 1
    else:
        print("      [!] NIDS project not found")
        issues += 1

    return nids_dir, issues, warnings


# ==================================================================
# Main
# ==================================================================
def main():
    os_name = platform.system()

    print(f"\n{'='*60}")
    print(f"  Victim Device Setup Check — {os_name}")
    print(f"{'='*60}")
    print(f"  Checks if this device is ready to receive attacks.")
    print(f"  Will NOT change anything without asking first.")
    print(f"{'='*60}\n")

    if not is_admin():
        if os_name == "Linux":
            print("  [ERROR] Run with sudo:  sudo python setup/setup_victim/setup_victim.py")
        else:
            print("  [ERROR] Run as Administrator")
        sys.exit(1)

    print("  [OK] Running with admin privileges\n")

    print("  [INFO] Recommended network setup:")
    print("    For VMs:     Host-Only adapter (attacker communication) + NAT (internet)")
    print("    For servers: At least 1 NIC reachable from attacker machine")
    print()

    ips = get_all_ips()
    print("  Network interfaces:")
    if ips:
        for ip in ips:
            print(f"      -> {ip}")
    else:
        print("      [!] Could not detect IPs")
    print()

    if os_name == "Linux":
        issues = setup_linux()
    elif os_name == "Windows":
        issues = setup_windows()
    else:
        print(f"  [!] Untested OS: {os_name}")
        issues = setup_linux()

    warnings = 0

    print("  Checking NIDS project...")
    print()
    nids_dir, nids_issues, nids_warnings = check_nids_project()
    issues += nids_issues
    warnings += nids_warnings
    print()

    # Summary
    print(f"{'='*60}")
    if issues == 0:
        if warnings == 0:
            print(f"  ALL CHECKS PASSED — Device is ready for attacks!")
        else:
            print(f"  CRITICAL CHECKS PASSED — {warnings} optional warning(s)")
    else:
        print(f"  {issues} issue(s) found, {warnings} warning(s)")
    print(f"{'='*60}\n")

    if ips:
        print(f"  Your device IP: {ips[0]}")
    print()
    print("  Required services:")
    print("    Web server  - port 80  -> DoS + DDoS attacks")
    print("    SSH server  - port 22  -> Brute Force SSH")
    print("    FTP server  - port 21  -> Brute Force FTP")
    print()
    print("  To start NIDS on this device:")
    if nids_dir:
        print(f"    cd {nids_dir}")
    if os_name == "Linux":
        print("    source venv/bin/activate")
        print("    sudo ./venv/bin/python classification.py --duration 600")
    else:
        print("    venv\\Scripts\\activate")
        print("    python classification.py --duration 600")
    print()
    print("  Then from your attacker machine:")
    if ips:
        print(f"    python setup/setup_attacker/device_attack.py {ips[0]}")
    else:
        print("    python setup/setup_attacker/device_attack.py <DEVICE_IP>")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
