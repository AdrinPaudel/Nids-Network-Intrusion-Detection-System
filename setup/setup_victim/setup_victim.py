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
    4. FTP server (vsftpd / Windows FTP) — asks before installing/starting
    5. Firewall rules (Windows) — asks before adding
    6. libpcap / Npcap — tells you if missing
    7. NIDS project, venv, trained models
    8. Packet capture permissions (Linux) — asks before granting

Supported:
    Windows 10 (1809+), Windows 11
    Ubuntu/Debian, Fedora/RHEL/CentOS, Arch, openSUSE, Alpine
"""

import sys
import os
import subprocess
import socket
import platform
import time
import shutil


# ==================================================================
# Helpers
# ==================================================================

def is_admin():
    """Check if running with admin/root privileges."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def run_cmd(cmd, shell=True, timeout=60):
    """Run a command, return (success: bool, combined_output: str)."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def run_ps(ps_cmd, timeout=120):
    """Run a PowerShell command (Windows only). Returns (success, output)."""
    full = [
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", ps_cmd,
    ]
    try:
        result = subprocess.run(
            full, capture_output=True, text=True, timeout=timeout
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def ask_yes_no(prompt):
    """Ask user a yes/no question, return True if yes."""
    try:
        answer = input(f"  {prompt} [y/n]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def get_all_ips():
    """Get all local non-loopback IPv4 addresses."""
    ips = []

    # Method 1: platform-specific commands
    try:
        if sys.platform == "win32":
            ok, out = run_cmd("ipconfig", timeout=10)
            if ok:
                for line in out.splitlines():
                    if "IPv4" in line and ":" in line:
                        ip = line.split(":")[-1].strip()
                        if ip and not ip.startswith("127."):
                            ips.append(ip)
        else:
            # Try 'ip' first (modern), then 'ifconfig' (legacy / Alpine / BSD)
            ok, out = run_cmd("ip -4 addr show 2>/dev/null", timeout=10)
            if ok:
                for line in out.splitlines():
                    if "inet " in line and "127.0.0" not in line:
                        ip = line.strip().split()[1].split("/")[0]
                        ips.append(ip)
            if not ips:
                ok, out = run_cmd("ifconfig 2>/dev/null", timeout=10)
                if ok:
                    for line in out.splitlines():
                        if "inet " in line and "127.0.0" not in line:
                            parts = line.strip().split()
                            for i, p in enumerate(parts):
                                if p == "inet" and i + 1 < len(parts):
                                    ip = parts[i + 1].split("/")[0]
                                    if ip.replace(".", "").isdigit():
                                        ips.append(ip)
    except Exception:
        pass

    # Method 2: socket fallback
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass

    return ips


def find_nids_dir():
    """Find the NIDS project directory."""
    # Relative to this script (setup/setup_victim/ -> project root)
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(script_dir))
        if os.path.isfile(os.path.join(project_root, "classification.py")):
            return project_root
    except Exception:
        pass

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
# Linux: Package Manager Abstraction
# ==================================================================

def detect_pkg_manager():
    """
    Detect the Linux package manager.
    Returns a dict with keys: name, install, update, check.
    """
    if shutil.which("apt-get"):
        return {
            "name": "apt",
            "update": "apt-get update -qq",
            "install": "apt-get install -y -qq",
            "check": lambda pkg: run_cmd(f"dpkg -l {pkg} 2>/dev/null | grep -q '^ii'")[0],
        }
    if shutil.which("dnf"):
        return {
            "name": "dnf",
            "update": None,
            "install": "dnf install -y",
            "check": lambda pkg: run_cmd(f"rpm -q {pkg} 2>/dev/null")[0],
        }
    if shutil.which("yum"):
        return {
            "name": "yum",
            "update": None,
            "install": "yum install -y",
            "check": lambda pkg: run_cmd(f"rpm -q {pkg} 2>/dev/null")[0],
        }
    if shutil.which("zypper"):
        return {
            "name": "zypper",
            "update": None,
            "install": "zypper install -y",
            "check": lambda pkg: run_cmd(f"rpm -q {pkg} 2>/dev/null")[0],
        }
    if shutil.which("pacman"):
        return {
            "name": "pacman",
            "update": "pacman -Sy --noconfirm",
            "install": "pacman -S --noconfirm",
            "check": lambda pkg: run_cmd(f"pacman -Qi {pkg} 2>/dev/null")[0],
        }
    if shutil.which("apk"):
        return {
            "name": "apk",
            "update": "apk update",
            "install": "apk add",
            "check": lambda pkg: run_cmd(f"apk info -e {pkg} 2>/dev/null")[0],
        }
    return None


# Package name mapping per distro
PKG_NAMES = {
    #              apt               dnf/yum/zypper     pacman        apk
    "ssh": {
        "apt": "openssh-server",
        "dnf": "openssh-server",
        "yum": "openssh-server",
        "zypper": "openssh",
        "pacman": "openssh",
        "apk": "openssh",
    },
    "apache": {
        "apt": "apache2",
        "dnf": "httpd",
        "yum": "httpd",
        "zypper": "apache2",
        "pacman": "apache",
        "apk": "apache2",
    },
    "vsftpd": {
        "apt": "vsftpd",
        "dnf": "vsftpd",
        "yum": "vsftpd",
        "zypper": "vsftpd",
        "pacman": "vsftpd",
        "apk": "vsftpd",
    },
    "libpcap": {
        "apt": "libpcap-dev",
        "dnf": "libpcap-devel",
        "yum": "libpcap-devel",
        "zypper": "libpcap-devel",
        "pacman": "libpcap",
        "apk": "libpcap-dev",
    },
}


def pkg_install(pm, category):
    """Install a package using the detected package manager."""
    pkg_name = PKG_NAMES.get(category, {}).get(pm["name"])
    if not pkg_name:
        print(f"      [!] Don't know the package name for '{category}' on {pm['name']}")
        return False

    if pm["update"]:
        run_cmd(pm["update"], timeout=120)

    ok, out = run_cmd(f"{pm['install']} {pkg_name}", timeout=300)
    if ok:
        return True
    # Some managers return non-zero but still install; double-check
    if pm["check"](pkg_name):
        return True
    print(f"      [!] Install output: {out[:200]}")
    return False


def pkg_is_installed(pm, category):
    """Check if a package category is installed."""
    pkg_name = PKG_NAMES.get(category, {}).get(pm["name"])
    if not pkg_name:
        return False
    return pm["check"](pkg_name)


def has_systemd():
    """Check if this system uses systemd."""
    return os.path.isdir("/run/systemd/system")


def service_is_running(service_name):
    """Check if a service is running (systemd or OpenRC)."""
    if has_systemd():
        ok, _ = run_cmd(f"systemctl is-active --quiet {service_name}")
        return ok
    else:
        # OpenRC (Alpine, Gentoo, etc.)
        ok, out = run_cmd(f"rc-service {service_name} status 2>/dev/null")
        if ok and "started" in out.lower():
            return True
        # Fallback: check process
        ok2, _ = run_cmd(f"pgrep -x {service_name}")
        return ok2


def service_start(service_name):
    """Start and enable a service (systemd or OpenRC)."""
    if has_systemd():
        run_cmd(f"systemctl enable {service_name} 2>/dev/null")
        ok, _ = run_cmd(f"systemctl start {service_name}")
        return ok
    else:
        run_cmd(f"rc-update add {service_name} default 2>/dev/null")
        ok, _ = run_cmd(f"rc-service {service_name} start 2>/dev/null")
        return ok


# ==================================================================
# Linux Setup
# ==================================================================

def setup_linux():
    issues = 0

    pm = detect_pkg_manager()
    if not pm:
        print("  [!] Could not detect package manager — manual setup required.")
        return 1

    print(f"  Detected package manager: {pm['name']}")
    print()

    # --- SSH Server ---
    print("  [1] Checking SSH Server (needed for Brute Force attack)...")
    print()

    ssh_installed = pkg_is_installed(pm, "ssh") or bool(shutil.which("sshd"))

    if ssh_installed:
        print("      [OK] SSH server is installed")
    else:
        print("      [!] SSH server is NOT installed")
        print("          Needed for the Brute Force attack.")
        print()
        if ask_yes_no("Install SSH server?"):
            print("      Installing...")
            if pkg_install(pm, "ssh"):
                ssh_installed = True
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
                issues += 1
        else:
            print("      [SKIP] Not installing")
            issues += 1

    if ssh_installed:
        # SSH service name varies: 'ssh' (Debian/Ubuntu), 'sshd' (everything else)
        svc = None
        for name in ("ssh", "sshd"):
            if service_is_running(name):
                svc = name
                break

        if svc:
            print(f"      [OK] {svc} service is running")
        else:
            print("      [!] SSH is installed but NOT running")
            print()
            if ask_yes_no("Start SSH service?"):
                started = False
                for name in ("sshd", "ssh"):
                    if service_start(name):
                        print(f"      [OK] {name} started")
                        started = True
                        break
                if not started:
                    print("      [!] Failed to start SSH")
                    issues += 1
            else:
                print("      [SKIP] SSH not started")
                issues += 1

    print()

    # --- Web Server ---
    print("  [2] Checking Web Server (needed for DoS and DDoS attacks)...")
    print()

    web_installed = False
    web_service = ""

    # Check for existing web servers
    for svc_name in ("apache2", "httpd", "nginx", "apache"):
        if service_is_running(svc_name):
            web_installed = True
            web_service = svc_name
            print(f"      [OK] {svc_name} is running")
            break

    if not web_installed:
        # Check if installed but not running
        if pkg_is_installed(pm, "apache") or shutil.which("httpd") or shutil.which("apache2"):
            web_installed = True
            # Figure out the service name
            for svc_name in ("apache2", "httpd", "apache"):
                if has_systemd():
                    ok, _ = run_cmd(f"systemctl list-unit-files {svc_name}.service 2>/dev/null | grep -q {svc_name}")
                else:
                    ok, _ = run_cmd(f"rc-service -l 2>/dev/null | grep -q {svc_name}")
                if ok:
                    web_service = svc_name
                    break
            if not web_service:
                web_service = "apache2" if pm["name"] in ("apt", "zypper", "apk") else "httpd"

            print(f"      [!] {web_service} is installed but NOT running")
            print()
            if ask_yes_no(f"Start {web_service}?"):
                if service_start(web_service):
                    print(f"      [OK] {web_service} started")
                else:
                    print(f"      [!] Failed to start {web_service}")
                    issues += 1
            else:
                print(f"      [SKIP] {web_service} not started")
                issues += 1
        else:
            # Check nginx too
            if shutil.which("nginx"):
                web_installed = True
                web_service = "nginx"
                print("      [OK] nginx found (not running)")
                if ask_yes_no("Start nginx?"):
                    service_start("nginx")
            else:
                print("      [!] No web server installed")
                print("          A web server on port 80 is REQUIRED for DoS and DDoS attacks.")
                print()
                if ask_yes_no("Install Apache?"):
                    print("      Installing...")
                    if pkg_install(pm, "apache"):
                        print("      [OK] Installed")
                        svc_name = "apache2" if pm["name"] in ("apt", "zypper", "apk") else "httpd"
                        if ask_yes_no(f"Start {svc_name} now?"):
                            if service_start(svc_name):
                                print(f"      [OK] {svc_name} started")
                            else:
                                print(f"      [!] Failed to start {svc_name}")
                                issues += 1
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

    ftp_installed = pkg_is_installed(pm, "vsftpd") or bool(shutil.which("vsftpd"))

    if ftp_installed:
        print("      [OK] vsftpd is installed")
    else:
        print("      [!] vsftpd FTP server NOT installed")
        print()
        if ask_yes_no("Install vsftpd?"):
            print("      Installing...")
            if pkg_install(pm, "vsftpd"):
                ftp_installed = True
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
        else:
            print("      [SKIP] Not installing FTP")

    if ftp_installed:
        if service_is_running("vsftpd"):
            print("      [OK] vsftpd service is running")
        else:
            print("      [!] vsftpd is installed but NOT running")
            print()
            if ask_yes_no("Start vsftpd service?"):
                if service_start("vsftpd"):
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

    # Check via ldconfig
    ok, out = run_cmd("ldconfig -p 2>/dev/null | grep libpcap")
    if ok and "libpcap" in out:
        libpcap_found = True
    else:
        # Check common library paths across distros
        lib_search_dirs = [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/lib64",
            "/lib",
        ]
        for d in lib_search_dirs:
            if os.path.isdir(d):
                try:
                    for f in os.listdir(d):
                        if f.startswith("libpcap.so"):
                            libpcap_found = True
                            break
                except OSError:
                    pass
            if libpcap_found:
                break

    if libpcap_found:
        print("      [OK] libpcap found")
    else:
        print("      [!] libpcap NOT found — NIDS packet capture won't work")
        pkg_name = PKG_NAMES["libpcap"].get(pm["name"], "libpcap-dev")
        print(f"      To install: sudo {pm['install']} {pkg_name}")
        if ask_yes_no("Install libpcap now?"):
            if pkg_install(pm, "libpcap"):
                print("      [OK] Installed")
            else:
                print("      [!] Installation failed")
                issues += 1
        else:
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
                real_path = real_path.strip()
                ok_cap, caps = run_cmd(f"getcap {real_path}")
                if ok_cap and "cap_net_raw" in caps:
                    print(f"      [OK] cap_net_raw set on: {real_path}")
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
                        print("      [SKIP]")
                        print(f"      Manual: sudo setcap cap_net_raw,cap_net_admin=eip {real_path}")
            else:
                print("      [SKIP] Could not resolve Python binary path")
        else:
            print("      [SKIP] venv Python not found")
    else:
        print("      [SKIP] No NIDS venv found — run setup_basic first")

    print()
    return issues


# ==================================================================
# Windows Setup
# ==================================================================

def win_get_version():
    """
    Get Windows version info.
    Returns (major, build) e.g. (10, 19045) for Win10 22H2, (10, 22631) for Win11 23H2.
    Win11 builds are >= 22000.
    """
    try:
        ver = platform.version()  # e.g. "10.0.19045"
        parts = ver.split(".")
        major = int(parts[0])
        build = int(parts[2]) if len(parts) >= 3 else 0
        return major, build
    except Exception:
        return 10, 0


def win_service_exists(service):
    """Check if a Windows service exists."""
    ok, out = run_cmd(f'sc.exe query "{service}"', timeout=10)
    if ok:
        return True
    # "1060" = service does not exist
    return "1060" not in out


def win_service_running(service):
    """Check if a Windows service is running."""
    ok, out = run_cmd(f'sc.exe query "{service}"', timeout=10)
    if ok and "RUNNING" in out:
        return True
    return False


def win_service_start(service):
    """Start a Windows service. Returns True on success."""
    # Set to auto start
    run_cmd(f'sc.exe config "{service}" start= auto', timeout=10)
    ok, out = run_cmd(f'net start "{service}"', timeout=30)
    if ok:
        return True
    if "already been started" in out.lower():
        return True
    return False


def win_install_ssh():
    """
    Install OpenSSH Server on Windows 10/11.
    Tries multiple methods for maximum compatibility.
    Returns True on success.
    """
    major, build = win_get_version()

    # Method 1: PowerShell Add-WindowsCapability (Win10 1809+ / Win11)
    # This is the most reliable method on modern Windows
    print("      Trying PowerShell method...")
    ok, out = run_ps(
        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
        timeout=300,
    )
    if ok or "already installed" in out.lower():
        print("      [OK] OpenSSH installed via PowerShell")
        return True

    # Method 2: DISM capability (works on most Win10/11)
    print("      PowerShell method failed, trying DISM...")
    ok, out = run_cmd(
        "dism /online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0",
        timeout=300,
    )
    if ok or "successfully" in out.lower():
        print("      [OK] OpenSSH installed via DISM capability")
        return True

    # Method 3: DISM feature (older Win10 builds)
    ok, out = run_cmd(
        "dism /online /enable-feature /featurename:OpenSSH-Server /all /norestart",
        timeout=300,
    )
    if ok or "successfully" in out.lower() or "already" in out.lower():
        print("      [OK] OpenSSH installed via DISM feature")
        return True

    print("      [!] All install methods failed")
    if "0x800f0954" in out or "update" in out.lower():
        print("      Windows Update may be interfering — close it and retry")
    print("      Alternative: Install Git for Windows (includes SSH)")
    print("          https://git-scm.com/download/win")
    return False


def win_check_ssh_installed():
    """Check if OpenSSH Server is installed on Windows."""
    # Check if service exists
    if win_service_exists("sshd"):
        return True

    # Check via PowerShell capability query
    ok, out = run_ps(
        "Get-WindowsCapability -Online -Name OpenSSH.Server* "
        "| Select-Object -ExpandProperty State",
        timeout=30,
    )
    if ok and "installed" in out.lower():
        return True

    return False


def setup_windows():
    issues = 0

    major, build = win_get_version()
    is_win11 = build >= 22000
    print(f"  Windows {'11' if is_win11 else '10'} (build {build})")
    print()

    # --- SSH Server ---
    print("  [1] Checking SSH Server (needed for Brute Force attack)...")
    print()

    if win_check_ssh_installed():
        print("      [OK] OpenSSH Server is installed")

        if win_service_running("sshd"):
            print("      [OK] sshd service is running")
        else:
            print("      [!] sshd is installed but not running")
            print()
            if ask_yes_no("Start SSH service?"):
                if win_service_start("sshd"):
                    time.sleep(2)
                    if win_service_running("sshd"):
                        print("      [OK] sshd started")
                    else:
                        print("      [OK] sshd start command succeeded (may need a moment)")
                else:
                    print("      [!] Failed to start sshd")
                    print("      Try: Restart your computer, then run setup again")
                    issues += 1
            else:
                issues += 1
    else:
        print("      [!] OpenSSH Server is NOT installed")
        print()
        if ask_yes_no("Install OpenSSH Server?"):
            print("      Installing... (this can take a minute)")
            if win_install_ssh():
                time.sleep(3)
                if win_service_start("sshd"):
                    time.sleep(2)
                    print("      [OK] sshd service started")
                else:
                    print("      [!] Installed but service won't start")
                    print("      Try: Restart your computer, then run setup again")
                    issues += 1
            else:
                issues += 1
                print()
                if ask_yes_no("Skip SSH and continue?"):
                    print("      [SKIP] Continuing without SSH")
                    print("      Note: DoS/DDoS attacks will still work with a web server")
                else:
                    pass
        else:
            print("      [SKIP] SSH not installed")
            issues += 1

    print()

    # --- Web Server ---
    print("  [2] Checking Web Server (needed for DoS and DDoS attacks)...")
    print()

    web_ok = False

    # Check IIS
    if win_service_running("W3SVC"):
        print("      [OK] IIS Web Server is running")
        web_ok = True

    # Check if anything is listening on port 80
    if not web_ok:
        ok, out = run_cmd('netstat -ano | findstr ":80 "', timeout=10)
        if ok and out:
            for line in out.splitlines():
                if "LISTENING" in line.upper() or "LISTEN" in line.upper():
                    print("      [OK] A web server is listening on port 80")
                    web_ok = True
                    break

    if not web_ok:
        print("      [!] No web server running on port 80")
        print("          DoS/DDoS attacks need a web server on port 80.")
        print()

        if ask_yes_no("Start a simple Python web server on port 80?"):
            print("      Starting Python HTTP server on port 80...")
            try:
                import tempfile
                temp_dir = tempfile.gettempdir()
                index_file = os.path.join(temp_dir, "index.html")
                with open(index_file, "w") as f:
                    f.write("<html><body><h1>NIDS Test Server</h1></body></html>")

                # Start detached process
                cmd = [sys.executable, "-m", "http.server", "80", "--directory", temp_dir]

                CREATE_NEW_CONSOLE = 0x00000010
                DETACHED_PROCESS = 0x00000008
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0  # SW_HIDE

                proc = subprocess.Popen(
                    cmd,
                    startupinfo=si,
                    creationflags=CREATE_NEW_CONSOLE | DETACHED_PROCESS,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                time.sleep(3)

                # Verify
                ok_check, out_check = run_cmd('netstat -ano | findstr ":80 "', timeout=10)
                if ok_check and "LISTEN" in out_check.upper():
                    print("      [OK] Web server running on port 80")
                elif proc.poll() is None:
                    print("      [OK] Web server started (verifying...)")
                else:
                    print("      [!] Web server process exited — port 80 may be in use")
                    issues += 1
            except Exception as e:
                print(f"      [!] Error: {e}")
                issues += 1
        else:
            print("      [SKIP] Not starting web server")
            print("      To start manually in another terminal:")
            print("        python -m http.server 80")
            issues += 1

    print()

    # --- Firewall ---
    print("  [3] Checking Firewall rules...")
    print()

    rules = {
        "NIDS-SSH":       ("tcp", "22"),
        "NIDS-FTP":       ("tcp", "21"),
        "NIDS-Ping":      ("icmpv4", None),
        "NIDS-Port-80":   ("tcp", "80"),
        "NIDS-Port-443":  ("tcp", "443"),
        "NIDS-Port-8080": ("tcp", "8080"),
        "NIDS-Port-8443": ("tcp", "8443"),
    }

    missing_rules = []
    for name, (proto, port) in rules.items():
        ok, _ = run_cmd(
            f'netsh advfirewall firewall show rule name="{name}"', timeout=10
        )
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
                    ok, _ = run_cmd(
                        f'netsh advfirewall firewall add rule name="{name}" '
                        f'dir=in action=allow protocol={proto} localport={port}',
                        timeout=10,
                    )
                else:
                    ok, _ = run_cmd(
                        f'netsh advfirewall firewall add rule name="{name}" '
                        f'dir=in action=allow protocol={proto}',
                        timeout=10,
                    )
                if ok:
                    print(f"      [OK] Added: {name}")
                else:
                    print(f"      [!] Failed to add: {name}")
        else:
            print("      [SKIP] Not adding rules")
            issues += 1

    print()

    # --- Npcap ---
    print("  [4] Checking Npcap (needed by NIDS for packet capture)...")
    print()

    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    npcap_paths = [
        os.path.join(sys_root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(sys_root, "System32", "wpcap.dll"),
        os.path.join(sys_root, "SysWOW64", "Npcap", "wpcap.dll"),
        os.path.join(sys_root, "SysWOW64", "wpcap.dll"),
    ]
    npcap_found = any(os.path.exists(p) for p in npcap_paths)

    if npcap_found:
        print("      [OK] Npcap found")
    else:
        print("      [!] Npcap NOT found — NIDS packet capture won't work")
        print("      Download from: https://npcap.com")
        print('      IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode"')
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
            print("      [!] No venv — run setup_basic first")
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
            print("  [ERROR] Run with sudo:")
            print("    sudo python setup/setup_victim/setup_victim.py")
        else:
            print("  [ERROR] Run as Administrator")
            print("    Right-click setup_victim.bat -> Run as administrator")
        sys.exit(1)

    print("  [OK] Running with admin privileges\n")

    print("  [INFO] Recommended network setup:")
    print("    VMs:     Host-Only adapter + NAT (internet)")
    print("    Servers: At least 1 NIC reachable from attacker machine")
    print()

    ips = get_all_ips()
    print("  Network interfaces:")
    if ips:
        for ip in ips:
            print(f"      -> {ip}")
    else:
        print("      [!] Could not detect IPs")
    print()

    if os_name == "Windows":
        issues = setup_windows()
    elif os_name == "Linux":
        issues = setup_linux()
    else:
        print(f"  [!] Untested OS: {os_name} — trying Linux-style setup")
        issues = setup_linux()

    warnings = 0

    print("  Checking NIDS project...")
    print()
    nids_dir, nids_issues, nids_warnings = check_nids_project()
    issues += nids_issues
    warnings += nids_warnings
    print()

    # ---- Summary ----
    print(f"{'='*60}")
    if issues == 0:
        if warnings == 0:
            print("  ALL CHECKS PASSED — Device is ready for attacks!")
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
    except KeyboardInterrupt:
        print("\n  Cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [FATAL ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
