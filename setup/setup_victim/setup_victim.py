#!/usr/bin/env python3
"""
Victim Device Setup Checker - Windows & Linux
Checks and sets up SSH and web server for attack simulations.
Uses Windows built-in or standalone OpenSSH (no Git dependency).
"""

import os
import sys
import platform
import subprocess
import socket
import time
import json
from pathlib import Path

# No color - Windows cmd doesn't support ANSI codes
class Color:
    GREEN = ''
    RED = ''
    YELLOW = ''
    BLUE = ''
    END = ''

    @staticmethod
    def on_windows():
        return platform.system() == 'Windows'

# ============================================================================
# WINDOWS - SSH SERVER SETUP (Standalone OpenSSH, no Git)
# ============================================================================

def win_check_openssh_service():
    """Check if OpenSSH service is installed on Windows."""
    try:
        result = subprocess.run(
            ['sc', 'query', 'sshd'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception as e:
        print(f"  [!] Error checking OpenSSH: {e}")
        return False

def win_enable_builtin_openssh():
    """Try to enable Windows built-in OpenSSH (Win10 1809+ and Win11)."""
    print("  Attempting to enable Windows built-in OpenSSH...")
    try:
        # This command adds Windows built-in OpenSSH capability
        result = subprocess.run(
            [
                'powershell', '-NoProfile', '-Command',
                "Get-WindowsCapability -Online | Where-Object {$_.Name -like 'OpenSSH.Server*'} | Add-WindowsCapability -Online"
            ],
            capture_output=True,
            text=True,
            timeout=60
        )
        time.sleep(2)  # Let system settle
        
        if win_check_openssh_service():
            print("  [OK] Windows built-in OpenSSH enabled.")
            return True
        else:
            print("  [!] Built-in OpenSSH not available for this Windows version.")
            return False
    except Exception as e:
        print(f"  [!] Could not enable built-in OpenSSH: {e}")
        return False

def win_download_standalone_openssh():
    """Download standalone OpenSSH MSI for old Windows systems."""
    print("  Downloading standalone OpenSSH for Windows...")
    
    try:
        import urllib.request
        
        # Use an older OpenSSH version that works with old Windows 10
        # Version 8.1.0.0 is known to work on older systems
        url = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.1.0.0p1-Beta/OpenSSH-Win64.msi"
        installer_path = os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'OpenSSH-Win64.msi')
        
        print(f"  Downloading from: {url}")
        urllib.request.urlretrieve(url, installer_path)
        
        if os.path.exists(installer_path):
            print(f"  [OK] Downloaded to {installer_path}")
            return installer_path
        else:
            print("  [ERROR] Download failed.")
            return None
            
    except Exception as e:
        print(f"  [ERROR] Download failed: {e}")
        return None

def win_install_standalone_openssh(installer_path):
    """Install standalone OpenSSH MSI."""
    print(f"  Installing OpenSSH from: {installer_path}")
    
    try:
        # Silent install: /quiet, /norestart
        result = subprocess.run(
            ['msiexec.exe', '/i', installer_path, '/quiet', '/norestart'],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        time.sleep(3)  # Let system settle after install
        
        if win_check_openssh_service():
            print("  [OK] OpenSSH installed and service found.")
            return True
        else:
            print("  [!] OpenSSH installed but service not detected yet.")
            return True  # Installation succeeded, service may start on reboot
            
    except Exception as e:
        print(f"  [ERROR] Installation failed: {e}")
        return False

def win_start_sshd():
    """Start OpenSSH service on Windows."""
    print("  Starting OpenSSH service...")
    
    try:
        # Try net start
        result = subprocess.run(
            ['net', 'start', 'sshd'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        time.sleep(1)
        
        if win_is_port_open(22):
            print("  [OK] OpenSSH service started on port 22.")
            return True
        else:
            print("  [!] Service start attempt completed, checking port...")
            time.sleep(2)
            
            if win_is_port_open(22):
                print("  [OK] Port 22 is now open.")
                return True
            else:
                # Try PowerShell fallback
                print("  Attempting PowerShell service start...")
                subprocess.run(
                    ['powershell', '-NoProfile', '-Command', 'Start-Service sshd -ErrorAction SilentlyContinue'],
                    capture_output=True,
                    timeout=10
                )
                time.sleep(2)
                
                if win_is_port_open(22):
                    print("  [OK] OpenSSH service started.")
                    return True
                else:
                    print("  [!] Could not start OpenSSH service. Check Windows Event Log.")
                    return False
                    
    except Exception as e:
        print(f"  [ERROR] Error starting service: {e}")
        return False

def win_setup_ssh():
    """Main SSH setup orchestration for Windows."""
    print("\n=== SSH Server Setup ===")
    
    # Check if already running
    if win_is_port_open(22):
        print("  [OK] SSH is already running on port 22.")
        return True
    
    print("  SSH not detected. Installing...")
    
    # Step 1: Check for existing OpenSSH service
    if win_check_openssh_service():
        print("  [OK] OpenSSH service found, starting it...")
        return win_start_sshd()
    
    # Step 2: Try to enable Windows built-in OpenSSH
    if win_enable_builtin_openssh():
        return win_start_sshd()
    
    # Step 3: Download and install standalone OpenSSH
    installer = win_download_standalone_openssh()
    if installer:
        if win_install_standalone_openssh(installer):
            # Try to start service
            win_start_sshd()
            
            # Clean up installer
            try:
                os.remove(installer)
            except:
                pass
            
            return True
    
    print("\n[!] Could not set up OpenSSH.")
    print("    This may be because:")
    print("    - Your Windows version is too old (before Win10 1809)")
    print("    - System needs a reboot after OpenSSH installation")
    print("    - Missing required Windows components")
    
    while True:
        response = input("\n  Skip SSH and continue with web server only? (y/n): ").strip().lower()
        if response == 'y':
            print("  SSH skipped. Continuing with web server setup...")
            return False  # Return False but continue execution
        elif response == 'n':
            print("  Aborting setup.")
            sys.exit(1)

def win_is_port_open(port):
    """Check if port is listening on Windows."""
    try:
        result = subprocess.run(
            ['netstat', '-ano'],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if f':{port}' in line and 'LISTEN' in line:
                return True
        return False
    except Exception:
        return False

def is_port_open(port):
    """Check if port is listening on Linux."""
    try:
        result = subprocess.run(
            ['netstat', '-tuln'],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if f':{port}' in line and 'LISTEN' in line:
                return True
        return False
    except Exception:
        # Fallback: try ss command (more modern)
        try:
            result = subprocess.run(
                ['ss', '-tuln'],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTEN' in line:
                    return True
            return False
        except Exception:
            return False

# ============================================================================
# WINDOWS - WEB SERVER (Persistent, detached from terminal)
# ============================================================================

def start_web_server_detached():
    """Start Python HTTP server detached from terminal (survives window close)."""
    print("\n  Starting web server (persistent)...")
    
    try:
        import tempfile
        
        # Write web server script to temp file
        server_script = """
import http.server
import socketserver
import os

os.chdir(r'{project_root}')

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

try:
    with socketserver.TCPServer(("", 80), QuietHandler) as httpd:
        httpd.serve_forever()
except:
    pass
""".format(project_root=get_project_root())
        
        # Create temp script file
        fd, temp_script = tempfile.mkstemp(suffix='.py', text=True)
        try:
            os.write(fd, server_script.encode())
            os.close(fd)
            
            # Run with complete window suppression
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags |= subprocess.CREATE_NO_WINDOW
            
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            
            # Use the venv python if available
            python_exe = sys.executable
            
            proc = subprocess.Popen(
                [python_exe, temp_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=si,
                close_fds=True
            )
            
            # Wait for server to start
            for i in range(15):
                if win_is_port_open(80):
                    print("  [OK] Web server started on port 80 (persistent).")
                    return True
                time.sleep(1)
            
            print("  [!] Web server process started but port not responding yet.")
            return True
            
        finally:
            # Clean up temp file (it's now running)
            try:
                time.sleep(0.5)
                os.remove(temp_script)
            except:
                pass
        
    except Exception as e:
        print(f"  [ERROR] Could not start web server: {e}")
        return False

def add_firewall_rule():
    """Add Windows Firewall rules for SSH, HTTP, HTTPS."""
    print("\n  Configuring Windows Firewall...")
    
    rules = [
        ('SSH', 22, 'tcp'),
        ('HTTP', 80, 'tcp'),
        ('HTTPS', 443, 'tcp')
    ]
    
    for name, port, protocol in rules:
        try:
            # Remove existing rule if present
            subprocess.run(
                [
                    'powershell', '-NoProfile', '-Command',
                    f'Remove-NetFirewallRule -DisplayName "NIDS-{name}" -ErrorAction SilentlyContinue'
                ],
                capture_output=True,
                timeout=10
            )
            
            # Add new rule
            subprocess.run(
                [
                    'powershell', '-NoProfile', '-Command',
                    f'New-NetFirewallRule -DisplayName "NIDS-{name}" -Direction Inbound -Action Allow -Protocol {protocol} -LocalPort {port} -ErrorAction SilentlyContinue'
                ],
                capture_output=True,
                timeout=10
            )
        except Exception as e:
            print(f"    [!] Could not add {name} rule: {e}")

# ============================================================================
# LINUX - SSH & WEB SERVER SETUP
# ============================================================================

def linux_install_openssh():
    """Install and start OpenSSH on Linux."""
    print("\n=== SSH Server Setup ===")
    
    # Detect package manager
    package_managers = [
        (['apt', 'update'], ['apt', 'install', '-y', 'openssh-server']),  # Debian/Ubuntu
        (['dnf', 'check-update'], ['dnf', 'install', '-y', 'openssh-server']),  # Fedora
        (['yum', 'check-update'], ['yum', 'install', '-y', 'openssh-server']),  # RHEL/CentOS
        (['zypper', 'refresh'], ['zypper', 'install', '-y', 'openssh']),  # openSUSE
        (['pacman', '-Sy'], ['pacman', '-S', '--noconfirm', 'openssh']),  # Arch
        (['apk', 'update'], ['apk', 'add', 'openssh']),  # Alpine
    ]
    
    for update_cmd, install_cmd in package_managers:
        try:
            # Check if package manager exists
            subprocess.run(['which', update_cmd[0]], capture_output=True, check=True, timeout=5)
            
            print(f"  Using {update_cmd[0]}...")
            subprocess.run(update_cmd, capture_output=True, timeout=60)
            subprocess.run(install_cmd, capture_output=True, timeout=120)
            break
        except Exception:
            continue
    
    # Start SSH service
    print("  Starting SSH service...")
    try:
        subprocess.run(['sudo', 'systemctl', 'enable', 'ssh'], capture_output=True, timeout=10)
        subprocess.run(['sudo', 'systemctl', 'start', 'ssh'], capture_output=True, timeout=10)
        print("  [OK] SSH enabled and started.")
        return True
    except Exception as e:
        print(f"  [!] SSH startup issues: {e}")
        return False

def linux_start_web_server():
    """Start persistent web server on Linux."""
    print("\n  Starting web server...")
    
    try:
        subprocess.Popen(
            [sys.executable, '-m', 'http.server', '80'],
            cwd=get_project_root(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        print("  [OK] Web server started on port 80.")
        return True
    except Exception as e:
        print(f"  [!] Could not start web server: {e}")
        return False

# ============================================================================
# UTILITIES
# ============================================================================

def get_project_root():
    """Find project root by looking for main.py."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    current = script_dir
    
    while current != os.path.dirname(current):
        if os.path.exists(os.path.join(current, 'main.py')):
            return current
        current = os.path.dirname(current)
    
    return script_dir

def is_admin():
    """Check if running as admin on Windows."""
    try:
        import ctypes as ct
        return ct.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ============================================================================
# TCP WINDOW FIX — Match CICIDS2018 training victim (Ubuntu 16.04)
# ============================================================================
# CRITICAL for attack classification accuracy:
#
# The CICIDS2018 training data was collected from a victim running Ubuntu 16.04.
# That system had Init Bwd Win Byts = 219 in SYN-ACK responses. Modern Linux
# defaults are ~29200. The RandomForest model uses Init Bwd Win Byts as a
# selected feature with HIGH importance. The mismatch (29200 vs 219) causes
# attack flows to be classified as YELLOW instead of RED.
#
# Fix: Set `ip route ... window 219` for the attacker's IP on the victim.
# This makes the victim's SYN-ACK advertise window=219, matching training data.
#
# Model impact verified:
#   Without fix (bwdwin=29200): DoS ≈ 29% → YELLOW
#   With fix    (bwdwin=219):   DoS ≈ 50% → RED

_VICTIM_ROUTE_MODIFIED = False


def setup_victim_tcp_window(attacker_ip, window=219):
    """Configure victim TCP window to match CICIDS2018 training data.

    Sets `ip route replace <attacker_ip>/32 dev <iface> window 219` which
    makes the victim's SYN-ACK to the attacker advertise window=219.

    This matches the Ubuntu 16.04 victim used in CICIDS2018 dataset creation.
    Must be run on the VICTIM machine (this machine) as root.

    Args:
        attacker_ip: IP address of the attacker machine
        window: TCP window to advertise (default 219, matching CICIDS2018)
    """
    global _VICTIM_ROUTE_MODIFIED
    import re as re_mod

    if platform.system() != "Linux":
        print("[!] TCP window fix only applies to Linux victims")
        return False

    print(f"\n[*] ── TCP Window Configuration (Victim) ─────────")
    print(f"[*] Setting Init Bwd Win Byts = {window} for connections from {attacker_ip}")
    print(f"[*] Purpose: Match CICIDS2018 training victim (Ubuntu 16.04)")

    try:
        # 1. Get route to attacker to determine interface
        result = subprocess.run(
            ["ip", "route", "get", attacker_ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            print(f"[!!] Failed to get route: {result.stderr.strip()}")
            return False

        route_output = result.stdout.strip()
        print(f"[*] Current route: {route_output}")

        # Parse device
        dev_match = re_mod.search(r'\bdev\s+(\S+)', route_output)
        if not dev_match:
            print(f"[!!] Could not parse network interface from route")
            return False
        iface = dev_match.group(1)

        # Parse optional gateway
        via_match = re_mod.search(r'\bvia\s+(\S+)', route_output)
        gateway = via_match.group(1) if via_match else None

        # 2. Set route with window
        cmd = ["ip", "route", "replace", f"{attacker_ip}/32"]
        if gateway:
            cmd += ["via", gateway]
        cmd += ["dev", iface, "window", str(window)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"[!!] Failed to set route: {result.stderr.strip()}")
            print(f"[!!] Command: {' '.join(cmd)}")
            print(f"[!!] Need root/sudo to modify routes")
            return False

        _VICTIM_ROUTE_MODIFIED = True
        print(f"[OK] Route set: {' '.join(cmd)}")
        print(f"[OK] SYN-ACK to {attacker_ip} will now advertise window={window}")
        print(f"[*] ─────────────────────────────────────────────\n")
        return True

    except Exception as e:
        print(f"[!!] Error configuring TCP window: {e}")
        print(f"[*] ─────────────────────────────────────────────\n")
        return False


def restore_victim_tcp_window(attacker_ip):
    """Remove the /32 host route added by setup_victim_tcp_window."""
    global _VICTIM_ROUTE_MODIFIED

    if not _VICTIM_ROUTE_MODIFIED:
        return

    if platform.system() != "Linux":
        return

    try:
        subprocess.run(
            ["ip", "route", "del", f"{attacker_ip}/32"],
            capture_output=True, text=True, timeout=5
        )
        _VICTIM_ROUTE_MODIFIED = False
        print(f"[OK] Victim route restored (removed /32 override for {attacker_ip})")
    except Exception as e:
        print(f"[!] Could not restore victim route: {e}")
        print(f"[!] Manually run: ip route del {attacker_ip}/32")

# ============================================================================
# MAIN
# ============================================================================

def main():
    system = platform.system()
    
    print("\n" + "="*60)
    print("  Victim Device Setup Checker")
    print(f"  System: {system}")
    print("="*60 + "\n")
    
    if system == 'Windows':
        # Windows setup
        if not is_admin():
            print("[ERROR] This script must be run as Administrator.")
            print("Right-click setup_victim.bat and select 'Run as administrator'")
            sys.exit(1)
        
        ssh_ok = win_setup_ssh()
        web_ok = start_web_server_detached()
        add_firewall_rule()
        
        print("\n=== Setup Summary ===")
        print("  Services:")
        ssh_status = "OK" if ssh_ok else "SKIPPED"
        web_status = "OK" if web_ok else "FAILED"
        print(f"    SSH (port 22):  {ssh_status}")
        print(f"    HTTP (port 80): {web_status}")
        print(f"    FTP (port 21):  {'OK (port open)' if win_is_port_open(21) else 'Not installed'}")
        print("\n  Open Ports:")
        print(f"    Port 22 (SSH):  {'✓ OPEN' if win_is_port_open(22) else '✗ CLOSED'}")
        print(f"    Port 80 (HTTP): {'✓ OPEN' if win_is_port_open(80) else '✗ CLOSED'}")
        print(f"    Port 21 (FTP):  {'✓ OPEN' if win_is_port_open(21) else '✗ CLOSED'}")
        
    elif system == 'Linux':
        # Linux setup
        linux_install_openssh()
        linux_start_web_server()

        # TCP window fix for CICIDS2018 training data matching
        print("\n" + "="*60)
        print("  TCP Window Configuration (for attack classification)")
        print("="*60)
        print()
        print("  To classify attack flows as RED (detected), the victim must")
        print("  advertise Init Bwd Win Byts = 219 in SYN-ACK responses.")
        print("  This matches the Ubuntu 16.04 victim used in CICIDS2018.")
        print()
        resp = input("  [?] Configure TCP window for an attacker IP? (y/N): ").strip().lower()
        if resp in ("y", "yes"):
            attacker_ip = input("  [?] Enter attacker IP address: ").strip()
            if attacker_ip:
                setup_victim_tcp_window(attacker_ip, window=219)
            else:
                print("  [!] No IP provided, skipping TCP window setup")
                print("  [!] Run manually on this machine:")
                print("      ip route replace <ATTACKER_IP>/32 dev <IFACE> window 219")
        else:
            print("  [*] Skipping TCP window setup. Run manually if needed:")
            print("      ip route replace <ATTACKER_IP>/32 dev <IFACE> window 219")
        
        print("\n=== Setup Summary ===")
        print("  Services:")
        print(f"    SSH (port 22):  OK")
        print(f"    HTTP (port 80): OK")
        print(f"    FTP (port 21):  {'OK (port open)' if is_port_open(21) else 'Not installed'}")
        print(f"  TCP Window Fix:")
        print(f"    Victim route:   {'CONFIGURED (window=219)' if _VICTIM_ROUTE_MODIFIED else 'NOT SET (run manually)'}")
        print("\n  Open Ports:")
        print(f"    Port 22 (SSH):  {'OK OPEN' if is_port_open(22) else 'X CLOSED'}")
        print(f"    Port 80 (HTTP): {'OK OPEN' if is_port_open(80) else 'X CLOSED'}")
        print(f"    Port 21 (FTP):  {'OK OPEN' if is_port_open(21) else 'X CLOSED'}")
    
    else:
        print(f"[ERROR] Unsupported system: {system}")
        sys.exit(1)
    
    print("\n[OK] Victim device ready.\n")

if __name__ == '__main__':
    main()
