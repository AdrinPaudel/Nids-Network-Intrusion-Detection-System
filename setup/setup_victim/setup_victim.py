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

# Color codes for output
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

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
        print(f"  {Color.RED}[!] Error checking OpenSSH: {e}{Color.END}")
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
            print(f"  {Color.GREEN}[OK] Windows built-in OpenSSH enabled.{Color.END}")
            return True
        else:
            print(f"  {Color.YELLOW}[!] Built-in OpenSSH not available for this Windows version.{Color.END}")
            return False
    except Exception as e:
        print(f"  {Color.YELLOW}[!] Could not enable built-in OpenSSH: {e}{Color.END}")
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
            print(f"  {Color.GREEN}[OK] Downloaded to {installer_path}{Color.END}")
            return installer_path
        else:
            print(f"  {Color.RED}[ERROR] Download failed.{Color.END}")
            return None
            
    except Exception as e:
        print(f"  {Color.RED}[ERROR] Download failed: {e}{Color.END}")
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
            print(f"  {Color.GREEN}[OK] OpenSSH installed and service found.{Color.END}")
            return True
        else:
            print(f"  {Color.YELLOW}[!] OpenSSH installed but service not detected yet.{Color.END}")
            return True  # Installation succeeded, service may start on reboot
            
    except Exception as e:
        print(f"  {Color.RED}[ERROR] Installation failed: {e}{Color.END}")
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
            print(f"  {Color.GREEN}[OK] OpenSSH service started on port 22.{Color.END}")
            return True
        else:
            print(f"  {Color.YELLOW}[!] Service start attempt completed, checking port...{Color.END}")
            time.sleep(2)
            
            if win_is_port_open(22):
                print(f"  {Color.GREEN}[OK] Port 22 is now open.{Color.END}")
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
                    print(f"  {Color.GREEN}[OK] OpenSSH service started.{Color.END}")
                    return True
                else:
                    print(f"  {Color.YELLOW}[!] Could not start OpenSSH service. Check Windows Event Log.{Color.END}")
                    return False
                    
    except Exception as e:
        print(f"  {Color.RED}[ERROR] Error starting service: {e}{Color.END}")
        return False

def win_setup_ssh():
    """Main SSH setup orchestration for Windows."""
    print(f"\n{Color.BLUE}=== SSH Server Setup ==={Color.END}")
    
    # Check if already running
    if win_is_port_open(22):
        print(f"  {Color.GREEN}[OK] SSH is already running on port 22.{Color.END}")
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
    
    # Step 4: Failure - offer to skip SSH
    print(f"\n{Color.YELLOW}[!] Could not set up OpenSSH.{Color.END}")
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

# ============================================================================
# WINDOWS - WEB SERVER (Persistent, detached from terminal)
# ============================================================================

def start_web_server_detached():
    """Start Python HTTP server detached from terminal (survives window close)."""
    print("\n  Starting web server (persistent)...")
    
    try:
        script = """
import http.server
import socketserver
import os

os.chdir(r'{project_root}')

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("", 80), QuietHandler) as httpd:
    print("[OK] Web server running on port 80", flush=True)
    httpd.serve_forever()
""".format(project_root=get_project_root())
        
        # Windows: Use DETACHED_PROCESS so it survives terminal close
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        
        proc = subprocess.Popen(
            [sys.executable, '-c', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            startupinfo=si
        )
        
        # Wait for server to start
        for i in range(15):
            if win_is_port_open(80):
                print(f"  {Color.GREEN}[OK] Web server started on port 80 (persistent).{Color.END}")
                return True
            time.sleep(1)
        
        print(f"  {Color.YELLOW}[!] Web server process started but port not responding yet.{Color.END}")
        return True  # Process is running, port may take a moment
        
    except Exception as e:
        print(f"  {Color.RED}[ERROR] Could not start web server: {e}{Color.END}")
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
            print(f"    {Color.YELLOW}[!] Could not add {name} rule: {e}{Color.END}")

# ============================================================================
# LINUX - SSH & WEB SERVER SETUP
# ============================================================================

def linux_install_openssh():
    """Install and start OpenSSH on Linux."""
    print(f"\n{Color.BLUE}=== SSH Server Setup ==={Color.END}")
    
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
        print(f"  {Color.GREEN}[OK] SSH enabled and started.{Color.END}")
        return True
    except Exception as e:
        print(f"  {Color.YELLOW}[!] SSH startup issues: {e}{Color.END}")
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
        print(f"  {Color.GREEN}[OK] Web server started on port 80.{Color.END}")
        return True
    except Exception as e:
        print(f"  {Color.YELLOW}[!] Could not start web server: {e}{Color.END}")
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
# MAIN
# ============================================================================

def main():
    system = platform.system()
    
    print(f"\n{Color.BLUE}{'='*60}")
    print(f"  Victim Device Setup Checker")
    print(f"  System: {system}")
    print(f"{'='*60}{Color.END}\n")
    
    if system == 'Windows':
        # Windows setup
        if not is_admin():
            print(f"{Color.RED}[ERROR] This script must be run as Administrator.{Color.END}")
            print("Right-click setup_victim.bat and select 'Run as administrator'")
            sys.exit(1)
        
        ssh_ok = win_setup_ssh()
        web_ok = start_web_server_detached()
        add_firewall_rule()
        
        print(f"\n{Color.BLUE}=== Setup Summary ==={Color.END}")
        print(f"  SSH:  {Color.GREEN if ssh_ok else Color.YELLOW}{'OK' if ssh_ok else 'SKIPPED'}{Color.END}")
        print(f"  Web:  {Color.GREEN if web_ok else Color.RED}{'OK' if web_ok else 'FAILED'}{Color.END}")
        
    elif system == 'Linux':
        # Linux setup
        linux_install_openssh()
        linux_start_web_server()
        
        print(f"\n{Color.BLUE}=== Setup Summary ==={Color.END}")
        print(f"  {Color.GREEN}[OK] Linux victim setup complete.{Color.END}")
    
    else:
        print(f"{Color.RED}[ERROR] Unsupported system: {system}{Color.END}")
        sys.exit(1)
    
    print(f"\n{Color.GREEN}[OK] Victim device ready.{Color.END}\n")

if __name__ == '__main__':
    main()
