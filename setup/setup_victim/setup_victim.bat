@echo off & python -x "%~f0" %* & exit /b !errorlevel!
"""
Victim Device Setup - Windows & Linux (Single File Launcher)
Run as: setup_victim.bat (on Windows)
Right-click -> Run as Administrator
"""

import os
import sys
import platform
import subprocess
import socket
import time
from pathlib import Path

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
        result = subprocess.run(
            ['msiexec.exe', '/i', installer_path, '/quiet', '/norestart'],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        time.sleep(3)
        
        if win_check_openssh_service():
            print("  [OK] OpenSSH installed and service found.")
            return True
        else:
            print("  [!] OpenSSH installed but service not detected yet.")
            return True
            
    except Exception as e:
        print(f"  [ERROR] Installation failed: {e}")
        return False

def win_start_sshd():
    """Start OpenSSH service on Windows."""
    print("  Starting OpenSSH service...")
    
    try:
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
    
    if win_is_port_open(22):
        print("  [OK] SSH is already running on port 22.")
        return True
    
    print("  SSH not detected. Installing...")
    
    if win_check_openssh_service():
        print("  [OK] OpenSSH service found, starting it...")
        return win_start_sshd()
    
    if win_enable_builtin_openssh():
        return win_start_sshd()
    
    installer = win_download_standalone_openssh()
    if installer:
        if win_install_standalone_openssh(installer):
            win_start_sshd()
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
            return False
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

def get_project_root():
    """Find project root by looking for main.py."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    current = script_dir
    
    while current != os.path.dirname(current):
        if os.path.exists(os.path.join(current, 'main.py')):
            return current
        current = os.path.dirname(current)
    
    return script_dir

def start_web_server_detached():
    """Start Python HTTP server detached from terminal (survives window close)."""
    print("\n  Starting web server (persistent)...")
    
    try:
        import tempfile
        
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
        
        fd, temp_script = tempfile.mkstemp(suffix='.py', text=True)
        try:
            os.write(fd, server_script.encode())
            os.close(fd)
            
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                creationflags |= subprocess.CREATE_NO_WINDOW
            
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            
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
            
            for i in range(15):
                if win_is_port_open(80):
                    print("  [OK] Web server started on port 80 (persistent).")
                    return True
                time.sleep(1)
            
            print("  [!] Web server process started but port not responding yet.")
            return True
            
        finally:
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
            subprocess.run(
                [
                    'powershell', '-NoProfile', '-Command',
                    f'Remove-NetFirewallRule -DisplayName "NIDS-{name}" -ErrorAction SilentlyContinue'
                ],
                capture_output=True,
                timeout=10
            )
            
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

def is_admin():
    """Check if running as admin on Windows."""
    try:
        import ctypes as ct
        return ct.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ============================================================================
# LINUX - SSH & WEB SERVER SETUP
# ============================================================================

def linux_install_openssh():
    """Install and start OpenSSH on Linux."""
    print("\n=== SSH Server Setup ===")
    
    package_managers = [
        (['apt', 'update'], ['apt', 'install', '-y', 'openssh-server']),
        (['dnf', 'check-update'], ['dnf', 'install', '-y', 'openssh-server']),
        (['yum', 'check-update'], ['yum', 'install', '-y', 'openssh-server']),
        (['zypper', 'refresh'], ['zypper', 'install', '-y', 'openssh']),
        (['pacman', '-Sy'], ['pacman', '-S', '--noconfirm', 'openssh']),
        (['apk', 'update'], ['apk', 'add', 'openssh']),
    ]
    
    for update_cmd, install_cmd in package_managers:
        try:
            subprocess.run(['which', update_cmd[0]], capture_output=True, check=True, timeout=5)
            print(f"  Using {update_cmd[0]}...")
            subprocess.run(update_cmd, capture_output=True, timeout=60)
            subprocess.run(install_cmd, capture_output=True, timeout=120)
            break
        except Exception:
            continue
    
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
# MAIN
# ============================================================================

def main():
    system = platform.system()
    
    print("\n" + "="*60)
    print("  Victim Device Setup Checker")
    print(f"  System: {system}")
    print("="*60 + "\n")
    
    if system == 'Windows':
        if not is_admin():
            print("[ERROR] This script must be run as Administrator.")
            print("Right-click setup_victim.bat and select 'Run as administrator'")
            sys.exit(1)
        
        ssh_ok = win_setup_ssh()
        web_ok = start_web_server_detached()
        add_firewall_rule()
        
        print("\n=== Setup Summary ===")
        ssh_status = "OK" if ssh_ok else "SKIPPED"
        web_status = "OK" if web_ok else "FAILED"
        print(f"  SSH:  {ssh_status}")
        print(f"  Web:  {web_status}")
        
    elif system == 'Linux':
        linux_install_openssh()
        linux_start_web_server()
        
        print("\n=== Setup Summary ===")
        print("  [OK] Linux victim setup complete.")
    
    else:
        print(f"[ERROR] Unsupported system: {system}")
        sys.exit(1)
    
    print("\n[OK] Victim device ready.\n")
    
    print("="*60)
    print("  Victim Setup Complete!")
    print("="*60)
    print()
    print("  Next steps:")
    print()
    print("  1. Activate venv (every new terminal):")
    print("       venv\\Scripts\\activate.bat")
    print()
    print("  2. For details on running features:")
    print("       See: PROJECT_RUN.md (in project root)")
    print()
    print("  3. To set up other components:")
    print("       See: setup/SETUPS.md")
    print()
    print("  4. For project overview:")
    print("       See: README.md (in project root)")
    print()

if __name__ == '__main__':
    main()
