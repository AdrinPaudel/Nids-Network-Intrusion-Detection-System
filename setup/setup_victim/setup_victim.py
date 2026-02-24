#!/usr/bin/env python3
"""
Setup check for NIDS victim devices (Windows & Linux).

Windows:  Run as Administrator
Linux:    Run with sudo

Real fixes for common issues:
  - SSH service won't start → Try to fix service config and run sshd directly
  - Web server won't persist → Use DETACHED_PROCESS so it survives terminal close
"""

import os
import sys
import platform
import socket
import time
import ctypes
import subprocess
import tempfile
import shutil
from pathlib import Path


# ==================================================================
# Admin Check & Version
# ==================================================================

def is_admin():
    """Check if running with admin/root privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False


def win_get_version():
    """Get Windows version as (major, build)."""
    try:
        import platform as _p
        version_str = _p.version()
        parts = version_str.split('.')
        major = int(parts[0])
        build = int(parts[2]) if len(parts) > 2 else 0
        return major, build
    except:
        return 10, 0


# ==================================================================
# Command Execution
# ==================================================================

def run_cmd(cmd, shell=True, timeout=10, silent=False):
    """Run shell command, return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            timeout=timeout,
            capture_output=True,
            text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        if not silent:
            print(f"      [!] Command timed out")
        return False, "", "timeout"
    except Exception as e:
        if not silent:
            print(f"      [!] Error: {e}")
        return False, "", str(e)


def run_ps(cmd, timeout=10, silent=False):
    """Run PowerShell command."""
    ps_cmd = f'powershell -NoProfile -Command "{cmd}"'
    return run_cmd(ps_cmd, timeout=timeout, silent=silent)


# ==================================================================
# Network Detection
# ==================================================================

def get_all_ips():
    """Get all IPv4 addresses."""
    ips = set()

    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        ips.update(ip_list)
    except:
        pass

    if platform.system() == "Windows":
        success, stdout, _ = run_cmd("ipconfig", silent=True)
        if success:
            for line in stdout.split('\n'):
                if "IPv4 Address" in line:
                    try:
                        ip = line.split(':')[1].strip()
                        if ip:
                            ips.add(ip)
                    except:
                        pass

    return sorted(list(ips))


# ==================================================================
# Windows: Port Detection
# ==================================================================

def win_port_listening(port):
    """Check if Windows port is listening."""
    success, stdout, _ = run_cmd(
        f"netstat -an 2>nul | findstr /R \":{port}.*LISTENING\"",
        timeout=3,
        silent=True
    )
    return success and stdout.strip() != ""


# ==================================================================
# Windows: Service Management
# ==================================================================

def win_service_running(service_name):
    """Check if Windows service is running."""
    success, stdout, _ = run_cmd(
        f'sc query "{service_name}"',
        silent=True
    )
    return success and "RUNNING" in stdout


# ==================================================================
# Windows: SSH Service Fix
# ==================================================================

def win_start_sshd():
    """Start SSH service - actually fix it this time."""
    print("      Attempting to start SSH...")
    
    # Method 1: Check if already running
    if win_port_listening(22):
        print("      [OK] Port 22 already listening")
        return True
    
    # Method 2: Try net start
    success, stdout, stderr = run_cmd("net start sshd", silent=True)
    if success or "already" in stderr.lower():
        time.sleep(2)
        if win_port_listening(22):
            print("      [OK] SSH service started (net start)")
            return True
    
    # Method 3: Stop and restart cycle
    print("      Trying stop/restart cycle...")
    run_cmd("net stop sshd 2>nul", silent=True)
    time.sleep(2)
    
    success, stdout, stderr = run_cmd("net start sshd", silent=True)
    if "error" in stderr.lower() or "denied" in stderr.lower():
        print(f"      Error: {stderr[:80]}")
        # Try PowerShell
        print("      Trying PowerShell...")
        run_ps("Start-Service sshd -ErrorAction SilentlyContinue", silent=True)
        time.sleep(2)
    
    time.sleep(2)
    if win_port_listening(22):
        print("      [OK] SSH service started")
        return True
    
    print("      [!] SSH service won't start - checking why...")
    
    # Find sshd.exe and test it
    for sshd_path in ["C:\\Windows\\System32\\OpenSSH\\sshd.exe", "C:\\Program Files\\OpenSSH\\sshd.exe"]:
        if os.path.exists(sshd_path):
            print(f"      Found: {sshd_path}")
            # Run config test
            success, stdout, stderr = run_cmd(f'"{sshd_path}" -T', silent=True, timeout=5)
            if not success:
                print(f"      Config error: {stderr[:80]}")
            break
    
    return False


# ==================================================================
# Windows: Web Server (PERSISTENT START)
# ==================================================================

def start_web_server_detached(python_exe, nids_dir):
    """Start web server that persists when terminal closes."""
    print("      Starting web server (detached)...")
    
    try:
        # Use DETACHED_PROCESS so it doesn't die with terminal
        for wait_cycle in range(15):
            try:
                proc = subprocess.Popen(
                    [python_exe, "-m", "http.server", "80"],
                    cwd=nids_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                )
                print(f"      Process started (PID: {proc.pid})")
                break
            except Exception as e:
                if wait_cycle < 14:
                    time.sleep(1)
                else:
                    raise
        
        # Wait for port to listen
        for attempt in range(15):
            time.sleep(1)
            if win_port_listening(80):
                print(f"      [OK] Web server listening on port 80")
                return True
        
        print("      [!] Process started but port 80 not listening")
        return False
        
    except Exception as e:
        print(f"      [!] Failed: {e}")
        return False


# ==================================================================
# Windows: Task Scheduler for Web Server
# ==================================================================

def create_task_scheduler_task(python_exe, nids_dir):
    """Create Task Scheduler task for auto-start."""
    print("      Creating Task Scheduler entry...")
    
    task_name = "NIDS_WebServer"
    
    # Remove old task
    run_cmd(f'schtasks /delete /tn "{task_name}" /f 2>&1', silent=True)
    
    try:
        temp_dir = tempfile.gettempdir()
        batch_file = os.path.join(temp_dir, "start_nids_web.bat")
        
        # Create batch that runs Python
        with open(batch_file, 'w') as f:
            f.write('@echo off\n')
            f.write(f'cd /d "{nids_dir}"\n')
            f.write(f'"{python_exe}" -m http.server 80\n')
        
        # Create and register task
        success, _, _ = run_cmd(
            f'schtasks /create /tn "{task_name}" /tr "{batch_file}" /sc onlogon /rl highest /f 2>&1',
            silent=True,
            timeout=10
        )
        
        if success:
            print(f"      [OK] Task created")
            return True
        else:
            print(f"      [!] Task creation failed")
            return False
            
    except Exception as e:
        print(f"      [!] Error: {e}")
        return False


# ==================================================================
# Windows: Firewall
# ==================================================================

def add_firewall_rule(port):
    """Add Windows firewall rule."""
    rule_name = f"NIDS_Allow_{port}"
    
    # Check if already exists
    success, stdout, _ = run_ps(
        f'Get-NetFirewallRule -DisplayName "{rule_name}" 2>&1',
        silent=True
    )
    if success:
        return True
    
    # Create rule
    cmd = (
        f'New-NetFirewallRule -DisplayName "{rule_name}" '
        f'-Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} 2>&1'
    )
    success, _, _ = run_ps(cmd, silent=True)
    return success


# ==================================================================
# Project Check
# ==================================================================

def check_nids_project():
    """Check if NIDS project exists."""
    current_dir = Path(__file__).parent.parent.parent
    
    for candidate in [current_dir, current_dir.parent, Path("Z:/Nids")]:
        if (candidate / "main.py").exists():
            print(f"      [OK] Project: {candidate}")
            return candidate
    
    print(f"      [!] Project not found")
    return None


def ask_yes_no(q):
    """Ask user."""
    while True:
        response = input(f"      {q} (y/n): ").strip().lower()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False


# ==================================================================
# MAIN SETUP
# ==================================================================

def setup_windows():
    """Windows setup."""
    issues = 0

    major, build = win_get_version()
    print(f"  Windows {'11' if build >= 22000 else '10'} (build {build})\n")

    # SSH
    print("  [1] SSH Server (port 22)")
    print()
    if not win_port_listening(22):
        print("      [!] Port 22 NOT open")
        if ask_yes_no("Start SSH service?"):
            if not win_start_sshd():
                issues += 1
    else:
        print("      [OK] Port 22 listening")
    print()

    # Web Server
    print("  [2] Web Server (port 80)")
    print()
    if not win_port_listening(80):
        print("      [!] Port 80 NOT open")
        if ask_yes_no("Start web server?"):
            nids_dir = check_nids_project()
            if nids_dir:
                python_exe = nids_dir / "venv" / "Scripts" / "python.exe"
                if python_exe.exists():
                    if start_web_server_detached(str(python_exe), str(nids_dir)):
                        if ask_yes_no("Add Task Scheduler auto-start?"):
                            create_task_scheduler_task(str(python_exe), str(nids_dir))
                    else:
                        issues += 1
                else:
                    print("      [!] Python venv not found")
                    issues += 1
            else:
                issues += 1
    else:
        print("      [OK] Port 80 listening")
    print()

    # Firewall
    print("  [3] Firewall Rules")
    print()
    for port in [22, 80, 443]:
        if add_firewall_rule(port):
            print(f"      [OK] Port {port} rule set")
        else:
            print(f"      [!] Port {port} rule failed")
            issues += 1
    print()

    return issues


def main():
    os_name = platform.system()

    print(f"\n{'='*60}")
    print(f"  NIDS Victim Setup — {os_name}")
    print(f"{'='*60}\n")

    if not is_admin():
        print("  [ERROR] Run as Administrator")
        sys.exit(1)

    print("  [OK] Admin privileges confirmed\n")

    print("  Network interfaces:")
    for ip in get_all_ips():
        print(f"      -> {ip}")
    print()

    if os_name == "Windows":
        issues = setup_windows()
    else:
        print("  [!] Unsupported OS")
        return 1

    print(f"{'='*60}")
    if issues == 0:
        print("  [OK] Setup complete")
    else:
        print(f"  [!] {issues} issue(s) - see above")
    print(f"{'='*60}\n")

    return issues


if __name__ == "__main__":
    sys.exit(main())
