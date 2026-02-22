#!/usr/bin/env python
"""
Botnet Behavior Simulation - Ares/Zeus Style (CICIDS2018 methodology)
Simulates botnet Command-and-Control (C2) communication patterns.

CICIDS2018 used Ares and Zeus botnets (Mar 2):
  - HTTP-based C2 channel (bot checks in with server, receives commands)
  - Remote shell command execution
  - File upload/download
  - Screenshots every 400 seconds
  - Keylogging data exfiltration

The key is BIDIRECTIONAL HTTP traffic with periodic beaconing,
command exchange, and data exfiltration patterns.

Should be detected as 'Botnet' by your NIDS.
"""

import sys
import time
import socket
import random
import string
import threading
import json
import base64
import hashlib


# ======================================================================
# C2 Beacon (HTTP-based check-in)
# ======================================================================
def c2_beacon(target_ip, target_port=80, duration=120, beacon_interval=10):
    """
    Ares-style C2 beaconing over HTTP.
    Bot periodically checks in with C2 server:
      1. POST /api/check_in  (bot info)
      2. GET  /api/commands   (poll for commands)
      3. POST /api/report     (send results)

    Creates realistic bidirectional HTTP flows with periodic patterns.
    """
    print(f"\n{'='*60}")
    print(f"Botnet - C2 Beaconing (Ares-style HTTP C2)")
    print(f"{'='*60}")
    print(f"Target C2: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Beacon interval: {beacon_interval} seconds")
    print(f"\n[!] Starting C2 beaconing... (Your NIDS should show 'Botnet')")
    print(f"{'='*60}\n")

    # Simulated bot identity
    bot_id = hashlib.md5(f"bot-{random.randint(1000,9999)}".encode()).hexdigest()[:12]
    os_info = random.choice(["Windows 10", "Windows 11", "Windows 7 SP1", "Ubuntu 22.04"])

    counters = {"beacons": 0, "commands_received": 0, "responses_sent": 0}
    stop_event = threading.Event()
    start_time = time.time()

    def send_http_request(method, path, body=None):
        """Send an HTTP request and read the full response"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, target_port))

            if body:
                body_bytes = body.encode() if isinstance(body, str) else body
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body_bytes)}\r\n"
                    f"X-Bot-ID: {bot_id}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode() + body_bytes
            else:
                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"Host: {target_ip}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"X-Bot-ID: {bot_id}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()

            s.sendall(request)

            # Read response (bidirectional traffic!)
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except:
                    break

            s.close()
            return response
        except Exception:
            return None

    def beacon_cycle():
        """One full beacon cycle: check-in -> poll -> respond"""
        # Step 1: Check in with C2 (POST bot info)
        checkin_data = json.dumps({
            "bot_id": bot_id,
            "os": os_info,
            "hostname": f"DESKTOP-{random.randint(1000,9999)}",
            "ip": f"192.168.1.{random.randint(10,250)}",
            "uptime": int(time.time() - start_time),
            "idle": random.randint(0, 300),
            "av": random.choice(["none", "Windows Defender", "Avast", "Norton"]),
        })
        resp = send_http_request("POST", "/api/check_in", checkin_data)
        counters["beacons"] += 1

        time.sleep(random.uniform(0.5, 2.0))

        # Step 2: Poll for commands (GET)
        resp = send_http_request("GET", f"/api/commands?bot_id={bot_id}&t={int(time.time())}")
        counters["commands_received"] += 1

        time.sleep(random.uniform(0.3, 1.5))

        # Step 3: Simulate executing a command and reporting result
        # Generate fake command output (like Ares remote shell)
        fake_commands = [
            ("whoami", f"DESKTOP-{''.join(random.choices(string.ascii_uppercase, k=4))}\\admin"),
            ("ipconfig", f"IPv4 Address: 192.168.1.{random.randint(10,250)}\nSubnet Mask: 255.255.255.0\nDefault Gateway: 192.168.1.1"),
            ("systeminfo", f"OS Name: Microsoft {os_info}\nOS Version: 10.0.19045\nSystem Type: x64-based PC\nTotal Physical Memory: {random.randint(4,32)},000 MB"),
            ("dir", "\n".join([f"{''.join(random.choices(string.ascii_lowercase, k=8))}.{''.join(random.choices(['txt','doc','pdf','xlsx'], k=1))}" for _ in range(random.randint(5, 15))])),
            ("tasklist", "\n".join([f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(4,12)))}.exe  {random.randint(1000,9999)}  Console  {random.randint(1,100)},000 K" for _ in range(random.randint(10, 30))])),
            ("netstat", "\n".join([f"TCP  192.168.1.{random.randint(10,250)}:{random.randint(49000,65535)}  {''.join(random.choices(string.digits, k=3))}.{''.join(random.choices(string.digits, k=3))}.{''.join(random.choices(string.digits, k=3))}.{''.join(random.choices(string.digits, k=3))}:{''.join(random.choices(['80','443','8080','22','3389'], k=1))}  ESTABLISHED" for _ in range(random.randint(5, 15))])),
        ]
        cmd, output = random.choice(fake_commands)

        report_data = json.dumps({
            "bot_id": bot_id,
            "command": cmd,
            "output": output,
            "exec_time": random.uniform(0.1, 2.0),
            "timestamp": int(time.time()),
        })
        resp = send_http_request("POST", "/api/report", report_data)
        counters["responses_sent"] += 1

    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            beacon_cycle()
            elapsed = time.time() - start_time
            print(f"[+] Beacon #{counters['beacons']} | Commands: {counters['commands_received']} | Reports: {counters['responses_sent']} | {elapsed:.0f}s / {duration}s")

            # Jittered sleep (realistic beaconing has random intervals)
            jitter = beacon_interval * random.uniform(0.7, 1.3)
            time.sleep(jitter)

    except KeyboardInterrupt:
        print("\n[!] Beaconing interrupted by user")
    finally:
        stop_event.set()
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] C2 Beaconing complete!")
        print(f"    Bot ID: {bot_id}")
        print(f"    Total beacons: {counters['beacons']}")
        print(f"    Commands received: {counters['commands_received']}")
        print(f"    Reports sent: {counters['responses_sent']}")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# File Transfer (Data Exfiltration)
# ======================================================================
def file_exfiltration(target_ip, target_port=80, duration=120):
    """
    Ares-style file upload/download simulation.
    Bot uploads 'stolen' files and downloads payloads from C2.
    Creates large bidirectional flows.
    """
    print(f"\n{'='*60}")
    print(f"Botnet - File Exfiltration (Ares-style uploads)")
    print(f"{'='*60}")
    print(f"Target C2: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"\n[!] Starting file exfiltration... (Your NIDS should show 'Botnet')")
    print(f"{'='*60}\n")

    bot_id = hashlib.md5(f"exfil-{random.randint(1000,9999)}".encode()).hexdigest()[:12]
    counters = {"uploads": 0, "downloads": 0, "bytes_up": 0, "bytes_down": 0}
    start_time = time.time()

    def simulate_upload(filename, size_range=(1024, 65536)):
        """Upload a 'stolen file' to C2"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target_ip, target_port))

            file_size = random.randint(*size_range)
            file_data = base64.b64encode(bytes(random.getrandbits(8) for _ in range(file_size // 2))).decode()

            body = json.dumps({
                "bot_id": bot_id,
                "filename": filename,
                "data": file_data,
                "timestamp": int(time.time()),
            })
            body_bytes = body.encode()

            request = (
                f"POST /api/upload HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"X-Bot-ID: {bot_id}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body_bytes

            s.sendall(request)
            counters["bytes_up"] += len(request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    counters["bytes_down"] += len(chunk)
                except:
                    break

            s.close()
            counters["uploads"] += 1
            return True
        except Exception:
            return False

    def simulate_download():
        """Download a 'payload' from C2"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target_ip, target_port))

            request = (
                f"GET /api/download?bot_id={bot_id}&file=update.bin&t={int(time.time())} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"X-Bot-ID: {bot_id}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            s.sendall(request)
            counters["bytes_up"] += len(request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    counters["bytes_down"] += len(chunk)
                except:
                    break

            s.close()
            counters["downloads"] += 1
            return True
        except Exception:
            return False

    fake_files = [
        "passwords.txt", "browser_cookies.db", "outlook_contacts.csv",
        "wallet.dat", "id_rsa", "credentials.xml", "keychain.plist",
        "financial_report.xlsx", "customer_data.csv", "ssh_keys.tar.gz",
        "screenshot.png", "keylog.txt", "browser_history.sqlite",
    ]

    try:
        while time.time() - start_time < duration:
            # Simulate upload
            filename = random.choice(fake_files)
            simulate_upload(filename)
            print(f"  [UPLOAD] {filename} ({counters['bytes_up']/1024:.1f} KB total up)")
            time.sleep(random.uniform(2, 8))

            # Occasionally download payloads
            if random.random() < 0.4:
                simulate_download()
                print(f"  [DOWNLOAD] payload ({counters['bytes_down']/1024:.1f} KB total down)")
                time.sleep(random.uniform(1, 5))

            elapsed = time.time() - start_time
            print(f"[+] Files: {counters['uploads']} up, {counters['downloads']} down | {elapsed:.0f}s / {duration}s")

    except KeyboardInterrupt:
        print("\n[!] Exfiltration interrupted by user")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] File Exfiltration complete!")
        print(f"    Uploads: {counters['uploads']}")
        print(f"    Downloads: {counters['downloads']}")
        print(f"    Bytes uploaded: {counters['bytes_up']/1024:.1f} KB")
        print(f"    Bytes downloaded: {counters['bytes_down']/1024:.1f} KB")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# Screenshot + Keylogger Exfil (Ares patterns)
# ======================================================================
def screenshot_keylog(target_ip, target_port=80, duration=120, screenshot_interval=30):
    """
    Ares-style screenshot + keylogger exfiltration.
    CICIDS2018: screenshots every 400 seconds, keylogging continuous.
    We use shorter intervals (30s default) to generate more traffic
    in a reasonable test duration.
    """
    print(f"\n{'='*60}")
    print(f"Botnet - Screenshot + Keylogger (Ares-style)")
    print(f"{'='*60}")
    print(f"Target C2: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Screenshot interval: {screenshot_interval}s (CICIDS2018 used 400s)")
    print(f"\n[!] Starting screenshot/keylog exfil... (Your NIDS should show 'Botnet')")
    print(f"{'='*60}\n")

    bot_id = hashlib.md5(f"spy-{random.randint(1000,9999)}".encode()).hexdigest()[:12]
    counters = {"screenshots": 0, "keylogs": 0, "bytes_sent": 0}
    start_time = time.time()
    last_screenshot = 0

    def send_data(path, data_dict):
        """Send data to C2 over HTTP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target_ip, target_port))

            body = json.dumps(data_dict).encode()
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"X-Bot-ID: {bot_id}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body

            s.sendall(request)
            counters["bytes_sent"] += len(request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except:
                    break

            s.close()
            return True
        except Exception:
            return False

    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time

            # Screenshot exfiltration at intervals
            if elapsed - last_screenshot >= screenshot_interval:
                # Simulate screenshot data (10-50 KB of base64 encoded "image")
                screenshot_size = random.randint(10240, 51200)
                screenshot_data = base64.b64encode(
                    bytes(random.getrandbits(8) for _ in range(screenshot_size))
                ).decode()

                send_data("/api/screenshot", {
                    "bot_id": bot_id,
                    "timestamp": int(time.time()),
                    "resolution": random.choice(["1920x1080", "2560x1440", "1366x768"]),
                    "data": screenshot_data,
                })
                counters["screenshots"] += 1
                last_screenshot = elapsed
                print(f"  [SCREENSHOT] #{counters['screenshots']} ({screenshot_size/1024:.1f} KB)")

            # Keylogger data every 5-15 seconds
            keylog_words = random.randint(20, 100)
            keylog_text = " ".join([
                ''.join(random.choices(string.ascii_lowercase, k=random.randint(2, 12)))
                for _ in range(keylog_words)
            ])

            # Include window titles (like real keyloggers)
            window_titles = random.choice([
                "Google Chrome - Gmail", "Microsoft Word - Document1",
                "Firefox - Facebook", "File Explorer - C:\\Users\\admin",
                "Outlook - Inbox", "cmd.exe", "PowerShell",
            ])

            send_data("/api/keylog", {
                "bot_id": bot_id,
                "timestamp": int(time.time()),
                "window": window_titles,
                "keys": keylog_text,
            })
            counters["keylogs"] += 1

            print(f"[+] Screenshots: {counters['screenshots']} | Keylogs: {counters['keylogs']} | {counters['bytes_sent']/1024:.1f} KB sent | {elapsed:.0f}s / {duration}s")

            # Sleep between keylog sends
            time.sleep(random.uniform(5, 15))

    except KeyboardInterrupt:
        print("\n[!] Exfiltration interrupted by user")
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"[+] Screenshot/Keylog exfiltration complete!")
        print(f"    Screenshots sent: {counters['screenshots']}")
        print(f"    Keylog batches sent: {counters['keylogs']}")
        print(f"    Total bytes: {counters['bytes_sent']/1024:.1f} KB")
        print(f"    Time elapsed: {elapsed:.1f}s")
        print(f"{'='*60}\n")


# ======================================================================
# Full Botnet Simulation (all behaviors combined)
# ======================================================================
def full_botnet(target_ip, target_port=80, duration=120, beacon_interval=10):
    """
    Combines all Ares-style botnet behaviors:
    - C2 beaconing (check-in, poll, report) in main thread
    - File exfiltration in background
    - Screenshot + keylog in background
    """
    print(f"\n{'='*60}")
    print(f"Botnet - Full Simulation (Ares + Zeus style)")
    print(f"{'='*60}")
    print(f"Target C2: http://{target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"\n[!] Running all botnet behaviors simultaneously...")
    print(f"{'='*60}\n")

    threads = []

    # Run each behavior in its own thread
    t1 = threading.Thread(
        target=c2_beacon,
        args=(target_ip, target_port, duration, beacon_interval),
        daemon=True
    )
    t2 = threading.Thread(
        target=file_exfiltration,
        args=(target_ip, target_port, duration),
        daemon=True
    )
    t3 = threading.Thread(
        target=screenshot_keylog,
        args=(target_ip, target_port, duration, 30),
        daemon=True
    )

    t1.start()
    time.sleep(2)
    t2.start()
    time.sleep(2)
    t3.start()

    try:
        t1.join()
        t2.join()
        t3.join()
    except KeyboardInterrupt:
        print("\n[!] Full botnet simulation interrupted")


# ======================================================================
# Main
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 5_botnet_behavior.py <TARGET_IP> [OPTIONS]")
        print()
        print("Modes (matching CICIDS2018 Ares/Zeus botnet):")
        print("  --beacon        C2 beaconing only (default)")
        print("  --exfil         File exfiltration simulation")
        print("  --keylog        Screenshot + keylogger exfiltration")
        print("  --full-botnet   All behaviors combined")
        print()
        print("Options:")
        print("  --port <PORT>       C2 port (default: 80)")
        print("  --duration <SEC>    Duration in seconds (default: 120)")
        print("  --interval <SEC>    Beacon interval in seconds (default: 10)")
        print()
        print("Examples:")
        print("  python 5_botnet_behavior.py 192.168.56.102")
        print("  python 5_botnet_behavior.py 192.168.56.102 --full-botnet --duration 300")
        print("  python 5_botnet_behavior.py 192.168.56.102 --exfil --duration 120")
        sys.exit(1)

    target_ip = sys.argv[1]
    port = 80
    duration = 120
    mode = "beacon"
    beacon_interval = 10

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--interval" and i + 1 < len(sys.argv):
            beacon_interval = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--beacon":
            mode = "beacon"
            i += 1
        elif sys.argv[i] == "--exfil":
            mode = "exfil"
            i += 1
        elif sys.argv[i] == "--keylog":
            mode = "keylog"
            i += 1
        elif sys.argv[i] == "--full-botnet":
            mode = "full"
            i += 1
        else:
            i += 1

    if mode == "full":
        full_botnet(target_ip, port, duration, beacon_interval)
    elif mode == "exfil":
        file_exfiltration(target_ip, port, duration)
    elif mode == "keylog":
        screenshot_keylog(target_ip, port, duration)
    else:
        c2_beacon(target_ip, port, duration, beacon_interval)
