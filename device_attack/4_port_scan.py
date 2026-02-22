#!/usr/bin/env python
"""
Port Scan / Infiltration - Nmap-style (CICIDS2018 methodology)
Simulates network reconnaissance used in the infiltration phase.

CICIDS2018 infiltration used Nmap for:
  - IP sweep (host discovery)
  - Full port scan (all 65535 ports)
  - Service version detection (-sV)
  - OS fingerprinting (-O)
  Dates: Feb 28, Mar 1

The key difference from simple SYN scans: service probes create
bidirectional flows with payloads (banner grabbing, version detection).

Should be detected as 'Infilteration' (6-class model) by your NIDS.
"""

import sys
import time
import socket
import struct
import random
import threading

# ======================================================================
# Service Probes (like Nmap's nmap-service-probes)
# ======================================================================
SERVICE_PROBES = {
    21: {
        "name": "FTP",
        "probe": None,  # FTP sends banner first
        "follow_up": [b"USER anonymous\r\n", b"PASS test@test.com\r\n", b"SYST\r\n", b"QUIT\r\n"],
    },
    22: {
        "name": "SSH",
        "probe": b"SSH-2.0-OpenSSH_8.0p1\r\n",
        "follow_up": [],
    },
    25: {
        "name": "SMTP",
        "probe": None,  # SMTP sends banner first
        "follow_up": [b"EHLO scanner.local\r\n", b"QUIT\r\n"],
    },
    53: {
        "name": "DNS",
        # DNS version query
        "probe": b"\x00\x1e\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        "follow_up": [],
    },
    80: {
        "name": "HTTP",
        "probe": b"GET / HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
        "follow_up": [
            b"GET /robots.txt HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"GET /favicon.ico HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"OPTIONS / HTTP/1.1\r\nHost: TARGET\r\n\r\n",
            b"HEAD / HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        ],
    },
    443: {
        "name": "HTTPS",
        # TLS Client Hello (simplified)
        "probe": b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03" + bytes(random.getrandbits(8) for _ in range(32)),
        "follow_up": [],
    },
    3306: {
        "name": "MySQL",
        "probe": None,  # MySQL sends greeting first
        "follow_up": [],
    },
    5432: {
        "name": "PostgreSQL",
        # PostgreSQL startup message
        "probe": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        "follow_up": [],
    },
    8080: {
        "name": "HTTP-Alt",
        "probe": b"GET / HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "follow_up": [],
    },
    8443: {
        "name": "HTTPS-Alt",
        "probe": b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03" + bytes(random.getrandbits(8) for _ in range(32)),
        "follow_up": [],
    },
}

# Common ports to scan (Nmap top 1000 style)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1723, 3306, 3389, 5432, 5900, 5901, 8000, 8080, 8443, 8888,
    9090, 27017, 6379, 11211, 1433, 1521, 2049, 2181, 4443, 5000,
    5001, 5601, 6443, 7001, 8001, 8081, 8181, 8888, 9000, 9200, 9300,
]


# ======================================================================
# TCP Connect Scan with Banner Grab
# ======================================================================
def tcp_connect_scan(target_ip, ports, duration=120, threads=10):
    """
    Nmap-style TCP connect scan with service version detection.
    Creates full TCP connections and grabs service banners.
    Generates bidirectional flows that CICFlowMeter can analyze.
    """
    print(f"\n{'='*60}")
    print(f"Port Scan - TCP Connect with Service Detection")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Ports: {len(ports)} ports")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting TCP connect scan... (Generates bidirectional flows)")
    print(f"{'='*60}\n")

    counters = {"scanned": 0, "open": 0, "closed": 0, "filtered": 0}
    open_ports = []
    lock = threading.Lock()
    stop_event = threading.Event()

    def scan_port(port):
        """Scan a single port - TCP connect + banner grab"""
        if stop_event.is_set():
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((target_ip, port))

            if result == 0:
                # Port is open - try to grab banner
                banner = ""
                service_name = "unknown"

                try:
                    # Check if service sends banner first (FTP, SSH, SMTP, MySQL)
                    if port in SERVICE_PROBES and SERVICE_PROBES[port]["probe"] is None:
                        data = s.recv(1024)
                        if data:
                            banner = data.decode(errors='ignore').strip()[:80]
                    # Send probe
                    elif port in SERVICE_PROBES:
                        probe = SERVICE_PROBES[port]["probe"]
                        if b"TARGET" in probe:
                            probe = probe.replace(b"TARGET", target_ip.encode())
                        s.sendall(probe)
                        data = s.recv(4096)
                        if data:
                            banner = data.decode(errors='ignore').strip()[:80]
                    else:
                        # Generic probe for unknown ports
                        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        data = s.recv(1024)
                        if data:
                            banner = data.decode(errors='ignore').strip()[:80]

                    if port in SERVICE_PROBES:
                        service_name = SERVICE_PROBES[port]["name"]

                    # Send follow-up probes for more version info
                    if port in SERVICE_PROBES:
                        for follow_up in SERVICE_PROBES[port]["follow_up"]:
                            if stop_event.is_set():
                                break
                            try:
                                probe = follow_up
                                if b"TARGET" in probe:
                                    probe = probe.replace(b"TARGET", target_ip.encode())
                                s.sendall(probe)
                                s.recv(4096)
                            except:
                                break

                except (socket.timeout, socket.error):
                    pass

                with lock:
                    counters["open"] += 1
                    open_ports.append((port, service_name, banner))
                    print(f"  [OPEN] {port}/tcp  {service_name:12s}  {banner[:50]}")

            else:
                with lock:
                    counters["closed"] += 1

            s.close()

        except socket.timeout:
            with lock:
                counters["filtered"] += 1
        except Exception:
            with lock:
                counters["closed"] += 1
        finally:
            with lock:
                counters["scanned"] += 1

    start_time = time.time()

    # Phase 1: Scan specified ports
    print("[*] Phase 1: Port scanning...")
    port_index = 0
    while port_index < len(ports) and not stop_event.is_set():
        if time.time() - start_time > duration:
            break

        # Launch batch of threads
        batch = []
        for _ in range(threads):
            if port_index >= len(ports):
                break
            t = threading.Thread(target=scan_port, args=(ports[port_index],), daemon=True)
            t.start()
            batch.append(t)
            port_index += 1

        for t in batch:
            t.join(timeout=5)

    # Phase 2: If time remains, do intensive probing on open ports
    remaining = duration - (time.time() - start_time)
    if remaining > 10 and open_ports:
        print(f"\n[*] Phase 2: Intensive service probing on {len(open_ports)} open ports ({remaining:.0f}s remaining)")
        probe_start = time.time()
        while time.time() - probe_start < remaining and not stop_event.is_set():
            for port, svc, _ in open_ports:
                if time.time() - probe_start > remaining:
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((target_ip, port))
                    # Send various probes to generate traffic
                    probes = [
                        b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                        b"OPTIONS / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                        b"HEAD / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n",
                        b"\r\n",
                        b"HELP\r\n",
                    ]
                    for probe in probes:
                        try:
                            s.sendall(probe)
                            s.recv(4096)
                        except:
                            break
                    s.close()
                except:
                    pass
                time.sleep(0.1)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[+] Port Scan complete!")
    print(f"    Ports scanned: {counters['scanned']}")
    print(f"    Open: {counters['open']} | Closed: {counters['closed']} | Filtered: {counters['filtered']}")
    print(f"    Time elapsed: {elapsed:.1f}s")
    if open_ports:
        print(f"\n    Open ports found:")
        for port, svc, banner in sorted(open_ports):
            print(f"      {port}/tcp  {svc:12s}  {banner[:50]}")
    print(f"{'='*60}\n")


# ======================================================================
# Full Port Scan (all 65535 ports)
# ======================================================================
def full_port_scan(target_ip, duration=120, threads=50):
    """
    Nmap-style full port scan (all TCP ports).
    Scans all 65535 ports to discover every open service.
    """
    print(f"\n{'='*60}")
    print(f"Port Scan - Full TCP Scan (all 65535 ports)")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Duration: {duration} seconds (may not complete all ports)")
    print(f"Threads: {threads}")
    print(f"\n[!] Starting full port scan...")
    print(f"{'='*60}\n")

    counters = {"scanned": 0, "open": 0}
    open_ports = []
    lock = threading.Lock()
    stop_event = threading.Event()
    start_time = time.time()

    def scan_port(port):
        if stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                # Try to grab banner
                banner = ""
                try:
                    if port in [21, 22, 25, 110, 143, 3306]:
                        data = s.recv(1024)
                        banner = data.decode(errors='ignore').strip()[:60]
                    else:
                        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        data = s.recv(1024)
                        banner = data.decode(errors='ignore').strip()[:60]
                except:
                    pass
                with lock:
                    counters["open"] += 1
                    open_ports.append((port, banner))
                    print(f"  [OPEN] {port}/tcp  {banner[:50]}")
            s.close()
        except:
            pass
        finally:
            with lock:
                counters["scanned"] += 1

    # Scan in random order to look more like real Nmap
    all_ports = list(range(1, 65536))
    random.shuffle(all_ports)

    port_idx = 0
    last_report = time.time()

    while port_idx < len(all_ports) and not stop_event.is_set():
        if time.time() - start_time > duration:
            break

        batch = []
        for _ in range(threads):
            if port_idx >= len(all_ports):
                break
            t = threading.Thread(target=scan_port, args=(all_ports[port_idx],), daemon=True)
            t.start()
            batch.append(t)
            port_idx += 1

        for t in batch:
            t.join(timeout=3)

        if time.time() - last_report > 10:
            elapsed = time.time() - start_time
            with lock:
                scanned = counters["scanned"]
                found = counters["open"]
            pct = (scanned / 65535) * 100
            print(f"[+] Progress: {scanned}/65535 ({pct:.1f}%) | {found} open | {elapsed:.0f}s / {duration}s")
            last_report = time.time()

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[+] Full Port Scan complete!")
    print(f"    Ports scanned: {counters['scanned']}/65535")
    print(f"    Open ports: {counters['open']}")
    print(f"    Time elapsed: {elapsed:.1f}s")
    if open_ports:
        print(f"\n    Open ports:")
        for port, banner in sorted(open_ports):
            print(f"      {port}/tcp  {banner[:50]}")
    print(f"{'='*60}\n")


# ======================================================================
# Aggressive Scan (Nmap -A equivalent)
# ======================================================================
def aggressive_scan(target_ip, duration=120, threads=10):
    """
    Nmap -A equivalent: OS detection + version detection + script scanning.
    Combines port scan with deep service probing.
    """
    print(f"\n{'='*60}")
    print(f"Port Scan - Aggressive (Nmap -A style)")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Duration: {duration} seconds")
    print(f"\n[!] Starting aggressive scan...")
    print(f"{'='*60}\n")

    # Phase 1: Quick scan of common ports (40% of time)
    phase1_time = int(duration * 0.4)
    tcp_connect_scan(target_ip, COMMON_PORTS, phase1_time, threads)

    # Phase 2: Full scan with remaining time (60% of time)
    phase2_time = max(duration - phase1_time - 5, 20)
    print(f"\n[*] Phase 2: Extended scan ({phase2_time}s remaining)")
    full_port_scan(target_ip, phase2_time, threads * 3)


# ======================================================================
# Main
# ======================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python 4_port_scan.py <TARGET_IP> [OPTIONS]")
        print()
        print("Modes (matching CICIDS2018 infiltration tools):")
        print("  --common        Scan common ports with service detection (default)")
        print("  --full          Full port scan (all 65535 ports)")
        print("  --aggressive    Aggressive scan (Nmap -A style)")
        print()
        print("Options:")
        print("  --duration <SEC>    Duration in seconds (default: 120)")
        print("  --threads <N>       Worker threads (default: 10)")
        print("  --ports <P1,P2,...> Custom port list (comma-separated)")
        print()
        print("Examples:")
        print("  python 4_port_scan.py 192.168.56.102")
        print("  python 4_port_scan.py 192.168.56.102 --full --duration 300")
        print("  python 4_port_scan.py 192.168.56.102 --aggressive --duration 120")
        print("  python 4_port_scan.py 192.168.56.102 --ports 80,443,8080,22")
        sys.exit(1)

    target_ip = sys.argv[1]
    duration = 120
    mode = "common"
    threads = 10
    custom_ports = None

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--duration" and i + 1 < len(sys.argv):
            duration = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--ports" and i + 1 < len(sys.argv):
            custom_ports = [int(p) for p in sys.argv[i + 1].split(",")]
            i += 2
        elif sys.argv[i] == "--common":
            mode = "common"
            i += 1
        elif sys.argv[i] == "--full":
            mode = "full"
            i += 1
        elif sys.argv[i] == "--aggressive":
            mode = "aggressive"
            i += 1
        else:
            i += 1

    if custom_ports:
        tcp_connect_scan(target_ip, custom_ports, duration, threads)
    elif mode == "full":
        full_port_scan(target_ip, duration, threads * 5)
    elif mode == "aggressive":
        aggressive_scan(target_ip, duration, threads)
    else:
        tcp_connect_scan(target_ip, COMMON_PORTS, duration, threads)
