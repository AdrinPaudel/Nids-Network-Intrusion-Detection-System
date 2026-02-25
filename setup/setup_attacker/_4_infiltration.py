"""
Infiltration Attack - Network reconnaissance and port scanning
Replicates CIC-IDS2018 Infiltration attack behavior:
  - Nmap-style TCP SYN scanning (rapid port probing)
  - Service banner grabbing (connect + read banner)
  - OS fingerprinting probes (unusual TCP flag combinations)

NOTE: Infiltration is ONLY used by the 6-class ("all") model variant.
      The default 5-class model removes Infiltration from training.

Key: Infiltration flows are characterized by:
  - Many short-lived connections to different ports
  - TCP SYN → RST patterns (half-open scanning)
  - Service enumeration probes with small payloads
  - Mix of TCP and UDP probes
"""

import socket
import threading
import time
import random
import struct

# ──────────────────────────────────────────────────────────
# Port lists (matching Nmap defaults)
# ──────────────────────────────────────────────────────────
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143,
    161, 389, 443, 445, 465, 514, 587, 636, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    3128, 3306, 3389, 5432, 5900, 5901, 6379, 8000, 8008,
    8080, 8443, 8888, 9090, 9200, 9300, 27017,
]

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 445, 500, 514, 1900, 5060, 5353]

# Service probe strings (Nmap-style)
SERVICE_PROBES = {
    21:   b"",                                     # FTP — read banner
    22:   b"",                                     # SSH — read banner
    23:   b"",                                     # Telnet — read banner
    25:   b"EHLO scan.test\r\n",                   # SMTP
    53:   b"\x00\x1e\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS version query
    80:   b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",  # HTTP
    110:  b"",                                     # POP3 — read banner
    143:  b"a001 CAPABILITY\r\n",                  # IMAP
    443:  b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03",  # TLS ClientHello start
    445:  b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc0",  # SMB negotiate
    3306: b"",                                     # MySQL — read banner
    3389: b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00Cookie: mstshash=nmap\r\n",  # RDP
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",   # PostgreSQL SSLRequest
    6379: b"PING\r\n",                             # Redis
    8080: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",  # HTTP alt
}


class InfiltrationAttack:
    def __init__(self, target_ip, duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = True
        self.scan_count = 0
        self.lock = threading.Lock()

    def _inc_count(self, n=1):
        with self.lock:
            self.scan_count += n

    # ──────────────────────────────────────────────────────
    # TCP Connect Scan (Nmap -sT)
    #   Full TCP handshake to detect open ports.
    #   CICFlowMeter sees short flows: SYN→SYN/ACK→ACK→RST
    #   with Dst Port varying across many values.
    # ──────────────────────────────────────────────────────
    def tcp_connect_scan(self):
        """TCP connect scan: probe many ports rapidly.
        Each probe is a separate flow with a different Dst Port.
        Open ports get a brief connection; closed ports get RST."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            # Scan common ports first, then random high ports
            ports = list(COMMON_TCP_PORTS) + random.sample(range(1024, 65535), 200)
            random.shuffle(ports)

            for port in ports:
                if not self.running or time.time() >= end_time:
                    return

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        # Port is open — read a bit of banner data
                        try:
                            sock.settimeout(0.5)
                            sock.recv(1024)
                        except Exception:
                            pass
                    sock.close()
                except Exception:
                    pass

                self._inc_count()
                # Very short delay — Nmap scans fast
                time.sleep(random.uniform(0.005, 0.02))

    # ──────────────────────────────────────────────────────
    # Service Banner Grabbing
    #   Connect to known ports, send service-specific probes,
    #   read responses. Creates flows with bidirectional data.
    # ──────────────────────────────────────────────────────
    def service_enumeration(self):
        """Service banner grab: probe known ports with protocol-specific queries.
        Each probe generates a flow with both forward (probe) and backward (banner)
        packets, creating distinctive bidirectional traffic patterns."""
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            ports_to_probe = list(SERVICE_PROBES.keys())
            random.shuffle(ports_to_probe)

            for port in ports_to_probe:
                if not self.running or time.time() >= end_time:
                    return

                probe_data = SERVICE_PROBES[port]

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.target_ip, port))

                    # For ports with no probe, just read the banner
                    if not probe_data:
                        try:
                            banner = sock.recv(1024)
                        except socket.timeout:
                            pass
                    else:
                        # Send probe and read response
                        sock.sendall(probe_data)
                        try:
                            response = sock.recv(4096)
                        except socket.timeout:
                            pass

                    # Send additional probes to create more flow data
                    for _ in range(random.randint(1, 3)):
                        try:
                            sock.sendall(b"HELP\r\n")
                            sock.recv(2048)
                        except Exception:
                            break

                    sock.close()
                except Exception:
                    pass

                self._inc_count()
                time.sleep(random.uniform(0.1, 0.5))

    # ──────────────────────────────────────────────────────
    # UDP Scan (Nmap -sU)
    #   Send UDP probes to common ports. Closed ports return
    #   ICMP unreachable, open ports may respond.
    # ──────────────────────────────────────────────────────
    def udp_scan(self):
        """UDP port scan: probe common UDP service ports.
        Each probe sends a service-appropriate payload."""
        end_time = time.time() + self.duration

        # DNS query for version.bind (common Nmap probe)
        dns_query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
        # SNMP get-request
        snmp_probe = b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
        # NTP version query
        ntp_probe = b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x00" * 32

        udp_probes = {
            53: dns_query,
            123: ntp_probe,
            161: snmp_probe,
            162: snmp_probe,
            500: b"\x00" * 28,  # IKE
            5060: b"OPTIONS sip:test@target SIP/2.0\r\nVia: SIP/2.0/UDP scan:5060\r\n\r\n".encode() if isinstance("", str) else b"",
            5353: dns_query,
        }

        while self.running and time.time() < end_time:
            for port in COMMON_UDP_PORTS:
                if not self.running or time.time() >= end_time:
                    return

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)

                    # Send appropriate probe for the port
                    probe = udp_probes.get(port, b"\x00" * 32)
                    sock.sendto(probe, (self.target_ip, port))

                    try:
                        response, _ = sock.recvfrom(1024)
                    except socket.timeout:
                        pass

                    sock.close()
                except Exception:
                    pass

                self._inc_count()
                time.sleep(random.uniform(0.05, 0.2))

    # ──────────────────────────────────────────────────────
    # Aggressive Scan (Nmap -A style)
    #   Combines connect + banner grab + multiple probes per port.
    #   Creates longer flows with more packets.
    # ──────────────────────────────────────────────────────
    def aggressive_scan(self):
        """Aggressive scan: deep probing of each open port.
        Sends multiple probe types per connection to fingerprint services."""
        end_time = time.time() + self.duration

        http_probes = [
            b"GET / HTTP/1.1\r\nHost: target\r\n\r\n",
            b"GET /robots.txt HTTP/1.1\r\nHost: target\r\n\r\n",
            b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
            b"OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n",
            b"GET /sitemap.xml HTTP/1.1\r\nHost: target\r\n\r\n",
        ]

        while self.running and time.time() < end_time:
            ports = list(COMMON_TCP_PORTS)
            random.shuffle(ports)

            for port in ports:
                if not self.running or time.time() >= end_time:
                    return

                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((self.target_ip, port))

                    if result == 0:
                        # Port is open — send multiple probes
                        if port in (80, 8080, 8443, 8888, 443):
                            # HTTP probes
                            for probe in random.sample(http_probes, min(3, len(http_probes))):
                                try:
                                    sock.sendall(probe)
                                    sock.recv(4096)
                                except Exception:
                                    break
                                time.sleep(0.1)
                        else:
                            # Generic probes
                            try:
                                sock.recv(1024)  # Read banner
                            except socket.timeout:
                                pass
                            for generic_probe in [b"HELP\r\n", b"INFO\r\n", b"QUIT\r\n"]:
                                try:
                                    sock.sendall(generic_probe)
                                    sock.recv(1024)
                                except Exception:
                                    break
                                time.sleep(0.1)

                    sock.close()
                except Exception:
                    pass

                self._inc_count()
                time.sleep(random.uniform(0.05, 0.3))

    def run_attack(self, num_threads=3):
        """Run infiltration attack with multiple threads."""
        print(f"[Infiltration] Starting on {self.target_ip} for {self.duration}s")
        print(f"[Infiltration] Techniques: TCP scan + Service enum + UDP scan + Aggressive scan")
        print(f"[Infiltration] Using {num_threads} threads")

        techniques = [
            self.tcp_connect_scan,
            self.service_enumeration,
            self.udp_scan,
            self.aggressive_scan,
        ]

        threads = []
        for i in range(num_threads):
            technique = techniques[i % len(techniques)]
            t = threading.Thread(target=technique, name=f"Infiltration-{technique.__name__}-{i}")
            t.daemon = True
            t.start()
            threads.append(t)

        start_time = time.time()
        for t in threads:
            remaining = max(1, self.duration - (time.time() - start_time) + 5)
            t.join(timeout=remaining)

        self.running = False
        elapsed = time.time() - start_time
        print(f"[Infiltration] Completed in {elapsed:.2f}s — Scanned {self.scan_count} ports/services")


def run_infiltration(target_ip, target_port=None, duration=60, threads=3):
    """Convenience function to run infiltration attack.
    target_port is accepted for API compatibility but not used
    (infiltration scans many ports by nature)."""
    attack = InfiltrationAttack(target_ip, duration)
    attack.run_attack(num_threads=threads)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        run_infiltration(target_ip, duration=duration)
    else:
        print("Usage: python _4_infiltration.py <target_ip> [duration]")
