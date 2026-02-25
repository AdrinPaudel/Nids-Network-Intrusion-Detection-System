# CICIDS2018 Network Intrusion Detection Dataset - Attack Generation Methodology

## Overview

The CICIDS2018 dataset is a benchmark network intrusion detection dataset created by the Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick. It contains 10 CSV files (~6 GB) with labeled network flow data representing benign and malicious traffic.

**Dataset Source:** University of New Brunswick / Canadian Institute for Cybersecurity (CIC)
- Official repository: https://www.unb.ca/cic/datasets/ids-2018.html
- Also available on Kaggle

**Key Characteristics:**
- **10 CSV files** with daily traffic captures (Monday through Friday across 2 weeks)
- **Total flows:** ~2.6 million network flows
- **Features:** 80+ network flow characteristics extracted by CICFlowMeter
- **Classes (5-class):** Benign, DoS, DDoS, Brute Force, Botnet
- **Classes (6-class):** Above + Infiltration
- **Time period:** February-March 2018
- **Network infrastructure:** Controlled laboratory environment with victim and attacker machines

---

## Attack Tools and Methods

### 1. DoS (Denial of Service) Attacks

**Attack Tools Used:** HULK, Slowloris, GoldenEye, SlowHTTPTest

#### 1.1 HULK (HTTP Unbearable Load King)

**Purpose:** Rapid HTTP GET flooding attack

**Technical Details:**
- **Connection model:** NEW TCP connection per request (critical for flow differentiation)
- **Request type:** HTTP/1.1 GET requests with randomized headers
- **Header randomization:**
  - Random User-Agent from browser pools
  - Random Referer URLs
  - Random Accept-* headers
  - Cache-Control headers (no-cache, no-store)
- **Keep-alive:** NOT used (each request = separate connection)
- **URL variation:** Random path strings with cache-busting query parameters
- **Timing:** Rapid-fire, minimal delay between connections

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~2.5 (mean), ~3 (median) packets per flow
- Fwd Seg Size Min: 32 bytes (TCP with timestamp options)
- Init Fwd Win Byts: 8192 bytes (SO_RCVBUF setting)
- Flow Duration: Short (milliseconds to ~100ms)
- Destination Port: 80 (primary), 8080, 8888, 3000, 5000, 443 (variations)

**Network Properties Generated:**
- High packet rate in short bursts
- Minimal packets per connection (rapid close/open)
- Randomized headers → inconsistent packet sizes
- No response reading / immediate disconnect pattern

---

#### 1.2 Slowloris

**Purpose:** Slow header transmission attack - holds connections open

**Technical Details:**
- **Connection model:** Keep many connections OPEN simultaneously (50-150 connections)
- **HTTP protocol:** Incomplete HTTP/1.1 requests sent line-by-line
- **Critical feature:** NEVER send the final `\r\n\r\n` (end of headers)
- **Keep-alive loop:**
  1. Open socket
  2. Send partial HTTP header (GET, Host, User-Agent, Accept-Language, Referer, etc.)
  3. NOT send final empty line
  4. Wait 10-15 seconds
  5. Send additional header line (X-a-{random}: {random})
  6. Repeat steps 4-5 until connection times out
  7. Reopen dropped connections to maintain pressure

**CICFlowMeter Signature:**
- Tot Fwd Pkts: Low (5-20 packets per flow)
- Flow Duration: VERY LONG (tens of seconds to minutes)
- Fwd IAT Mean: Very high (many seconds between packets)
- Fwd IAT Max: Very high
- Idle Mean/Min: High (connections waiting for server timeout)
- Destination Port: 80

**Network Properties Generated:**
- Long-lived connections with irregular packet timing
- Low overall packet count but extremely long duration
- Asymmetric traffic (more client inactivity than normal)
- Stream-based flow characteristics

---

#### 1.3 GoldenEye

**Purpose:** HTTP GET/POST flooding attack - hybrid of HULK and Slowloris

**Technical Details:**
- **Connection model:** NEW TCP connection per request
- **Request mix:** 60% GET, 40% POST
- **GET requests:**
  - Random URL paths with cache-busting parameters (2-10 query params)
  - Cache-Control headers (no-store, no-cache)
  - Pragma and other standard headers
- **POST requests:**
  - Variable body size (50-400 bytes) for randomization
  - Content-Type: application/x-www-form-urlencoded
  - Content-Length correctly set
- **Header pools:**
  - 8+ User-Agent strings
  - 8+ Referer URLs
  - Multiple Accept and Accept-Encoding combinations
  - Accept-Language variations
- **Port variation:** Randomized across [80, 8080, 8888, 3000, 5000, 443]

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~3.76 (mean), ~4 (median) packets per flow
- TotLen Fwd Pkts: ~359.6 bytes (mean), ~358 (median)
- Fwd Seg Size Min: 32 bytes
- Init Fwd Win Byts: 8192 bytes
- Flow Duration: ~11 seconds (mean), ~6.7 seconds (median)
- Destination Port: 80 (primary)

**Network Properties Generated:**
- Medium packet count per flow (3-4 packets)
- Moderate flow duration
- Randomized packet sizes (GET vs POST variation)
- Mixed protocol patterns (hybrid attack style)

---

#### 1.4 SlowHTTPTest

**Purpose:** Slow body transmission attack - sends POST headers then drips body slowly

**Technical Details:**
- **Connection model:** 50 persistent connections, body sent slowly
- **HTTP protocol:** Announce large Content-Length, then send body bytes very slowly
- **Initial payload:**
  ```
  POST /random_path HTTP/1.1
  Host: target
  User-Agent: [random]
  Content-Type: application/x-www-form-urlencoded
  Content-Length: [100000-500000]
  Connection: keep-alive
  
  (body transmitted at 1-10 bytes per interval)
  ```
- **Data drip rate:** 1-10 random bytes per 1-3 second interval
- **Connection reuse:** Keep-alive connections maintained across multiple requests
- **Connection refresh:** When sockets drop, reopen to maintain total connection count

**CICFlowMeter Signature:**
- Tot Fwd Pkts: Moderate (20-50+ packets per flow)
- Fwd IAT Mean: HIGH (1-3 seconds between packets)
- Fwd IAT Max: VERY HIGH
- Flow Duration: LONG (tens of seconds to minutes)
- TotLen Fwd Pkts: High (due to large Content-Length)
- Idle Mean: Moderate to high

**Network Properties Generated:**
- Very slow transmission rate
- Long idle periods between bursts
- Moderate packet count with very long flow duration
- Bandwidth-efficient attack (low throughput)

---

### 2. DDoS (Distributed Denial of Service) Attacks

**Attack Tools Used:** LOIC-HTTP, LOIC-UDP, HOIC

#### 2.1 LOIC-HTTP

**Purpose:** High-volume HTTP GET flooding (simulating multiple attackers)

**Technical Details:**
- **Intensity:** Multiple threads (10+) each sending requests
- **Request model:** 1-5 requests per keep-alive connection (reduced from 20-200 for realism)
- **HTTP method:** GET only
- **URL format:** `/{random_path}?{random_param}={random_value}`
- **Headers:**
  - User-Agent: Randomized
  - Accept: */*
  - Connection: keep-alive
  - Host: target
- **Port variation:** [80, 8080, 8888, 3000, 5000, 443]
- **Response handling:** Minimal (quick timeout on recv)
- **Thread delay:** Multiple threads creating concurrent load

**CICFlowMeter Signature:**
- Tot Fwd Pkts: VERY HIGH (hundreds to thousands)
- Flow Pkts/s: VERY HIGH (high packet rate)
- TotLen Fwd Pkts: Very high
- PSH flag count: Very high (data-carrying packets)
- Destination Port: 80 (primary)
- Init Fwd Win Byts: 8192

**Network Properties Generated:**
- Extreme packet volume in short timeframe
- Keep-alive connections with many requests
- Rapid handshakes followed by data flooding
- Multiple concurrent flows to same target

---

#### 2.2 LOIC-UDP

**Purpose:** High-volume UDP packet flooding to fixed port

**Technical Details:**
- **Protocol:** UDP (connectionless)
- **Destination port:** Fixed during attack run (53, 123, 161, 514, 1900, 5353, 19132, random variations)
- **Payload size:** Random (512, 1024, 1400 bytes)
- **Packet rate:** High (minimal delay between packets)
- **Flow grouping:** All packets to SAME port → Single CICFlowMeter flow with massive packet count
- **Port variation between flows:** Different flows target different UDP ports
- **Timing:** 0.3-0.5 second delays between UDP packets (creates realistic flow separation)

**CICFlowMeter Signature:**
- Tot Fwd Pkts: EXTREMELY HIGH (thousands)
- Fwd IAT Mean/Max: Very low (rapid-fire packets)
- TotLen Fwd Pkts: Extremely high
- Protocol: 17 (UDP)
- Destination Port: Varies per flow
- Flow duration: Variable (based on attack length)

**Network Properties Generated:**
- Stateless flooding (no connection establishment)
- Uniform packet sizes per flow
- Very high volume in short timeframes
- Minimal inter-packet delays

---

#### 2.3 HOIC (High Orbit ION Cannon)

**Purpose:** HTTP POST flooding with large body payloads - boosted LOIC variant

**Technical Details:**
- **HTTP method:** POST only
- **Connection model:** NEW TCP connection per 1-3 requests
- **Payload size:** 500-12,000 bytes per POST body (variable for diversity)
- **Request structure:**
  ```
  POST /random_path HTTP/1.1
  Host: target
  User-Agent: [random]
  Content-Type: application/x-www-form-urlencoded
  Content-Length: [body_length]
  Accept: */*
  Connection: close
  
  [1000-12000 bytes of random payload]
  ```
- **Port variation:** Multiple HTTP ports [80, 8080, 8888, 3000, 5000, 443]
- **Requests per connection:** 1-3 (then close and reopen)
- **Thread intensity:** 10+ threads for distributed effect

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~2.5 (mean), ~2.5 (median) packets per flow
- TotLen Fwd Pkts: ~149.4 bytes (mean), ~36.5 (median)
- Fwd Seg Size Min: 20 bytes (no TCP timestamps in HOIC)
- Init Fwd Win Byts: 49,136 bytes
- Flow Duration: Very short (~17ms)
- Destination Port: 80

**Network Properties Generated:**
- Short-lived connections with large payloads
- Many flows opening/closing rapidly
- High throughput in very short windows
- POST-specific traffic pattern

---

### 3. Brute Force Attacks

**Attack Tools Used:** Patator (SSH/FTP variants)

#### 3.1 SSH Brute Force

**Purpose:** Credential guessing attack on SSH service

**Technical Details:**
- **Protocol:** SSH (port 22)
- **Attack method:** Full SSH key exchange + authentication attempt per try
- **Credential wordlists:**
  - Usernames (25+): root, admin, user, ubuntu, test, guest, oracle, postgres, mysql, ftp, www, deploy, pi, ec2-user, etc.
  - Passwords (30+): password, 123456, admin, root, test, "", password123, 12345678, qwerty, letmein, etc.
- **Per-attempt process:**
  1. TCP connect (SYN → ACK)
  2. SSH version exchange (SSH-2.0 banner)
  3. SSH key exchange initiation (KEXINIT message)
  4. Authentication attempt (password auth)
  5. Disconnect (usually failed auth)
- **Implementation:** Paramiko library (Python SSH client) for full handshake
- **Timing:** 50-300ms delay between attempts for realism (not instant-fire)
- **Socket settings:** SO_RCVBUF = 8192 bytes (matching training data)

**CICFlowMeter Signature:**
- Dst Port: 22 (always SSH)
- Tot Fwd Pkts: 10-30 packets per flow (full handshake)
- Fwd Seg Size Min: 20-32 bytes (SSH protocol messages)
- Flow Duration: 2-5 seconds per attempt
- Many rapid successive flows (credential attempts)
- Init Fwd Win Byts: 8192

**Network Properties Generated:**
- Rapid sequential connections to port 22
- Each connection contains full SSH protocol exchange
- Failed authentication pattern (attempt → disconnect)
- Short-lived but highly structured flows

---

#### 3.2 FTP Brute Force

**Purpose:** Credential guessing attack on FTP service

**Technical Details:**
- **Protocol:** FTP (port 21)
- **Attack method:** Full FTP handshake + USER/PASS exchange
- **Credential wordlists:** Same as SSH (25+ usernames, 30+ passwords)
- **Per-attempt process:**
  1. TCP connect (port 21)
  2. Read FTP server banner ("220 Ready")
  3. Send USER command (USER {username}\r\n)
  4. Read response
  5. Send PASS command (PASS {password}\r\n)
  6. Read response (usually "530 Login invalid")
  7. Send QUIT to cleanly close connection
- **Timing:** 50-300ms delay between attempts
- **Socket settings:** SO_RCVBUF = 8192 bytes

**CICFlowMeter Signature:**
- Dst Port: 21 (always FTP)
- Tot Fwd Pkts: 6-12 packets per flow
- Fwd Seg Size Min: 20-32 bytes
- Flow Duration: 1-3 seconds per attempt
- Many rapid successive flows
- Init Fwd Win Byts: 8192

**Network Properties Generated:**
- Rapid connections to port 21
- Consistent FTP protocol patterns (banner, commands, responses)
- Failed authentication signature
- Bidirectional traffic (server responses)

---

### 4. Botnet Attacks

**Attack Tool Used:** Ares/Zeus C2 behavioral simulation

#### 4.1 C2 Beaconing

**Purpose:** Command & Control periodic callback simulation

**Technical Details:**
- **Protocol:** HTTP (port 80 or 8080)
- **Beacon type:** Simple HTTP GET to control server
- **Request format:**
  ```
  GET /api/check?id={bot_id}&seq={sequence}&t={timestamp} HTTP/1.1
  Host: target
  User-Agent: [Ares/Zeus-style agent]
  Cookie: session={bot_id}
  Accept: application/json
  Connection: close
  ```
- **Bot ID:** Unique 16-character identifier per session
- **Sequence:** Incrementing counter for each beacon
- **Timing:** Regular intervals with jitter (3-8 second intervals)
- **Connection model:** NEW connection per beacon (not keep-alive)
- **Ports:** 80 or 8080 (C2 controller)

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~2.56 (mean), ~2 (median) packets per flow
- TotLen Fwd Pkts: ~159.5 bytes (mean), ~0 (median edge case)
- Fwd Seg Size Min: 20 bytes
- Init Fwd Win Byts: 2,053 bytes (distinct from normal HTTP)
- Dst Port: 8080 (primary)
- Flow Duration: Very short (< 100ms typically)

**Network Properties Generated:**
- Periodic regular connections (timer-driven)
- Very small payloads and quick close
- Consistent timing intervals (detectable pattern)
- Unusual TCP window sizes compared to normal browsers

---

#### 4.2 Data Exfiltration

**Purpose:** Upload "stolen" data to C2 server

**Technical Details:**
- **Protocol:** HTTP POST (port 80 or 8080)
- **Data types simulated:** Credentials, keylogs, screenshots, clipboard, browser history, cookies, system info, files
- **Payload sizes:**
  - Credentials/cookies/history: 1-8 KB
  - Screenshots/files: 4-32 KB
  - Keylogs: 256-2048 bytes
- **Request format:**
  ```
  POST /api/upload HTTP/1.1
  Host: target
  User-Agent: [Ares/Zeus-style]
  Content-Type: application/json
  Content-Length: {body_length}
  Cookie: session={bot_id}
  Connection: close
  
  {"id":"{bot_id}","type":"{data_type}","data":"{base64_payload}","ts":{timestamp}}
  ```
- **Connection model:** NEW connection per upload
- **Timing:** 2-6 second intervals between uploads in burst pattern
- **Encoding:** Base64-encoded payload data

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~2 packets per flow (request + close)
- TotLen Fwd Pkts: High (due to payload size variation)
- Fwd Seg Size Min: 20-32 bytes
- Dst Port: 80 or 8080
- Flow Duration: Very short (< 100ms)
- BUT: Larger overall bytes indicates data exfil activity

**Network Properties Generated:**
- POST-specific traffic patterns
- Variable payload sizes (unlike regular browsing)
- JSON-formatted data exfil signature
- Rapid opening/closing connections

---

#### 4.3 Keylogging & Command Polling

**Purpose:** Send captured keylogs and poll for commands

**Technical Details:**
- **Keylog snippets simulated:**
  - Admin credential entries
  - Website logins
  - SSH commands
  - SQL queries
  - Windows admin commands
  - PowerShell commands
  - File access patterns
- **Request format (keylog POST):**
  ```
  POST /api/keylog HTTP/1.1
  Host: target
  User-Agent: [bot-agent]
  Content-Type: application/json
  Content-Length: {length}
  Connection: close
  
  {"id":"{bot_id}","keylog":"{keylog_data} [{timestamp}]"}
  ```
- **Command polling (GET):**
  ```
  GET /api/cmd?id={bot_id}&status=idle HTTP/1.1
  Host: target
  Connection: close
  ```
- **Connection model:** NEW connection per request
- **Cycle timing:** 1-4 second intervals

**CICFlowMeter Signature:**
- Tot Fwd Pkts: ~2 per flow (POST/GET + close)
- TotLen Fwd Pkts: Moderate (keylog message varies)
- Fwd Seg Size Min: 20 bytes
- Dst Port: 80/8080
- Flow Duration: Very short (< 100ms)
- Regular timing pattern

**Network Properties Generated:**
- Periodic polling pattern (command execution loop)
- POST + GET alternation
- Small but regular payloads
- Consistent C2 server interaction

---

### 5. Infiltration Attacks

**Attack Tool Used:** Nmap-style reconnaissance

#### 5.1 TCP Connect Scan (-sT)

**Purpose:** Full TCP connection scan for open port detection

**Technical Details:**
- **Scanning method:** Complete TCP three-way handshake to each port
- **Port list:** 
  - Common TCP ports (22, 80, 443, 3306, 3389, 5432, 8080, etc.) 
  - Random ports from 1024-65535 range (200+ variations)
- **Per-port process:**
  1. TCP SYN
  2. Wait for SYN-ACK
  3. Send ACK (connection established)
  4. Close connection (FIN or RST)
- **Open port handling:** Brief read attempt (socket.recv), then close
- **Timing:** 5-20ms delay between port probes (rapid but not detectable as flood)
- **Socket timeout:** 500ms per port

**CICFlowMeter Signature:**
- Dst Port: VARIES widely (each probe to different port)
- Tot Fwd Pkts: 3-4 packets per flow (SYN, ACK, data, FIN/RST)
- Flow Duration: Very short (50-500ms)
- Many successive flows to same source but different destination ports
- Init Fwd Win Byts: 8192 (varies with system)

**Network Properties Generated:**
- Systematic port enumeration pattern
- Short-lived connections to many different ports
- No application-layer data
- Rapid sequential flows with increasing port numbers

---

#### 5.2 Service Banner Grabbing

**Purpose:** Identify services by protocol-specific probes and response analysis

**Technical Details:**
- **Known port probes:** Service-specific protocols
  ```
  FTP(21): Read banner only
  SSH(22): Read banner only
  HTTP(80): GET / HTTP/1.0\r\nHost: target\r\n\r\n
  SMTP(25): EHLO scan.test\r\n
  DNS(53): DNS version query payload
  IMAP(143): a001 CAPABILITY\r\n
  MySQL(3306): Read banner only
  PostgreSQL(5432): SSLRequest packet
  Redis(6379): PING\r\n
  TLS(443): TLS ClientHello start
  SMB(445): SMB negotiate request
  RDP(3389): RDP connection initiation
  ```
- **Per-port process:**
  1. TCP connect
  2. Read server banner (if applicable)
  3. Send service-specific probe (or skip if banner-only)
  4. Read response (up to 4KB)
  5. Send additional probes (1-3 more) to enumerate capabilities
  6. Close connection
- **Response handling:** Capture and parse service signatures
- **Timing:** 100-500ms per service probe

**CICFlowMeter Signature:**
- Tot Fwd Pkts: 4-10 packets per flow (probes + responses)
- TotLen Fwd Pkts: Moderate (probe payloads + responses)
- Fwd Seg Size Min: 20-32 bytes (varies by protocol)
- Flow Duration: 1-3 seconds
- Bidirectional traffic (forward + backward packets)
- Dst Port: Fixed per probe (22, 25, 443, etc.)

**Network Properties Generated:**
- Bidirectional protocol exchange
- Service signature patterns
- Multiple probes per connection
- Protocol-specific behaviors (banner exchange, authentication handshakes)

---

#### 5.3 UDP Scan (-sU)

**Purpose:** Probe UDP services for open/closed determination

**Technical Details:**
- **Protocol:** UDP (connectionless)
- **Port list:** 53, 67, 68, 69, 123, 161, 162, 445, 500, 514, 1900, 5060, 5353
- **Service-specific probes:**
  - DNS (53): DNS version.bind query
  - NTP (123): NTP version query
  - SNMP (161/162): SNMP GET-REQUEST
  - IKE (500): IKE SA Initiator
  - RTP/SIP (5060): SIP OPTIONS message
  - mDNS (5353): DNS query
- **Per-port process:**
  1. Send UDP packet to port
  2. Wait for response (1 second timeout)
  3. Parse response (ICMP unreachable vs service response)
  4. Move to next port
- **Payload size:** Protocol-specific (28-100+ bytes)

**CICFlowMeter Signature:**
- Protocol: 17 (UDP)
- Tot Fwd Pkts: 1-2 per flow (no handshake)
- Dst Port: Varies (26 common UDP ports)
- TotLen Fwd Pkts: Protocol-specific payload size
- Flow Duration: Very short (probe only, no response = milliseconds)

**Network Properties Generated:**
- Stateless probing
- No connection establishment
- Service-specific probe signatures
- Rapid enumeration of UDP services

---

#### 5.4 Aggressive Scan (Nmap -A style)

**Purpose:** Deep service fingerprinting with multiple protocol probes

**Technical Details:**
- **Scan targets:** Common TCP ports [21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, etc.]
- **For HTTP ports (80, 8080, 8443, 8888, 443):**
  ```
  Multiple GET requests:
  - GET / HTTP/1.1\r\nHost: target\r\n\r\n
  - GET /robots.txt HTTP/1.1\r\nHost: target\r\n\r\n
  - HEAD / HTTP/1.1\r\nHost: target\r\n\r\n
  - OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n
  - GET /sitemap.xml HTTP/1.1\r\nHost: target\r\n\r\n
  ```
- **For SSH ports (22):** Banner grab + version detection
- **For SMTP ports (25):** EHLO + MAIL FROM + additional commands
- **Other services:** Port-specific multi-probe sequences
- **Connection model:** Keep-alive with multiple requests per connection
- **Timing:** 3 second timeout per connection, multiple probes per service

**CICFlowMeter Signature:**
- Tot Fwd Pkts: 10-20+ packets per flow (multiple requests)
- TotLen Fwd Pkts: High (multiple HTTP requests + responses)
- Fwd IAT Mean: Moderate (time between probes)
- Flow Duration: 2-5 seconds
- Bidirectional traffic pattern (requests + responses)

**Network Properties Generated:**
- Complex multi-probe HTTP patterns
- Service version/capability enumeration
- Deep traffic analysis signatures
- Detective bot behavior

---

## Attack Duration & Network Infrastructure

### Typical Attack Scenarios

**Default Duration:** 120 seconds per attack rotation
**Total capture window:** ~2 hours (multiple attack runs per day)

**Attack sequence:**
1. Attacks can run individually or in combination
2. Default mode: DoS, DDoS, Brute Force, Botnet (shuffled)
3. All mode: Above + Infiltration
4. Each attack allocated equal time from total duration

**Network topology:**
- **Victim machine:** Windows Server 2016 or Ubuntu system
  - Running Apache/Nginx (HTTP - port 80)
  - Running SSH (port 22)
  - Running FTP (port 21)
  - CICFlowMeter installed for flow capture
  
- **Attacker machine:** Linux (Kali preferred)
  - Python-based attack tools
  - Paramiko (SSH attacks)
  - Raw sockets (flooding)
  - Scapy/raw socket libraries (packet crafting)

- **Network capture:** CICFlowMeter (Java tool)
  - Extracts 80+ features from flows
  - Flows defined by: {Source IP, Source Port, Destination IP, Destination Port, Protocol}
  - 5-tuple flow grouping with timeout cleanup

---

## CICFlowMeter Feature Extraction

### Flow Definition
- **Bidirectional flow:** Packets with same 5-tuple (src IP, src port, dst IP, dst port, protocol)
- **Flow timeout:** 120 seconds of inactivity
- **Timeout cleanup:** Flows with no activity for 120+ seconds are written to CSV

### Key Features Used in Training

**Packet Count Metrics:**
- Tot Fwd Pkts: Total forward packets
- Tot Bwd Pkts: Total backward packets
- Tot Pkts: Total packets (forward + backward)

**Byte Volume Metrics:**
- TotLen Fwd Pkts: Total bytes in forward direction
- TotLen Bwd Pkts: Total bytes in backward direction

**Timing Metrics:**
- Flow Duration: Time from first to last packet (microseconds)
- Fwd IAT Mean: Mean inter-arrival time of forward packets
- Fwd IAT Max: Maximum inter-arrival time (forward)
- Idle Mean: Mean idle time during flow
- Idle Min: Minimum idle time

**TCP Window Features:**
- Init Fwd Win Byts: Initial TCP window size (forward)
- Init Bwd Win Byts: Initial TCP window size (backward)

**Packet Size Metrics:**
- Fwd Seg Size Min: Minimum forward packet size
- Fwd Seg Size Max: Maximum forward packet size
- Fwd Seg Size Avg: Average forward packet size

**Protocol Metrics:**
- Protocol: Protocol type (6=TCP, 17=UDP)
- Dst Port: Destination port number

**TCP Flag Metrics:**
- PSH (Push) flag count
- ACK (Acknowledgment) flag count
- FIN (Finish) flag count
- SYN (Synchronize) flag count
- RST (Reset) flag count
- URG (Urgent) flag count

---

## Published Literature

### Official CIC Dataset Papers

1. **"Toward Generalized Models for Network Intrusion Detection"**
   - Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A.
   - Proceedings of the 3rd International Conference on Information Systems Security and Privacy (ICISSP), 2017
   - Dataset creation and evaluation methodology

2. **"CICIDS2018: An Intrusion Detection Dataset and Evaluation of Intrusion Detection Methods"**
   - Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A.
   - Proceedings of Cyber Science and Technology Congress (RCSC'18)
   - Comprehensive dataset description and benchmark results

3. **"Detecting Encrypted VPNs to Block Pornographic Content"**
   - Related work on flow classification, informing dataset generation

### Data Repository Links

- **Official UNB CIC website:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Kaggle mirror:** https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
- **GitHub implementations:** Various PyPI packages (cicflowmeter)

---

## Key Methodological Notes

### Critical Implementation Details

1. **Linux generation requirement:** Dataset generated on Linux (Kali) - TCP timestamps differ from Windows, affecting flow signatures

2. **CICFlowMeter specifics:**
   - Java-based tool for flow extraction
   - Specific timeout and feature calculation algorithms
   - Python wrapper library: `cicflowmeter` (PyPI)

3. **Randomization:** Attack parameters randomized within bounds to create diverse traffic patterns
   - User-Agent pool rotation
   - URL path randomization
   - Port variation
   - Timing jitter

4. **Flow grouping:** CICFlowMeter groups packets by 5-tuple (not connections) - relevant for multi-packet request sequences

5. **Realism constraints:**
   - Attack intensity tuned to generate measurable traffic without overwhelming capture tools
   - Delays between packets to simulate realistic network conditions
   - Large wordlists to avoid immediate repetition detection

---

## Summary Table: Attack Characteristics

| Attack Type | Tool | Protocol | Port(s) | Flows/Sec | Pkts/Flow | Duration | Key Feature |
|---|---|---|---|---|---|---|---|
| HULK | - | TCP HTTP | 80+ | 3-5 | 2-3 | <1s | Rapid new connections |
| Slowloris | - | TCP HTTP | 80 | 0.1-0.5 | 5-20 | 60-300s | Long idle connections |
| GoldenEye | - | TCP HTTP | 80+ | 2-4 | 3-4 | 5-15s | Mixed GET/POST |
| SlowHTTPTest | - | TCP HTTP | 80 | 0.5-2 | 20-50 | 30-120s | Slow body drip |
| LOIC-HTTP | - | TCP HTTP | 80+ | 5-10 | 50+ | 10-60s | High volume keep-alive |
| LOIC-UDP | - | UDP | 53+ | 2-3 | 100+ | 10-60s | Stateless flooding |
| HOIC | - | TCP HTTP | 80+ | 1-3 | 2-3 | 10-60s | Large POST bodies |
| SSH Brute | Patator | TCP | 22 | 3-10 | 10-30 | 10-60s | Failed auth pattern |
| FTP Brute | Patator | TCP | 21 | 2-5 | 6-12 | 10-60s | FTP protocol sequence |
| C2 Beacon | Ares | TCP HTTP | 80/8080 | 0.2-0.5 | 2 | 60-300s | Regular intervals |
| Exfiltration | Ares | TCP HTTP | 80/8080 | 0.2-0.5 | 2 | 60-300s | Large POST payloads |
| Keylog+Cmd | Ares | TCP HTTP | 80/8080 | 1-3 | 2 | 60-300s | Periodic polling |
| TCP Scan | Nmap | TCP | 1-65535 | 10-50 | 3-4 | <1s | Sequential port sweep |
| Banner Grab | Nmap | TCP | 22/25/53 | 2-5 | 4-10 | 1-5s | Service enumeration |
| UDP Scan | Nmap | UDP | 53+ | 5-10 | 1-2 | <1s | Service probes |

---

## Replication Considerations for Dataset Generation

When replicating this dataset methodology:

1. **Use Linux as the attack source** - Dataset trained on Linux traffic profiles
2. **Maintain SO_RCVBUF=8192** - Controls TCP window sizes matching training
3. **Randomize parameters** - Avoid deterministic patterns that differ from training
4. **Use exact attack timing** - Keep delays and intervals within documented ranges
5. **Deploy CICFlowMeter** - Use identical flow extraction tool for consistency
6. **Preserve 5-tuple grouping** - Ensure flow definition matches original
7. **Monitor timeout handling** - Set 120-second flow idle timeout
8. **Validate flow duration** - Flows should match expected duration ranges

This dataset has become a standard benchmark for network intrusion detection research due to its comprehensive attack coverage and publicly available implementation details.
