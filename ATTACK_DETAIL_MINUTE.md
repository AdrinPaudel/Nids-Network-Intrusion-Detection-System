# CSE-CIC-IDS2018 — ATTACK GENERATION: EVERY MINUTE DETAIL

## Table of Contents

1. [Project Overview & Collaboration](#1-project-overview--collaboration)
2. [Network Infrastructure & Topology](#2-network-infrastructure--topology)
3. [Profiling Methodology (B-Profiles & M-Profiles)](#3-profiling-methodology-b-profiles--m-profiles)
4. [Attack Scenario 1: Brute-Force Attacks](#4-attack-scenario-1-brute-force-attacks)
5. [Attack Scenario 2: Heartbleed (OpenSSL Vulnerability)](#5-attack-scenario-2-heartbleed-openssl-vulnerability)
6. [Attack Scenario 3: Botnet (Zeus & Ares)](#6-attack-scenario-3-botnet-zeus--ares)
7. [Attack Scenario 4: DoS (Denial-of-Service)](#7-attack-scenario-4-dos-denial-of-service)
8. [Attack Scenario 5: DDoS (Distributed Denial-of-Service)](#8-attack-scenario-5-ddos-distributed-denial-of-service)
9. [Attack Scenario 6: Web Attacks (XSS, SQL Injection, Brute-Force)](#9-attack-scenario-6-web-attacks-xss-sql-injection-brute-force)
10. [Attack Scenario 7: Infiltration of the Network from Inside](#10-attack-scenario-7-infiltration-of-the-network-from-inside)
11. [Day-by-Day Attack Execution Schedule](#11-day-by-day-attack-execution-schedule)
12. [Exact Attacker & Victim IPs (Per Attack)](#12-exact-attacker--victim-ips-per-attack)
13. [Feature Extraction (CICFlowMeter-V3)](#13-feature-extraction-cicflowmeter-v3)
14. [Labeling Methodology](#14-labeling-methodology)
15. [Dataset File Structure & Organization](#15-dataset-file-structure--organization)
16. [Full List of 80+ Extracted Features](#16-full-list-of-80-extracted-features)
17. [Known Issues, Limitations & Biases](#17-known-issues-limitations--biases)

---

## 1. Project Overview & Collaboration

### Who Created It
- **Communications Security Establishment (CSE)**: Canada's national signals intelligence agency, responsible for foreign signals intelligence and cybersecurity. CSE is part of the Canadian government's defense architecture.
- **Canadian Institute for Cybersecurity (CIC)**: Part of the **University of New Brunswick (UNB)**, Fredericton, Canada. CIC is led by Dr. Ali A. Ghorbani and is the primary academic research arm behind the dataset.

### Key Researchers
- **Iman Sharafaldin** — Lead researcher, PhD candidate at CIC/UNB
- **Arash Habibi Lashkari** — Research associate at CIC/UNB, creator of CICFlowMeter
- **Ali A. Ghorbani** — Director of CIC, Professor at UNB

### Reference Paper
> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

### Why It Was Created
- Previous datasets (KDD'99, NSL-KDD, DARPA) were outdated, heavily anonymized, or did not reflect modern traffic compositions and attack patterns.
- The community needed **dynamically generated, modifiable, extensible, and reproducible** datasets.
- Existing datasets lacked recently discovered attack types (e.g., Heartbleed was discovered in 2014).
- Privacy issues prevented sharing of internal real network datasets.
- A **systematic, profile-based** approach was needed to generate standardized, repeatable datasets.

### Core Design Philosophy
The dataset uses the concept of **profiles** to generate cybersecurity data in a systematic manner:
- **B-Profiles** (Benign Profiles): Abstract behavioral models of legitimate users
- **M-Profiles** (Malicious Profiles): Abstract descriptions of attack scenarios

---

## 2. Network Infrastructure & Topology

### Platform
- The **entire infrastructure was hosted on Amazon Web Services (AWS)**.
- All machines were AWS EC2 instances running in the `us-east-2` (Ohio) region.
- The network was a **common LAN topology** on the AWS computing platform.

### Victim Organization
- **Total victim machines: 420 PCs + 30 servers = 450 machines**
- Organized into **5 departments** plus a server room:

| Department | Name | OS Configuration |
|---|---|---|
| Dep1 | R&D Department | Mix of Windows 8.1 and Windows 10 |
| Dep2 | Management Department | Mix of Windows 8.1 and Windows 10 |
| Dep3 | Technician Department | Mix of Windows 8.1 and Windows 10 |
| Dep4 | Secretary & Operations Department | Mix of Windows 8.1 and Windows 10 |
| Dep5 | IT Department | **Ubuntu Linux** (all machines) |
| Server Room | Server Room | Windows Server 2012 and Windows Server 2016 |

### Subnet Architecture
- 5 subnets for the 5 departments, all interconnected in a LAN
- Separate server room subnet
- The internal network IP range used `172.31.69.x` for victim machines
- Each victim machine also had a valid (public) IP like `18.217.x.x`, `18.218.x.x`, `18.219.x.x`, `18.221.x.x`, `18.222.x.x`, etc.

### Attacking Infrastructure
- **50 attacking machines** total
- All attacker machines ran **Kali Linux** (the leading penetration testing Linux distribution)
- Attacker machines were **outside** the target network
- Internal IP range for attackers: `172.31.70.x`
- Public IPs for attackers included: `18.221.219.4`, `13.58.98.64`, `18.219.211.138`, `18.217.165.70`, `13.59.126.31`, `18.219.193.20`, `18.218.115.60`, `18.219.9.1`, `18.219.32.43`, `18.218.55.126`, `52.14.136.135`, `18.219.5.43`, `18.216.200.189`, `18.218.229.235`, `18.218.11.51`, `18.216.24.42`, `13.58.225.34`

### OS Diversity Rationale
- Different Windows service packs were chosen deliberately because **each pack has a diverse set of known vulnerabilities**
- For Linux machines, **Metasploitable** distribution was used (a distribution intentionally developed to be exploitable by penetration testers)
- This diversity mimics real-world corporate networks where patches are applied inconsistently

---

## 3. Profiling Methodology (B-Profiles & M-Profiles)

### B-Profiles (Benign Traffic Generation)

**Purpose**: Generate realistic legitimate background traffic that mimics real human user behavior.

**Approach**: 
- Machine learning and statistical analysis techniques are used to extract abstract behavioral patterns of real users
- Techniques include: **K-Means clustering, Random Forest, SVM (Support Vector Machine), and J48 decision tree**
- The encapsulated features include:
  - **Distribution of packet sizes** per protocol
  - **Number of packets per flow**
  - **Certain patterns in the payload data**
  - **Size of payload** distributions
  - **Request time distribution** per protocol (when users typically make requests)

**Protocols simulated**:
| Protocol | Port | Description |
|---|---|---|
| HTTP | 80 | Unencrypted web traffic |
| HTTPS | 443 | Encrypted web traffic (majority of all traffic) |
| SMTP | 25/587 | Email sending |
| POP3 | 110/995 | Email retrieval |
| IMAP | 143/993 | Email retrieval (advanced) |
| SSH | 22 | Secure shell remote access |
| FTP | 21 | File transfer protocol |

**Traffic composition observation**: Based on initial observations, the **majority of traffic is HTTP and HTTPS**, which matches real-world corporate network behavior.

**Tool used**: **CIC-BenignGenerator** — an agent that takes B-Profiles as input and generates realistic benign network events. Published through the River Publishers journal.

**How it works**:
1. Real user behavior is observed and recorded over a period of time
2. Statistical models are built from this real behavior data
3. The models are parameterized (abstracted) into B-Profiles 
4. The CIC-BenignGenerator agent reads these B-Profiles
5. It then generates synthetic but statistically realistic network traffic following these profiles
6. This background traffic runs continuously during the attack data collection period

### M-Profiles (Malicious Traffic Generation)

**Purpose**: Describe attack scenarios in an **unambiguous, executable manner**.

**Approach**:
- In the simplest case, **human operators** (security researchers) interpret the M-Profiles and execute the attacks manually
- Ideally, **autonomous agents with compilers** would interpret and execute scenarios automatically
- For CSE-CIC-IDS2018, attacks were executed by security researchers from Kali Linux machines using specific tools

**Seven distinct attack scenarios were defined** (detailed in sections below):
1. Brute-force attacks (FTP & SSH)
2. Heartbleed vulnerability exploitation
3. Botnet deployment (Zeus & Ares)
4. DoS attacks (Hulk, GoldenEye, Slowloris, SlowHTTPTest)
5. DDoS attacks (LOIC HTTP, LOIC UDP, HOIC)
6. Web attacks (SQL Injection, XSS, Brute-force)
7. Infiltration from inside (email exploit + lateral movement)

---

## 4. Attack Scenario 1: Brute-Force Attacks

### Overview
Brute-force attacks are designed to break into accounts with weak username/password combinations by systematically trying every possible combination from a dictionary.

### Tool: Patator

**Why Patator was chosen over alternatives:**

The researchers evaluated multiple brute-force tools before choosing:
| Tool | Limitation |
|---|---|
| Hydra | Less reliable, rigid usage patterns |
| Medusa | Less flexible, fewer protocol modules |
| Ncrack | Limited protocol support |
| Metasploit modules | Heavier, slower for pure brute-forcing |
| Nmap NSE scripts | Not designed as primary brute-force tool |
| hashcat / hashpump | Only for offline password hash cracking, not network login brute-force |

**Patator was selected because:**
- Written in **Python** — multi-threaded, more reliable and flexible
- Most **comprehensive multi-threaded** brute-forcing tool available
- Supports saving **every response in a separate log file** for later review
- Modular architecture — separate modules for each protocol
- Better error handling and retry logic than competitors

### Patator Technical Details

**Patator modules used:**
- `ftp_login`: Brute-force FTP login
- `ssh_login`: Brute-force SSH login

**Patator capabilities:**
- Multi-threaded parallel connection attempts
- Per-response logging to individual files
- Configurable ignore rules (filter out known responses like "Login incorrect")
- Retry logic for connection failures (code 500, timeouts)
- Rate limiting to avoid lockouts
- Resume capability (can resume from where it left off)
- Supports combo files (username:password pairs in one file)

**FTP Brute-Force command structure:**
```bash
patator ftp_login host=<VICTIM_IP> user=FILE0 password=FILE1 0=usernames.txt 1=passwords.txt -x ignore:mesg='Login incorrect.'
```

**SSH Brute-Force command structure:**
```bash
patator ssh_login host=<VICTIM_IP> user=FILE0 password=FILE1 0=usernames.txt 1=passwords.txt -x ignore:mesg='Authentication failed.'
```

### Dictionary
- A **large dictionary containing 90 million words** was used as the password list
- This is a realistic attack: real-world brute-force attacks commonly use dictionaries of leaked/common passwords

### Attack Configuration

| Parameter | Value |
|---|---|
| Attack tool | Patator |
| Modules used | `ftp_login`, `ssh_login` |
| Attacker OS | Kali Linux |
| Victim OS | Ubuntu 16.04 (Web Server) |
| Password dictionary size | 90 million words |
| Duration | One day |
| FTP port targeted | 21 |
| SSH port targeted | 22 |

### Execution Details

**FTP Brute-Force:**
- **Date**: Wednesday, February 14, 2018
- **Attacker IP**: 172.31.70.4 (Public: 18.221.219.4)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148)
- **Start time**: 10:32 AM
- **End time**: 12:09 PM
- **Duration**: ~1 hour 37 minutes

**SSH Brute-Force:**
- **Date**: Wednesday, February 14, 2018
- **Attacker IP**: 172.31.70.6 (Public: 13.58.98.64)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148)
- **Start time**: 14:01 (2:01 PM)
- **End time**: 15:31 (3:31 PM)
- **Duration**: ~1 hour 30 minutes

**Key observation**: FTP and SSH brute-force were launched from **different attacker machines** against the **same victim**. This made it harder for an IDS to correlate the two attacks.

### Network Behavior During Attack
- Each attempt creates a **new TCP connection** to the target service
- Thousands of short-lived connections in rapid succession
- High volume of "Authentication failed" responses from the server
- Increased TCP SYN packets per second
- Flows show very **small packet sizes** (just credentials being sent) and **short flow durations**

---

## 5. Attack Scenario 2: Heartbleed (OpenSSL Vulnerability)

### Background

**CVE-2014-0160** — The Heartbleed Bug

- Discovered in April 2014, one of the most devastating vulnerabilities in internet history
- Affected **OpenSSL versions 1.0.1 through 1.0.1f** (released December 31, 2011 to January 6, 2014)
- Estimated to have affected **17% of all SSL servers** (~500,000 servers worldwide)
- The bug was in the **TLS heartbeat extension** implementation (RFC 6520)

**How Heartbleed Works (Technical Detail):**

1. TLS/SSL has a "heartbeat" extension that allows one endpoint to send a "heartbeat request" to keep the connection alive
2. The request contains a **payload** and declares **how long the payload is**
3. The vulnerable OpenSSL implementation **trusts the declared length** without verifying it matches the actual payload
4. An attacker sends a tiny payload (e.g., 1 byte) but declares the length as up to **65,535 bytes** (64 KB)
5. The server reads the 1-byte payload, then reads the remaining 65,534 bytes **from its own memory** (buffer over-read)
6. These memory bytes are sent back to the attacker in the heartbeat response
7. The leaked memory can contain:
   - **Private SSL/TLS keys** (most devastating — allows decryption of all traffic)
   - **Session cookies**
   - **Usernames and passwords** in cleartext
   - **Other users' requests** currently in memory
   - **Application data**
8. The attack leaves **no trace in server logs** — making it undetectable without network IDS

### Tool: Heartleech

**Why Heartleech was chosen:**
Heartleech is one of the most capable Heartbleed exploitation tools. Features:
- **Conclusive/inconclusive verdicts** — definitively determines if target is vulnerable
- **Bulk/fast download** of heartbleed data into a large file for offline processing using **many threads**
- **Automatic retrieval of private keys** with no additional manual steps
- **Limited IDS evasion** capabilities built in
- **STARTTLS support** — can exploit Heartbleed on services that upgrade to TLS (like SMTP, IMAP, FTP)
- **IPv6 support**
- **Tor/Socks5n proxy support** — can route attacks through anonymization networks
- **Extensive connection diagnostic information**

### Vulnerable Server Setup

The researchers **deliberately compiled a vulnerable version of OpenSSL**:
- **OpenSSL version 1.0.1f** — specifically known to be vulnerable
- Installed on an **Ubuntu 12.04** server
- The server was configured to use this vulnerable OpenSSL for HTTPS connections

### Attack Execution

| Parameter | Value |
|---|---|
| Tool | Heartleech |
| Attacker OS | Kali Linux |
| Victim OS | Ubuntu 12.04 |
| Vulnerable software | OpenSSL 1.0.1f |
| CVE | CVE-2014-0160 |
| Duration | One day |
| Exploitation method | TLS heartbeat extension buffer over-read |
| Data exfiltrated | Server memory contents (up to 64KB per request) |

### What Heartleech Does Step-by-Step

1. **Scan phase**: Sends a crafted heartbeat request with mismatched length to determine if the server responds with extra memory data
2. **Verdict**: Reports whether the target is definitely vulnerable, not vulnerable, or inconclusive
3. **Exploitation phase**: Sends repeated heartbeat requests to bulk-download server memory
4. **Key extraction**: Automatically analyzes downloaded memory dumps to find and reconstruct the server's private RSA key
5. **Output**: Saves all captured memory to a file for offline analysis

### Network Signature
- Uses **standard TLS handshake** initially (legitimate-looking)
- Then sends **TLS heartbeat requests** (record type 0x18)
- The response packets are **much larger than the request** (64KB responses to tiny requests)
- No server error logs generated — purely network-observable attack
- Flows show asymmetric traffic: small forward packets, large backward packets

---

## 6. Attack Scenario 3: Botnet (Zeus & Ares)

### Overview
Two different botnets were deployed to infect victim machines and create a command-and-control (C2) network.

### Botnet 1: Zeus (Zbot)

**Background:**
- Zeus is a **Trojan horse malware package** that targets Microsoft Windows
- First identified in July 2007
- Used to steal banking information via **man-in-the-browser** attacks
- Uses **keystroke logging** (recording all keys typed) and **form grabbing** (intercepting data before it's encrypted)
- Also used to install **CryptoLocker ransomware**
- Spread primarily through:
  - **Drive-by downloads** (visiting compromised websites)
  - **Phishing schemes** (malicious email attachments)

**Zeus Technical Capabilities:**
- Injects itself into browser processes (Internet Explorer, Firefox, etc.)
- Hooks Windows API calls to intercept data
- Modifies web pages in the browser before displaying them to the user
- Can be controlled remotely via HTTP-based C2 (command and control)
- Self-propagation capability
- Polymorphic code — changes its binary signature to evade antivirus

### Botnet 2: Ares

**Background:**
- Ares is an **open-source Python-based botnet** (available on GitHub)
- Chosen as a complement to Zeus for its different capabilities and simplicity

**Ares Capabilities (exactly as used in the dataset):**
| Capability | Description |
|---|---|
| Remote cmd.exe shell | Execute arbitrary commands on the infected machine remotely |
| Persistence | Survive reboots — installs itself in startup/registry |
| File upload | Upload files FROM the C2 server TO the victim |
| File download | Download files FROM the victim TO the C2 server (data exfiltration) |
| Screenshot capture | Take screenshots of the victim's desktop |
| Key logging | Record all keystrokes (passwords, messages, etc.) |

**Ares Architecture:**
- **Agent**: Python script running on infected victim machines
- **C2 Server**: Web-based command-and-control interface running on the attacker machine
- **Communication**: HTTP-based — blends with normal web traffic
- Agents periodically check in with the C2 server for new commands (beaconing)

### Infection Method
- Machines were **directly infected** with both Zeus and Ares payloads
- Infected OS versions span the entire Windows lineup to test diversity:
  - Windows Vista
  - Windows 7
  - Windows 8.1
  - Windows 10 (32-bit)
  - Windows 10 (64-bit)

### Botnet Command-and-Control Activity
- **Every 400 seconds** (~6.67 minutes), screenshots were requested from all zombie machines
- This periodic beaconing creates a **regular, detectable pattern** in network traffic
- The C2 communication also included command-response exchanges for remote shell, file operations

### Attack Configuration

| Parameter | Value |
|---|---|
| Botnets used | Zeus + Ares |
| Attacker (C2 Server) | Kali Linux |
| Victim OS versions | Windows Vista, 7, 8.1, 10 (32-bit), 10 (64-bit) |
| Duration | One day |
| Screenshot interval | Every 400 seconds |
| Date | Friday, March 2, 2018 |

### Execution Details

**Session 1:**
- **C2 Server IP**: 18.219.211.138
- **Zombie (victim) IPs**:
  - 18.217.218.111 (172.31.69.23)
  - 18.222.10.237 (172.31.69.17)
  - 18.222.86.193 (172.31.69.14)
  - 18.222.62.221 (172.31.69.12)
  - 13.59.9.106 (172.31.69.10)
  - 18.222.102.2 (172.31.69.8)
  - 18.219.212.0 (172.31.69.6)
  - 18.216.105.13 (172.31.69.26)
  - 18.219.163.126 (172.31.69.29)
  - 18.216.164.12 (172.31.69.30)
- **Start time**: 10:11 AM
- **End time**: ~11:XX AM

**Session 2:**
- Same C2 and zombie IPs
- **Start time**: 14:24 (2:24 PM)
- **End time**: ~15:XX PM

### Network Behavior
- Periodic **HTTP POST requests** from zombies to C2 (beaconing)
- **Small regular-interval** connections (400-second heartbeat)
- Occasional **large data transfers** (screenshots being uploaded)
- **cmd.exe shell** commands produce small request/large response patterns
- File upload/download create **asymmetric flow** patterns
- The traffic **mimics normal web browsing** (HTTP protocol) to evade simple firewalls

---

## 7. Attack Scenario 4: DoS (Denial-of-Service)

### Overview
Four different DoS tools were used across two days, each representing a different denial-of-service technique. All attacks targeted web servers to make them completely inaccessible.

### Tool 1: GoldenEye

**What it is:**
- GoldenEye is an **HTTP DoS tool** written in Python
- Specifically designed to take down web servers
- Uses **HTTP Keep-Alive** connections with random headers
- Simulates legitimate-looking browser behavior

**How GoldenEye works (technical detail):**
1. Opens many concurrent connections to the target web server
2. Sends HTTP requests with **random User-Agent strings** (mimicking different browsers)
3. Sends **random, partial HTTP headers** to keep connections open
4. Uses **HTTP Keep-Alive** to prevent the server from closing connections
5. Each connection consumes a server thread/worker
6. Eventually all server resources (connection slots, memory, CPU) are exhausted
7. Legitimate users cannot connect

**GoldenEye execution:**
- **Date**: Thursday, February 15, 2018
- **Attacker IP**: 172.31.70.46 (Public: 18.219.211.138)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148) — Ubuntu 16.04 running Apache
- **Start time**: 9:26 AM
- **End time**: 10:09 AM
- **Duration**: 43 minutes

### Tool 2: Slowloris

**What it is:**
- Slowloris is a type of **denial of service attack tool** invented by **Robert "RSnake" Hansen** in 2009
- It is a **Perl-based** script
- Revolutionary because it allows a **single machine** to take down a web server with **minimal bandwidth**
- Has **no side effects on unrelated services and ports** — surgically targets the HTTP service

**How Slowloris works (technical detail):**
1. The attacker opens a large number of **full TCP connections** to the target web server
2. Each connection starts a legitimate HTTP request by sending the initial headers:
   ```
   GET / HTTP/1.1\r\n
   Host: target.com\r\n
   ```
3. But the HTTP request is **never completed** — the final `\r\n\r\n` (empty line signaling end of headers) is never sent
4. Instead, at **regular intervals**, the tool sends additional **valid but incomplete HTTP headers**:
   ```
   X-a: b\r\n    (sent periodically to keep connection alive)
   ```
5. The web server keeps the connection open, waiting for the rest of the headers (which never come)
6. Since web servers have a **finite number of connection slots** (e.g., Apache's MaxClients), eventually ALL slots are consumed
7. No new legitimate connections can be made
8. The attack uses **minimal bandwidth** — just a few bytes sent per connection every few seconds
9. Unrelated ports (SSH, FTP, etc.) remain functional — only HTTP is affected

**Key characteristics:**
- Works against **Apache** (and many other) web servers
- Does NOT work against servers that handle connections asynchronously (like nginx, lighttpd)
- Very **stealthy** — low bandwidth, no malformed packets
- Hard to distinguish from **slow legitimate clients**
- Each connection sends valid HTTP data — just never completes

**Slowloris execution:**
- **Date**: Thursday, February 15, 2018
- **Attacker IP**: 172.31.70.8 (Public: 18.217.165.70)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148) — Ubuntu 16.04 running Apache
- **Start time**: 10:59 AM
- **End time**: 11:40 AM
- **Duration**: 41 minutes

### Tool 3: SlowHTTPTest

**What it is:**
- SlowHTTPTest is a **highly configurable tool** that simulates various Application Layer DoS attacks
- It implements several slow HTTP attack vectors:
  - **Slowloris-style** (slow headers)
  - **Slow HTTP POST** (R-U-Dead-Yet / RUDY attack)
  - **Slow Read** (reading responses extremely slowly)
  - **Apache Range Header** attack

**How SlowHTTPTest works (technical detail):**

*Slow Headers (Slowloris mode):*
- Same as Slowloris — send partial headers with periodic keep-alive bytes

*Slow POST (R-U-Dead-Yet):*
1. Send a legitimate HTTP POST request with a **Content-Length header** declaring a large body size (e.g., 100000 bytes)
2. The server allocates resources and waits for the full body
3. The body is sent **one byte at a time** at very long intervals
4. Server resources are tied up waiting for the full POST body
5. Multiple concurrent slow POST connections exhaust server resources

*Slow Read:*
1. Send a legitimate HTTP request normally
2. Advertise a very **small TCP receive window** (e.g., 1 byte)
3. Read the server's response **extremely slowly** (byte by byte)
4. Server buffers pile up with unsent data
5. Server resources are consumed by connections that are "receiving" but never finishing

**SlowHTTPTest execution:**
- **Date**: Friday, February 16, 2018
- **Attacker IP**: 172.31.70.23 (Public: 13.59.126.31)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148) — Ubuntu 16.04 running Apache
- **Start time**: 10:12 AM
- **End time**: 11:08 AM
- **Duration**: 56 minutes

### Tool 4: Hulk (HTTP Unbearable Load King)

**What it is:**
- Hulk is a **web server DoS tool** designed to generate unique, obfuscated traffic to bypass caching and detection
- Written in Python
- Designed to be an advanced flood tool

**How Hulk works (technical detail):**
1. **Generates unique requests** for each connection — every request has:
   - Random URL parameters (e.g., `/?rnd=83741928`)
   - Random User-Agent string (rotates from a list of real browser User-Agents)
   - Random Referer header
   - Randomized Accept-Encoding, Accept-Language, Accept-Charset headers
2. This randomization **defeats caching mechanisms** — every request looks unique
3. The server must **fully process each request** (cache cannot serve pre-computed responses)
4. High volume of unique GET requests **floods the server's request processing capacity**
5. Each request forces the server to:
   - Parse the unique URL
   - Execute server-side scripts/applications
   - Generate a full response
   - Allocate memory for the unique request

**Key difference from other DoS tools:**
- Hulk uses **high-bandwidth flooding** (unlike Slowloris which uses low bandwidth)
- Every request is **unique**, making it look like traffic from many different legitimate users
- Harder to filter with simple rate-limiting rules because each request appears different

**Hulk execution:**
- **Date**: Friday, February 16, 2018
- **Attacker IP**: 172.31.70.16 (Public: 18.219.193.20)
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148) — Ubuntu 16.04 running Apache
- **Start time**: 13:45 (1:45 PM)
- **End time**: 14:19 (2:19 PM)
- **Duration**: 34 minutes

### DoS Attack Summary Table

| Tool | Technique | Bandwidth | Sophistication | Date | Start | End | Duration |
|---|---|---|---|---|---|---|---|
| GoldenEye | HTTP Keep-Alive + random headers | Medium | Medium | Feb 15 | 9:26 | 10:09 | 43 min |
| Slowloris | Incomplete HTTP headers | Very Low | High | Feb 15 | 10:59 | 11:40 | 41 min |
| SlowHTTPTest | Slow headers/POST/Read | Very Low | High | Feb 16 | 10:12 | 11:08 | 56 min |
| Hulk | Unique randomized HTTP floods | High | Medium | Feb 16 | 13:45 | 14:19 | 34 min |

### All DoS Target
- **Same victim**: Ubuntu 16.04 running **Apache HTTP Server**
- **Same victim IP**: 172.31.69.25 (Public: 18.217.21.148)
- **Different attacker machines** used for each tool

---

## 8. Attack Scenario 5: DDoS (Distributed Denial-of-Service)

### Overview
Unlike DoS (single attacker), DDoS attacks use **multiple attacking machines** simultaneously. The dataset used 10 attacker machines coordinated against a single victim.

### Tool 1: LOIC (Low Orbit Ion Cannon)

**What it is:**
- LOIC is an **open-source network stress testing** and denial-of-service attack application
- Originally developed by **Praetox Technologies**
- Written in C#
- Famously used by the **Anonymous hacktivist group** in operations against Visa, MasterCard, PayPal, etc.
- Can send floods of **TCP, UDP, or HTTP packets**
- Simple GUI — extremely easy to use (point-and-click)

**How LOIC works (technical detail):**

*HTTP Mode:*
1. Each attacker machine runs LOIC pointing at the target URL
2. LOIC generates a massive volume of **HTTP GET requests** simultaneously
3. All requests target the same URL endpoint
4. The combined traffic from multiple machines overwhelms the web server
5. HTTP requests appear somewhat legitimate but the **volume is abnormal**

*UDP Mode:*
1. LOIC sends massive amounts of **UDP packets** to the target
2. UDP is connectionless — no handshake required
3. The target must process every incoming UDP packet
4. **Source IPs can potentially be spoofed** in UDP mode
5. Target's network bandwidth and processing capacity are overwhelmed
6. Network infrastructure (routers, firewalls) can also be overwhelmed by the packet volume

*TCP Mode:*
1. LOIC creates many **TCP connections simultaneously**
2. Each connection sends repeated TCP packets
3. Overwhelms the target's connection table and processing capacity

### Tool 2: HOIC (High Orbit Ion Cannon)

**What it is:**
- HOIC is the **successor to LOIC**, designed to be more powerful
- Written in **BASIC (RealBASIC/Xojo)**
- Can attack up to **256 URLs simultaneously** per instance
- Uses **"booster" scripts** that add randomization to HTTP requests
- The boosters add:
  - Random User-Agent headers
  - Random Referer headers
  - Random URL parameters
- This makes HOIC traffic **harder to filter** than LOIC
- More closely mimics legitimate traffic patterns

**How HOIC works:**
1. Load one or more target URLs
2. Optionally load "booster" scripts (`.hoic` files) for randomization
3. Set the number of threads (concurrent connections)
4. Launch — each thread sends randomized HTTP requests at maximum speed
5. With 256 URLs and boosters, the traffic is highly varied and harder to block

### DDoS Attacker Machine List

**All 10 attacker machine IPs:**
1. `18.218.115.60`
2. `18.219.9.1`
3. `18.219.32.43`
4. `18.218.55.126`
5. `52.14.136.135`
6. `18.219.5.43`
7. `18.216.200.189`
8. `18.218.229.235`
9. `18.218.11.51`
10. `18.216.24.42`

### DDoS Execution Details

**DDoS-LOIC-HTTP:**
- **Date**: Tuesday, February 20, 2018
- **Attackers**: All 10 machines listed above
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148)
- **Start time**: 10:12 AM
- **End time**: 11:17 AM
- **Duration**: ~1 hour 5 minutes
- **Method**: HTTP flood

**DDoS-LOIC-UDP (Session 1):**
- **Date**: Tuesday, February 20, 2018
- **Attackers**: All 10 machines
- **Victim IP**: 172.31.69.25 (Public: 18.217.21.148)
- **Start time**: 13:13 (1:13 PM)
- **End time**: 13:32 (1:32 PM)
- **Duration**: 19 minutes
- **Method**: UDP flood

**DDoS-LOIC-UDP (Session 2):**
- **Date**: Wednesday, February 21, 2018
- **Attackers**: All 10 machines
- **Victim IP**: 172.31.69.28 (Public: 18.218.83.150)
- **Start time**: 10:09 AM
- **End time**: 10:43 AM
- **Duration**: 34 minutes
- **Method**: UDP flood
- **Note**: Different victim machine than previous day

**DDoS-HOIC:**
- **Date**: Wednesday, February 21, 2018
- **Attackers**: All 10 machines
- **Victim IP**: 172.31.69.28 (Public: 18.218.83.150)
- **Start time**: 14:05 (2:05 PM)
- **End time**: 15:05 (3:05 PM)
- **Duration**: 1 hour
- **Method**: HTTP flood with booster randomization

### Network Behavior During DDoS
- **Massive spike** in packets-per-second from 10 different source IPs
- For HTTP attacks: thousands of HTTP GET requests per second
- For UDP attacks: very high volume of UDP datagrams, potentially with spoofed sources
- Extreme **asymmetry** in flow sizes (many small attack requests, large responses)
- **Consistent source IPs** (the 10 known attacker machines — no IP spoofing in HTTP mode)
- Server response time degrades to timeout
- Eventually server stops responding entirely

---

## 9. Attack Scenario 6: Web Attacks (XSS, SQL Injection, Brute-Force)

### Overview
Three types of web application attacks were conducted against a vulnerable web application. The attacks spanned two days with identical attack types repeated.

### Target Application: DVWA (Damn Vulnerable Web App)

**What is DVWA:**
- DVWA is a **PHP/MySQL web application** that is **intentionally vulnerable**
- Developed as a training tool for security professionals
- Contains **known vulnerabilities** that can be exploited in a controlled environment
- Supports different security levels (low, medium, high) to practice different evasion techniques
- Has built-in modules for:
  - SQL Injection
  - Cross-Site Scripting (XSS) — both Reflected and Stored
  - Command Injection
  - File Upload vulnerabilities
  - CSRF (Cross-Site Request Forgery)
  - Brute-force login
  - File Inclusion
  - Insecure CAPTCHA

### Attack Type 1: Brute-Force Web Login

**What it is:**
- Dictionary-based password guessing against the DVWA web login form
- Unlike SSH/FTP brute-force, this targets the **HTTP form authentication**

**How it works:**
1. The automation framework sends HTTP POST requests to the login form
2. Each request contains a different username/password combination
3. The response is checked for success/failure indicators
4. Thousands of login attempts are made rapidly

**Automation tool**: An **in-house Selenium framework** developed by the CIC researchers
- **Selenium** is a web browser automation tool
- Originally designed for web application testing
- Can programmatically control a real web browser (Chrome, Firefox, etc.)
- The custom framework automates:
  - Form filling with credentials from a dictionary
  - Form submission
  - Response validation (success vs. failure detection)
  - Iteration through the password list

### Attack Type 2: Cross-Site Scripting (XSS)

**What is XSS:**
- XSS allows an attacker to **inject client-side scripts** (usually JavaScript) into web pages viewed by other users
- The injected script runs in the victim's browser with the same privileges as the legitimate page

**Types of XSS exploited:**
1. **Reflected XSS**: The malicious script is reflected off the web server (via URL parameter or form input) and executed in the victim's browser
2. **Stored XSS**: The malicious script is permanently stored on the target server (in a database, comment field, etc.) and executed whenever any user views the page

**How XSS attacks were automated:**
- The **in-house Selenium framework** was used
- The framework:
  1. Navigates to vulnerable form fields in DVWA
  2. Injects various XSS payloads (e.g., `<script>alert('XSS')</script>`)
  3. Submits the form
  4. Verifies if the XSS payload was executed
  5. Records success/failure
  6. Tries different evasion techniques (encoding, obfuscation)

**Common XSS payloads that would have been used:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert(document.cookie)</script>
<body onload=alert('XSS')>
```

### Attack Type 3: SQL Injection

**What is SQL Injection:**
- SQL Injection allows an attacker to **interfere with the queries** that an application makes to its database
- Can be used to:
  - **Bypass authentication** (login without valid credentials)
  - **Extract data** from the database (dump tables, read other users' data)
  - **Modify data** (INSERT, UPDATE, DELETE)
  - **Execute operating system commands** (in some configurations)
  - **Read/write files** on the server

**How SQL Injection works in DVWA:**
1. DVWA has a vulnerable search/lookup form that directly concatenates user input into SQL queries
2. Example vulnerable code: `SELECT * FROM users WHERE id = '$user_input'`
3. Attacker enters: `' OR '1'='1` — this always evaluates to TRUE
4. The query becomes: `SELECT * FROM users WHERE id = '' OR '1'='1'` — returns ALL users

**Common SQL Injection payloads used:**
```sql
' OR '1'='1
' OR 1=1 --
' UNION SELECT null, table_name FROM information_schema.tables --
' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT user, password FROM users --
1'; DROP TABLE users;--
```

**This attack was conducted manually** (not automated like XSS and web brute-force), as SQL Injection typically requires adaptive input based on server responses.

### Web Attack Execution Details

**Day 1 — Thursday, February 22, 2018:**

| Attack | Attacker IP | Victim IP | Start | End | Duration |
|---|---|---|---|---|---|
| Brute Force - Web | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 10:17 | 11:24 | 67 min |
| Brute Force - XSS | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 13:50 | 14:29 | 39 min |
| SQL Injection | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 16:15 | 16:29 | 14 min |

**Day 2 — Friday, February 23, 2018:**

| Attack | Attacker IP | Victim IP | Start | End | Duration |
|---|---|---|---|---|---|
| Brute Force - Web | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 10:03 | 11:03 | 60 min |
| Brute Force - XSS | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 13:00 | 14:10 | 70 min |
| SQL Injection | 18.218.115.60 | 18.218.83.150 (172.31.69.28) | 15:05 | 15:18 | 13 min |

**Key observations:**
- **Same single attacker** (18.218.115.60) for all web attacks across both days
- **Same victim** (18.218.83.150 / 172.31.69.28) for all web attacks
- SQL Injection had the shortest duration (~14 min) — fewer payloads needed
- Web Brute Force took the longest — many credential combinations to try
- Attacks were **separated by gaps** (morning + afternoon) — realistic scheduling
- Day 2 durations were slightly different, suggesting **non-identical** execution

### Network Behavior During Web Attacks
- **HTTP POST requests** at high frequency (brute-force)
- **HTTP GET/POST with SQL special characters** in parameters (`'`, `--`, `UNION`, `SELECT`)
- **HTTP GET/POST with script tags** in parameters (`<script>`, `<img>`, `onerror`)
- All traffic on **port 80 (HTTP)** or **port 443 (HTTPS)**
- Response sizes vary (success vs. error pages have different sizes)
- **Single source IP to single destination** — concentrated attack pattern

---

## 10. Attack Scenario 7: Infiltration of the Network from Inside

### Overview
This is the most **complex and multi-stage** attack scenario. It simulates an Advanced Persistent Threat (APT) where an attacker gains initial access through social engineering, then performs lateral movement within the network.

### Attack Methodology (Step by Step)

**Phase 1: Initial Compromise (Social Engineering + Client-Side Exploit)**

1. The attacker crafts a **malicious document** (e.g., a PDF)
2. The malicious PDF exploits a vulnerability in **Adobe Acrobat Reader 9** (known vulnerable version)
3. The document is sent to the victim via **email**
4. The victim opens the email attachment on their computer
5. Adobe Acrobat Reader processes the malicious PDF
6. The exploit triggers and executes **shellcode** (machine code embedded in the PDF)
7. The shellcode downloads and executes a **backdoor/stager** from the attacker's server

**Phase 2: Establishing Backdoor (Metasploit Framework)**

1. The exploit payload is generated using **Metasploit Framework** — the world's most widely used penetration testing framework
2. The victim's machine establishes a **reverse connection** back to the attacker's Metasploit handler
3. This gives the attacker a **Meterpreter session** (interactive command shell on the victim)
4. The attacker now has full control of the victim's machine

**Phase 3: Internal Reconnaissance & Lateral Movement**

With the backdoor active, the attacker conducts the following from the victim's compromised machine:

1. **IP Sweep (Ping Scan)**:
   - Uses Nmap to discover other live hosts on the victim's internal network
   - Command: `nmap -sn 172.31.69.0/24` (ping sweep of the entire subnet)
   - Identifies which IPs are active

2. **Full Port Scan**:
   - For each discovered host, scans all 65,535 TCP ports
   - Command: `nmap -p 1-65535 <target_ip>`
   - Identifies all open services on internal machines

3. **Service Enumeration**:
   - Probes open ports to determine what software/version is running
   - Command: `nmap -sV -A <target_ip>`
   - Identifies vulnerable services for further exploitation

4. **Exploitation of Internal Machines** (if possible):
   - If vulnerable services are found, the attacker attempts to exploit them
   - This creates additional compromised machines in the network

### Tools Used

| Tool | Purpose |
|---|---|
| Malicious PDF | Initial compromise vector |
| Adobe Acrobat Reader 9 (victim) | Vulnerable application being exploited |
| Email | Delivery mechanism |
| **Metasploit Framework** | Backdoor generation, exploit delivery, post-exploitation |
| **Meterpreter** | Interactive shell on compromised machine |
| **Nmap** | Network reconnaissance (ping sweep, port scan, service enumeration) |

### Victim Machines
- **Windows Vista** machines and **Macintosh** (Mac) machines
- These represent less secure/older machines in a typical corporate environment
- The Dropbox download method was also used — victim downloads a file from Dropbox that contains the exploit

### Infiltration Execution Details

**Session 1 — Wednesday, February 28, 2018 (Morning):**
- **Attacker IP**: 13.58.225.34
- **Victim IP**: 18.221.148.137 (172.31.69.24)
- **Start time**: 10:50 AM
- **End time**: 12:05 PM
- **Duration**: 1 hour 15 minutes

**Session 2 — Wednesday, February 28, 2018 (Afternoon):**
- **Attacker IP**: 13.58.225.34
- **Victim IP**: 18.221.148.137 (172.31.69.24)
- **Start time**: 13:42 (1:42 PM)
- **End time**: 14:40 (2:40 PM)
- **Duration**: 58 minutes

**Session 3 — Thursday, March 1, 2018 (Morning):**
- **Attacker IP**: 13.58.225.34
- **Victim IP**: 18.216.254.154 (172.31.69.13) — **Different victim**
- **Start time**: 9:57 AM
- **End time**: 10:55 AM
- **Duration**: 58 minutes

**Session 4 — Thursday, March 1, 2018 (Afternoon):**
- **Attacker IP**: 13.58.225.34
- **Victim IP**: 18.216.254.154 (172.31.69.13)
- **Start time**: 14:00 (2:00 PM)
- **End time**: 15:37 (3:37 PM)
- **Duration**: 1 hour 37 minutes

### Two-Level Attack Description (from official documentation)
- **First Level**: Dropbox download on a Windows machine (delivering the malicious payload)
- **Second Level**: Nmap and portscan (internal network reconnaissance from the compromised machine)

### Network Behavior During Infiltration
**Phase 1 (Initial compromise):**
- Email traffic (SMTP) with attachment
- HTTP/HTTPS download from Dropbox (looks like normal file download)
- This phase is extremely hard to detect by network IDS

**Phase 2 (Backdoor communication):**
- Reverse TCP/HTTP connection from victim to attacker (Meterpreter)
- Regular beaconing (check-in) between victim and C2
- Can be encrypted, making payload inspection impossible

**Phase 3 (Reconnaissance):**
- **ICMP echo requests** (ping sweep) — victim machine pinging many internal IPs
- **TCP SYN packets** to many ports on many internal IPs (port scanning)
- **Service probing** — partial TCP connections with protocol-specific payloads
- This phase generates a **distinctive scanning pattern** visible in flow data

---

## 11. Day-by-Day Attack Execution Schedule

| Date | Day | Attacks Executed | Duration |
|---|---|---|---|
| **Feb 14, 2018** | Wednesday | FTP Brute-Force, SSH Brute-Force | One day |
| **Feb 15, 2018** | Thursday | DoS-GoldenEye, DoS-Slowloris | One day |
| **Feb 16, 2018** | Friday | DoS-SlowHTTPTest, DoS-Hulk | One day |
| **Feb 17-19, 2018** | Sat-Mon | **No attacks** (weekend + holiday) | — |
| **Feb 20, 2018** | Tuesday | DDoS-LOIC-HTTP, DDoS-LOIC-UDP | One day |
| **Feb 21, 2018** | Wednesday | DDoS-LOIC-UDP, DDoS-HOIC | One day |
| **Feb 22, 2018** | Thursday | Web Attack: Brute Force, XSS, SQL Injection | One day |
| **Feb 23, 2018** | Friday | Web Attack: Brute Force, XSS, SQL Injection | One day |
| **Feb 24-27, 2018** | Sat-Tue | **No attacks** (weekend + gap) | — |
| **Feb 28, 2018** | Wednesday | Infiltration (two sessions) | One day |
| **Mar 1, 2018** | Thursday | Infiltration (two sessions, different victim) | One day |
| **Mar 2, 2018** | Friday | Botnet (Zeus + Ares, two sessions) | One day |

### Important Timing Notes
- Attacks are executed during **business hours** (approximately 9:00 AM - 4:30 PM)
- There are **gaps between attacks** on the same day (morning and afternoon sessions)
- Benign background traffic runs **continuously throughout** the entire data collection period
- **Weekends and holidays have no attacks** — only benign traffic
- This creates a realistic pattern where attacks happen during workdays, mixed with normal traffic

---

## 12. Exact Attacker & Victim IPs (Per Attack)

### Complete IP Address Mapping

| Attack | Attacker Internal IP | Attacker Public IP | Victim Internal IP | Victim Public IP |
|---|---|---|---|---|
| FTP-BruteForce | 172.31.70.4 | 18.221.219.4 | 172.31.69.25 | 18.217.21.148 |
| SSH-Bruteforce | 172.31.70.6 | 13.58.98.64 | 172.31.69.25 | 18.217.21.148 |
| DoS-GoldenEye | 172.31.70.46 | 18.219.211.138 | 172.31.69.25 | 18.217.21.148 |
| DoS-Slowloris | 172.31.70.8 | 18.217.165.70 | 172.31.69.25 | 18.217.21.148 |
| DoS-SlowHTTPTest | 172.31.70.23 | 13.59.126.31 | 172.31.69.25 | 18.217.21.148 |
| DoS-Hulk | 172.31.70.16 | 18.219.193.20 | 172.31.69.25 | 18.217.21.148 |
| DDoS-LOIC-HTTP | (10 machines) | See DDoS section | 172.31.69.25 | 18.217.21.148 |
| DDoS-LOIC-UDP (Feb 20) | (10 machines) | See DDoS section | 172.31.69.25 | 18.217.21.148 |
| DDoS-LOIC-UDP (Feb 21) | (10 machines) | See DDoS section | 172.31.69.28 | 18.218.83.150 |
| DDoS-HOIC | (10 machines) | See DDoS section | 172.31.69.28 | 18.218.83.150 |
| Brute Force-Web | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 |
| Brute Force-XSS | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 |
| SQL Injection | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 |
| Infiltration (Feb 28) | — | 13.58.225.34 | 172.31.69.24 | 18.221.148.137 |
| Infiltration (Mar 1) | — | 13.58.225.34 | 172.31.69.13 | 18.216.254.154 |
| Botnet | — | 18.219.211.138 | (10 zombies) | See Botnet section |

### Botnet Zombie IPs (Complete List)

| # | Internal IP | Public IP |
|---|---|---|
| 1 | 172.31.69.23 | 18.217.218.111 |
| 2 | 172.31.69.17 | 18.222.10.237 |
| 3 | 172.31.69.14 | 18.222.86.193 |
| 4 | 172.31.69.12 | 18.222.62.221 |
| 5 | 172.31.69.10 | 13.59.9.106 |
| 6 | 172.31.69.8 | 18.222.102.2 |
| 7 | 172.31.69.6 | 18.219.212.0 |
| 8 | 172.31.69.26 | 18.216.105.13 |
| 9 | 172.31.69.29 | 18.219.163.126 |
| 10 | 172.31.69.30 | 18.216.164.12 |

---

## 13. Feature Extraction (CICFlowMeter-V3)

### What is CICFlowMeter

- **CICFlowMeter** (formerly ISCXFlowMeter) is a **network traffic flow generator and analyzer** 
- Written in **Java**
- Developed by CIC/UNB specifically for generating features for intrusion detection datasets
- GitHub: https://github.com/ahlashkari/CICFlowMeter

### How It Works

1. **Input**: Raw PCAP (packet capture) files
2. **Processing**: Groups individual packets into **bidirectional flows (biflows)**
3. **Flow definition**: A flow is identified by the 5-tuple:
   - Source IP
   - Destination IP
   - Source Port
   - Destination Port
   - Protocol
4. **Direction**: The **first packet** in a flow determines the forward direction (source → destination). All subsequent packets in the reverse direction are tagged as backward.
5. **Flow termination**:
   - TCP flows are terminated upon **FIN packet** (connection teardown)
   - UDP flows are terminated by **flow timeout** (configurable, default: 600 seconds)
   - TCP flows can also timeout if inactive
6. **Output**: CSV files with flow-level statistical features

### Output Format
Each row in the CSV represents one network flow. Columns include:
- `FlowID` — Unique identifier for the flow
- `SourceIP` — Source IP address
- `DestinationIP` — Destination IP address
- `SourcePort` — Source port number
- `DestinationPort` — Destination port number
- `Protocol` — Protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
- **80+ statistical features** (listed in next section)

---

## 14. Labeling Methodology

### How Labels Were Assigned

1. After feature extraction, the CSV files contained **unlabeled flows**
2. Researchers used the **attack schedule** (Table 2 — attacker IPs, victim IPs, start/end times)
3. For each flow, they checked:
   - **Source IP** and **Destination IP** — match known attacker/victim pairs?
   - **Port numbers** — match the attacked service?
   - **Protocol** — match the expected protocol?
   - **Timestamp** — fall within the attack's start and end time?
4. If ALL conditions match → labeled as the **specific attack type**
5. If conditions don't match → labeled as **Benign**

### Label Types in the Dataset

| Label | Count (approx.) | Description |
|---|---|---|
| Benign | Majority | Normal/legitimate traffic |
| FTP-BruteForce | Varies | FTP brute-force via Patator |
| SSH-Bruteforce | Varies | SSH brute-force via Patator |
| DoS attacks-Hulk | Varies | HTTP flood via Hulk |
| DoS attacks-GoldenEye | Varies | HTTP DoS via GoldenEye |
| DoS attacks-Slowloris | Varies | Slow header DoS via Slowloris |
| DoS attacks-SlowHTTPTest | Varies | Slow HTTP DoS via SlowHTTPTest |
| DDoS attacks-LOIC-HTTP | Varies | Distributed HTTP flood via LOIC |
| DDOS-LOIC-UDP | Varies | Distributed UDP flood via LOIC |
| DDOS-HOIC | Varies | Distributed HTTP flood via HOIC |
| Brute Force -Web | Varies | Web form brute-force |
| Brute Force -XSS | Varies | XSS exploitation attempts |
| SQL Injection | Varies | SQL injection attacks |
| Infilteration | Varies | Multi-stage infiltration (note: typo is in original dataset) |
| Bot | Varies | Botnet C2 communication |

### Important Labeling Notes
- The label **"Infilteration"** contains a **typo** in the original dataset (should be "Infiltration") — preserved as-is in the CSV files
- Labels are assigned at the **flow level**, not the packet level
- A single attack session generates **many flows** (each TCP connection = one flow)
- Some legitimate traffic during attack windows may be **mislabeled** as attack traffic (false positives in labeling)
- Some attack traffic outside the official time windows may be **missed** (false negatives in labeling)

---

## 15. Dataset File Structure & Organization

### Data Organization Per Day
For each day, the following was recorded:

1. **Raw PCAP files**: Complete packet captures of all network traffic
   - Individual PCAP files per machine
   - Total raw data: ~450 GB

2. **Event Logs**: 
   - Windows Event Logs (from Windows machines)
   - Ubuntu system logs (from Linux machines)
   - Per-machine log files

3. **CSV Feature Files**: 
   - Generated by CICFlowMeter-V3 from the PCAPs
   - Per-machine CSV files
   - Contains 80+ features per flow
   - Labeled with attack type

### CSV Files Available (by date)

| Filename | Date | Attacks | Size |
|---|---|---|---|
| 02-14-2018.csv | Feb 14 | FTP-BruteForce, SSH-Bruteforce | ~358 MB |
| 02-15-2018.csv | Feb 15 | DoS-GoldenEye, DoS-Slowloris | Large |
| 02-16-2018.csv | Feb 16 | DoS-SlowHTTPTest, DoS-Hulk | Large |
| 02-20-2018.csv | Feb 20 | DDoS-LOIC-HTTP, DDoS-LOIC-UDP | Large |
| 02-21-2018.csv | Feb 21 | DDoS-LOIC-UDP, DDoS-HOIC | Large |
| 02-22-2018.csv | Feb 22 | Web attacks (BF, XSS, SQL) | Large |
| 02-23-2018.csv | Feb 23 | Web attacks (BF, XSS, SQL) | Large |
| 02-28-2018.csv | Feb 28 | Infiltration | Large |
| 03-01-2018.csv | Mar 1 | Infiltration | Large |
| 03-02-2018.csv | Mar 2 | Botnet | Large |

### Storage Location
- AWS S3 bucket: `s3://cse-cic-ids2018/`
- AWS Region: `ca-central-1` (Canada)
- **No AWS account required** to download (public bucket)
- Download command: `aws s3 sync --no-sign-request --region <your-region> "s3://cse-cic-ids2018/" dest-dir`

---

## 16. Full List of 80+ Extracted Features

### Flow-Level Statistical Features

| # | Feature Name | Description |
|---|---|---|
| 1 | fl_dur | Flow duration (in microseconds) |
| 2 | tot_fw_pk | Total packets in the forward direction |
| 3 | tot_bw_pk | Total packets in the backward direction |
| 4 | tot_l_fw_pkt | Total size of packets in forward direction |
| 5 | fw_pkt_l_max | Maximum size of packet in forward direction |
| 6 | fw_pkt_l_min | Minimum size of packet in forward direction |
| 7 | fw_pkt_l_avg | Average size of packet in forward direction |
| 8 | fw_pkt_l_std | Standard deviation of packet size in forward direction |
| 9 | Bw_pkt_l_max | Maximum size of packet in backward direction |
| 10 | Bw_pkt_l_min | Minimum size of packet in backward direction |
| 11 | Bw_pkt_l_avg | Mean size of packet in backward direction |
| 12 | Bw_pkt_l_std | Standard deviation of packet size in backward direction |
| 13 | fl_byt_s | Flow byte rate (bytes transferred per second) |
| 14 | fl_pkt_s | Flow packet rate (packets transferred per second) |
| 15 | fl_iat_avg | Average inter-arrival time between two flows |
| 16 | fl_iat_std | Standard deviation of inter-arrival time |
| 17 | fl_iat_max | Maximum inter-arrival time between two flows |
| 18 | fl_iat_min | Minimum inter-arrival time between two flows |
| 19 | fw_iat_tot | Total time between two packets sent in forward direction |
| 20 | fw_iat_avg | Mean time between two packets sent in forward direction |
| 21 | fw_iat_std | Std dev of time between two packets in forward direction |
| 22 | fw_iat_max | Maximum time between two packets in forward direction |
| 23 | fw_iat_min | Minimum time between two packets in forward direction |
| 24 | bw_iat_tot | Total time between two packets sent in backward direction |
| 25 | bw_iat_avg | Mean time between two packets sent in backward direction |
| 26 | bw_iat_std | Std dev of time between two packets in backward direction |
| 27 | bw_iat_max | Maximum time between two packets sent in backward direction |
| 28 | bw_iat_min | Minimum time between two packets sent in backward direction |
| 29 | fw_psh_flag | Number of times PSH flag set in forward direction (0 for UDP) |
| 30 | bw_psh_flag | Number of times PSH flag set in backward direction (0 for UDP) |
| 31 | fw_urg_flag | Number of times URG flag set in forward direction (0 for UDP) |
| 32 | bw_urg_flag | Number of times URG flag set in backward direction (0 for UDP) |
| 33 | fw_hdr_len | Total bytes used for headers in forward direction |
| 34 | bw_hdr_len | Total bytes used for headers in backward direction |
| 35 | fw_pkt_s | Number of forward packets per second |
| 36 | bw_pkt_s | Number of backward packets per second |
| 37 | pkt_len_min | Minimum length of a flow |
| 38 | pkt_len_max | Maximum length of a flow |
| 39 | pkt_len_avg | Mean length of a flow |
| 40 | pkt_len_std | Standard deviation of flow length |
| 41 | pkt_len_va | Variance of flow length |
| 42 | fin_cnt | Number of packets with FIN flag |
| 43 | syn_cnt | Number of packets with SYN flag |
| 44 | rst_cnt | Number of packets with RST flag |
| 45 | pst_cnt | Number of packets with PUSH flag |
| 46 | ack_cnt | Number of packets with ACK flag |
| 47 | urg_cnt | Number of packets with URG flag |
| 48 | cwe_cnt | Number of packets with CWE flag |
| 49 | ece_cnt | Number of packets with ECE flag |
| 50 | down_up_ratio | Download and upload ratio |
| 51 | pkt_size_avg | Average size of packet |
| 52 | fw_seg_avg | Average segment size observed in forward direction |
| 53 | bw_seg_avg | Average segment size observed in backward direction |
| 54 | fw_byt_blk_avg | Average number of bytes bulk rate in forward direction |
| 55 | fw_pkt_blk_avg | Average number of packets bulk rate in forward direction |
| 56 | fw_blk_rate_avg | Average bulk rate in forward direction |
| 57 | bw_byt_blk_avg | Average number of bytes bulk rate in backward direction |
| 58 | bw_pkt_blk_avg | Average number of packets bulk rate in backward direction |
| 59 | bw_blk_rate_avg | Average bulk rate in backward direction |
| 60 | subfl_fw_pk | Average number of packets in a sub flow (forward) |
| 61 | subfl_fw_byt | Average number of bytes in a sub flow (forward) |
| 62 | subfl_bw_pkt | Average number of packets in a sub flow (backward) |
| 63 | subfl_bw_byt | Average number of bytes in a sub flow (backward) |
| 64 | fw_win_byt | Number of bytes sent in initial window (forward) |
| 65 | bw_win_byt | Number of bytes sent in initial window (backward) |
| 66 | Fw_act_pkt | Number of packets with at least 1 byte of TCP data (forward) |
| 67 | fw_seg_min | Minimum segment size observed in forward direction |
| 68 | atv_avg | Mean time a flow was active before becoming idle |
| 69 | atv_std | Std dev of time a flow was active before becoming idle |
| 70 | atv_max | Maximum time a flow was active before becoming idle |
| 71 | atv_min | Minimum time a flow was active before becoming idle |
| 72 | idl_avg | Mean time a flow was idle before becoming active |
| 73 | idl_std | Std dev of time a flow was idle before becoming active |
| 74 | idl_max | Maximum time a flow was idle before becoming active |
| 75 | idl_min | Minimum time a flow was idle before becoming active |

### Plus additional identification columns:
- FlowID
- Source IP
- Destination IP  
- Source Port
- Destination Port
- Protocol
- Timestamp
- **Label** (the target column for classification)

---

## 17. Known Issues, Limitations & Biases

### Dataset-Level Issues

1. **AWS-Hosted Infrastructure**: All traffic was confined to AWS — network latencies, routing paths, and packet characteristics may differ from on-premises corporate networks.

2. **Synthetic Benign Traffic**: B-Profile-generated traffic, while statistically modeled on real users, may lack the full complexity and unpredictability of actual human behavior.

3. **Limited Attack Duration**: Most attacks lasted 30-90 minutes — real-world attacks can persist for hours, days, or even months (especially APTs).

4. **Class Imbalance**: Benign traffic vastly outnumbers attack traffic, creating significant class imbalance for ML training.

5. **Temporal Patterns**: Attacks only happen on weekdays during business hours — this creates a temporal bias that models might learn to exploit (time-of-day as a feature).

6. **Labeling Accuracy**: Labels are based on time windows and IP addresses — there's potential for:
   - False positives: Benign traffic during attack windows labeled as attack
   - False negatives: Attack traffic outside official windows labeled as benign

7. **Single Attack Per TimeSslot**: Attacks don't overlap — in the real world, multiple attacks may occur simultaneously.

8. **Known Attacker IPs**: All attacker IPs are known and listed — a trivial IP blocklist would stop all attacks, which is unrealistic.

9. **Feature Extraction Limitations**: CICFlowMeter-V3 has known bugs and limitations in flow timeout handling, especially for very long-lived flows.

10. **Missing Heartbleed Data**: The Heartbleed attack details (specific date, exact IPs, start/end times) are less documented than other attacks in the official source.

### Per-Attack Specific Issues

- **Brute-force**: The 90-million-word dictionary is unrealistically large for a real attack (most real attacks use smaller, targeted lists)
- **DoS attacks**: Single-machine DoS against AWS infrastructure may behave differently than against on-premises servers
- **DDoS**: Only 10 attacker machines — real DDoS botnets have thousands to millions of nodes
- **Botnet**: Zeus + Ares combined is unusual — real botnets typically use one malware family
- **Web attacks**: DVWA is intentionally vulnerable — real web applications have more complex and subtle vulnerabilities
- **Infiltration**: Adobe Acrobat Reader 9 is very old — modern attacks use more sophisticated delivery mechanisms (Office macros, PowerShell, etc.)
- **Label typo**: "Infilteration" is misspelled in the dataset and preserved as-is

### Research Community Criticisms

- Some researchers have noted that the **CICFlowMeter** has issues with:
  - Handling bidirectional flows correctly in some edge cases
  - TCP flow timeout values being too aggressive or too lenient
  - Feature calculation inconsistencies between versions (V3 vs V4)
- The dataset was generated in **2018** — attack patterns have evolved significantly since then
- The **AWS network** may introduce artifacts not present in real enterprise networks (e.g., specific MTU values, consistent latency profiles)

---

## Summary of All Attack Tools

| Tool | Type | Language | Target Protocol | Attack Category |
|---|---|---|---|---|
| Patator | Brute-force | Python | FTP, SSH | Brute-Force |
| Heartleech | Exploit | C | TLS/SSL | Heartbleed |
| Zeus (Zbot) | Trojan/Botnet | C++ | HTTP (C2) | Botnet |
| Ares | Botnet | Python | HTTP (C2) | Botnet |
| GoldenEye | DoS | Python | HTTP | DoS |
| Slowloris | DoS | Perl | HTTP | DoS |
| SlowHTTPTest | DoS | C++ | HTTP | DoS |
| Hulk | DoS | Python | HTTP | DoS |
| LOIC | DDoS | C# | HTTP/TCP/UDP | DDoS |
| HOIC | DDoS | BASIC | HTTP | DDoS |
| Selenium (custom) | Web automation | Python/Java | HTTP | Web Attacks |
| DVWA | Vulnerable app | PHP/MySQL | HTTP | Web Attacks (target) |
| Metasploit | Exploit framework | Ruby | Various | Infiltration |
| Nmap | Scanner | C/Lua | TCP/UDP/ICMP | Infiltration (recon) |

---

*Document compiled from official UNB/CIC sources, AWS Open Data Registry, the referenced research paper by Sharafaldin et al. (2018), and tool documentation from their respective repositories.*
