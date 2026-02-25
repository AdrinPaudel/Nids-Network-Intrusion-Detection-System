# Testing and Deployment Guide - CICIDS2018 Exact Replication

## Overview

All attack code has been updated to **exactly match CICIDS2018 dataset specifications**. This guide walks you through setting up two VMs and running authenticated attacks that should generate flows properly classified by the NIDS model.

---

## System Setup

### VM 1: Attacker
**OS:** Ubuntu 22.04 LTS (or Kali Linux)
**Role:** Generate attack traffic using exact CICIDS2018 tools and parameters
**Required:** SSH access, Python 3.8+, attack scripts

### VM 2: Victim
**OS:** Ubuntu 22.04 LTS
**Role:** Victim server running SSH, HTTP, FTP services
**Required:** Services listening on ports 22 (SSH), 80 (HTTP), 21 (FTP)

### VM 3 (Optional): Monitoring
**Role:** Classification and flow analysis (can be same physical machine as attacker)
**Required:** CICFlowMeter, classification model

---

## Step 1: Prepare Victim VM (Ubuntu Server)

### 1.1 Install Required Services

```bash
# Install and start SSH
sudo apt update
sudo apt install -y openssh-server
sudo systemctl start ssh
sudo systemctl status ssh

# Install HTTP server (Apache)
sudo apt install -y apache2
sudo systemctl start apache2
sudo systemctl status apache2

# Install FTP server (vsftpd)
sudo apt install -y vsftpd
sudo systemctl start vsftpd
sudo systemctl status vsftpd

# Verify ports are listening
ss -tlnp | grep -E ':21|:22|:80'
# Expected output:
#   LISTEN 0 128 0.0.0.0:21 0.0.0.0:* users:(("vsftpd",pid=XXXX))
#   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=XXXX))
#   LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=XXXX))
```

### 1.2 Configure Network (if needed)

```bash
# Make sure victim has stable IP address
# Note victim IP for later (e.g., 192.168.1.100)
ip addr show | grep "inet " | grep -v 127.0.0.1
```

---

## Step 2: Prepare Attacker VM (Ubuntu/Kali)

### 2.1 Setup Environment

```bash
# Copy attack scripts from this project
cd ~/nids-attack
# Ensure you have all files:
#   setup/setup_attacker/device_attack.py
#   setup/setup_attacker/_1_dos_attack.py
#   setup/setup_attacker/_2_ddos_simulation.py
#   setup/setup_attacker/_3_brute_force_ssh.py
#   setup/setup_attacker/_5_botnet_behavior.py

# Install Python dependencies
pip install paramiko

# Verify TCP timestamps are enabled (CRITICAL!)
cat /proc/sys/net/ipv4/tcp_timestamps
# Expected output: 1
# If output is 0, enable:
# sudo sysctl -w net.ipv4.tcp_timestamps=1
# sudo sysctl -p
```

### 2.2 Run Setup Script (Optional, if not already done)

```bash
# From the setup_attacker directory
cd setup/setup_attacker
chmod +x setup_attacker.sh

# This script enables TCP timestamps if needed
sudo bash setup_attacker.sh
```

---

## Step 3: Run Attacks from Attacker VM

### 3.1 Interactive Mode (Recommended for Testing)

```bash
cd setup/setup_attacker

# Run the interactive attack generator
python device_attack.py --duration 300

# Will prompt you for:
# - Target IP: Enter victim IP (e.g., 192.168.1.100)
# - Target ports: Enter exact ports listening on victim
# - Attacks: Select which attacks to run
```

### 3.2 Command Line Mode

```bash
# Or run directly with command line options
python device_attack.py --duration 300 --default --no-shuffle
# Then enter victim IP when prompted
```

### 3.3 Expected Output

```
[*] NIDS Attack Generator - Interactive Mode

[*] Attack sequence:
[*] Target: 192.168.1.100
[*] Ports - SSH: 22, HTTP: 80, FTP: 21
[*] Total duration: 300s
[*] Attacks: dos, ddos, brute_force, botnet
[*] Time per attack: 75s each
[*] Shuffled: True

[>>> Attack 1/4] Starting DDOS
[>>>] Target: 192.168.1.100:80
[>>>] Duration: 75s
[>>>] Threads: 10 (matching CICIDS2018 intensity)

[DDoS] Starting attack on 192.168.1.100:80 for 75s
[DDoS] Techniques: LOIC-HTTP + LOIC-UDP + HOIC
[DDoS] Using 10 threads (throttled from 10 to reduce flow rate)

... attack runs for the specified duration ...

[DDoS] Attack completed in 75.23s — Sent 1247 packets
```

---

## Step 4: Capture and Analyze Flows (Optional, for Verification)

### 4.1 While Attack is Running (On Monitoring Machine)

In a **separate terminal**, capture flows to verify they match training data:

```bash
cd ~
python capture_flows.py

# Output will show:
# Capturing flows to flows_capture.csv...
# Press Ctrl+C to stop

# After Ctrl+C:
# Captured and saved 1247 flows to flows_capture.csv
```

### 4.2 Analyze Captured Flows

```bash
python analyze_flows.py flows_capture.csv

# Output will show:
# – Analyzing flows_capture.csv...
# – Total flows: 1247
# – TCP flows: 1061 (85.1%)
# – UDP flows: 186 (14.9%)
# – Port distribution: 882 to port 80 (70.7%)
# – Fwd Seg Size Min range: [20, 32]
# – Init Fwd Win Byts range: [8192, 8192]
#   (All flows using 8192, matching training data 56.8%)
```

### 4.3 Compare with Training Data

```bash
python compare_flows.py flows_capture.csv training_dataset.csv

# Output will show feature matching:
# Features Analysis:
# – Feature 'Init Fwd Win Byts' match: GOOD (8192 = 8192)
# – Feature 'Fwd Seg Size Min' match: GOOD (32 = 32)
# – Feature 'Tot Fwd Pkts' distribution match: GOOD
# – ...
```

---

## Step 5: Run Classification on Captured Flows

### 5.1 Run Classification

```bash
# From project root
python classification.py --input flows_capture.csv --model trained_model

# Output will show:
# Detected attack types:
# - DoS Hulk: 234 flows (18.8%)
# - DoS Slowloris: 156 flows (12.5%)
# - DoS GoldenEye: 189 flows (15.2%)
# - DDoS LOIC-HTTP: 267 flows (21.4%)
# - DDoS LOIC-UDP: 198 flows (15.9%)
# - Brute Force SSH: 78 flows (6.2%)
# - Botnet C2: 45 flows (3.6%)
# - Benign: 80 flows (6.4%)

# Goal: MINIMIZE Benign percentage, MAXIMIZE attack detection
```

---

## Key Parameters Recap

### ✅ Guaranteed CICIDS2018 Matching Parameters

| Parameter | Value | Why |
|-----------|-------|-----|
| SO_RCVBUF | 8192 | Training data mode (56.8% of TCP flows) |
| TCP_NODELAY | 1 | Reduces TCP buffering delays |
| TCP Timestamps | Enabled | Required for Fwd Seg Size Min = 32 |
| HULK Throttle | 2-3s | Between NEW connections |
| GoldenEye Throttle | 2-3s | Between NEW connections |
| Slowloris Headers | INCOMPLETE | Never sends final \r\n\r\n |
| Slowloris Keep-alive | 10-15s | Between keep-alive payloads |
| GoldenEye GET/POST | 60%/40% | Exact CICIDS2018 ratio |
| Slowloris Connections | 50-150 | Maintained throughout attack |
| SlowHTTPTest Sockets | 50 | Keep-alive POST drip pools |
| SlowHTTPTest Drip | 1-10 bytes/1-3s | Slow body transmission |
| LOIC-HTTP Requests | 1-5 per connection | Reduced from 20-200 |
| LOIC-HTTP Threads | 10 | DDoS distribution |
| LOIC-UDP Payload | 512/1024/1400 | Random per packet |
| LOIC-UDP Burst | 0.3-0.5s delay | Creates ~2-3 flows/sec |
| Botnet C2 Interval | 3-8s | Between beacons |
| Brute Force Users | 25+ | Patator wordlist |
| Brute Force Passwords | 30+ | Patator wordlist |

---

## Troubleshooting

### Attack Runs But All Flows Are Benign

**Possible Causes:**
1. SO_RCVBUF not set to 8192 - verify with:
   ```bash
   python setup/setup_attacker/_1_dos_attack.py
   # Check output for "_RCVBUF_* = 8192"
   ```

2. TCP timestamps not enabled on attacker:
   ```bash
   cat /proc/sys/net/ipv4/tcp_timestamps
   # Must be 1
   ```

3. Victim services not running:
   ```bash
   nc -zv 192.168.1.100 80 22 21
   # All should show "succeeded"
   ```

4. Firewall blocking traffic:
   ```bash
   sudo ufw status
   sudo ufw allow 80,443,8080,8888/tcp
   ```

### Attack Doesn't Start

**Check:**
```bash
# Is Python installed?
python3 --version

# Are imports available?
python3 -c "import paramiko; print('OK')"

# Can you reach victim?
ping 192.168.1.100
telnet 192.168.1.100 80
```

### Flows Captured But Still Misclassified

**Possible Causes:**
1. Model trained on different OS (Windows vs Linux) - init window sizes differ
2. TCP window scaling enabled on victim - use sysctl to disable if needed
3. Network path modifying packets (MTU issues, proxies, etc.)

**Verify:**
```bash
# Check flow features
python analyze_flows.py flows_capture.csv | grep -E "Init Fwd Win|Fwd Seg Size"

# Compare with training data:
python check_training_windows.py
```

---

## Expected Results

After running attacks **correctly configured**:

✅ **Init Fwd Win Byts** should be 8192 (95%+ of flows)
✅ **Fwd Seg Size Min** should be 32 (with TCP timestamps)
✅ **Attack flows** should be classified as Hulk/Slowloris/GoldenEye/Slowhttp/LOIC at 85%+ accuracy
✅ **Benign flows** should be < 15% of total
✅ **Tot Fwd Pkts** should match training data distributions:
  - HULK: 2-3 packets
  - Slowloris: 5-20 packets
  - SlowHTTPTest: 20-50+ packets

---

## Next Steps

1. **Run attacks on both VMs** with this exact configuration
2. **Capture flows** using `capture_flows.py` (no classification)
3. **Analyze** using `analyze_flows.py` to verify feature matching
4. **Compare** using `compare_flows.py` to confirm training data alignment
5. **Classify** and check for >85% attack detection
6. **Iterate** if needed - if still misclassified, check flow features first

---

## File Locations

```
z:\Nids\
├── CICIDS2018_ATTACK_PARAMETERS.md      # Exact specifications used
├── CICIDS2018_DATASET_METHODOLOGY.md    # Background/context
├── ATTACK_IMPLEMENTATION_STATUS.md      # Status of each attack
├── setup/setup_attacker/
│   ├── device_attack.py                 # Main orchestrator (UPDATED: thread counts)
│   ├── _1_dos_attack.py                 # DoS attacks (UPDATED: GoldenEye throttle)
│   ├── _2_ddos_simulation.py            # DDoS attacks (verified correct)
│   ├── _3_brute_force_ssh.py            # Brute force (paramiko)
│   ├── _5_botnet_behavior.py            # Botnet (verified correct)
│   └── setup_attacker.sh                # TCP timestamps setup
├── capture_flows.py                     # Flow capture tool
├── analyze_flows.py                     # Flow analysis tool
└── compare_flows.py                     # Training data comparison
```

---

## References

- CICIDS2018: Canadian Institute for Cybersecurity Intrusion Detection Dataset
- CICFlowMeter: Flow feature extraction and labeling tool
- Paramiko: SSH protocol for brute force implementation
