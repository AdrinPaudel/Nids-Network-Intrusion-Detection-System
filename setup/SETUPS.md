# Setups

4 setup scripts for 4 different things.

---

## `setup_basic/` — Classification (Live + Batch)

For running the NIDS to classify network traffic. Sets up everything needed for:
- **Live classification** — capture packets in real-time and classify them (5-class model: Benign, DoS, DDoS, Brute Force, Botnet)
- **Batch classification** — feed a CSV of pre-captured flows and classify them

```bash
# Windows
setup\setup_basic\setup_basic.bat

# Linux
./setup/setup_basic/setup_basic.sh
```

After setup:
```bash
python classification.py                                    # Live capture (120s default)
python classification.py --batch setup/sample_batch.csv     # Batch mode
```

---

## `setup_full/` — ML Model Training

Everything in basic setup PLUS what you need to retrain the Random Forest model from scratch using the CICIDS2018 dataset (~6GB).

```bash
# Windows
setup\setup_full\setup_full.bat

# Linux
./setup/setup_full/setup_full.sh
```

The script walks you through downloading the dataset, fixing the Tuesday CSV bug, and configuring training for your RAM size.

After setup:
```bash
python ml_model.py --full     # Full pipeline: load → preprocess → train → test
```

---

## `setup_victim/` — Prep a Device to Be Attacked

Run this **ON THE DEVICE YOU WANT TO ATTACK** (a VM or server). It checks and sets up:
- SSH server (port 22) — needed for Brute Force attacks
- Web server (port 80) — needed for DoS and DDoS attacks
- FTP server (port 21) — needed for FTP Brute Force
- Firewall rules — opens the ports above
- Packet capture (Npcap/libpcap) — so the NIDS can sniff traffic on the victim
- NIDS project files + trained model — so you can run classification on the victim

It asks before installing or changing anything.

```bash
# Windows (Run as Administrator)
setup\setup_victim\setup_victim.bat

# Linux
sudo ./setup/setup_victim/setup_victim.sh

# Or directly with Python (either OS)
sudo python setup/setup_victim/setup_victim.py
```

---

## `setup_attacker/` — Prep Your Machine to Launch Attacks

Run this **ON YOUR MACHINE** (the attacker). It installs the attack dependencies (paramiko for SSH, etc.) and verifies the attack scripts are in place.

All the attack scripts live in this folder:
- `device_attack.py` — main attack launcher (DoS, DDoS, Brute Force, Botnet, Infiltration)
- `discover_and_save.py` — scans the network to find your victim device
- `config.py` — stores the target IP and ports (auto-updated by discover_and_save.py)
- `_1_dos_attack.py` through `_5_botnet_behavior.py` — individual attack modules

```bash
# Windows
setup\setup_attacker\setup_attacker.bat

# Linux
./setup/setup_attacker/setup_attacker.sh
```

After setup:
```bash
python setup/setup_attacker/discover_and_save.py                    # Find victim on network
python setup/setup_attacker/device_attack.py                        # Run default attacks (5-class)
python setup/setup_attacker/device_attack.py --dos --duration 60    # Just DoS for 60s
python setup/setup_attacker/device_attack.py --all --duration 300   # All 6 attacks for 5min
```

---

## Typical Workflow: Attack Testing

**Step 1 — On the victim device (VM/server):**
```bash
sudo ./setup/setup_victim/setup_victim.sh       # Set up SSH, HTTP, FTP
python classification.py --duration 600          # Start NIDS (captures for 10 min)
```

**Step 2 — On your machine (attacker):**
```bash
setup\setup_attacker\setup_attacker.bat                     # Install attack deps
python setup\setup_attacker\discover_and_save.py            # Find the victim
python setup\setup_attacker\device_attack.py --duration 120 # Attack for 2 min
```

The NIDS on the victim will detect and classify the attacks in real-time.

---

## Other Files

| File | What |
|---|---|
| `sample_batch.csv` | Example CSV for batch classification |
