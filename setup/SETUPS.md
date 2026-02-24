# Setups

4 setup scripts for 4 different things.

---

## `setup_basic/` — Classification (Live + Batch)

Enables real-time and batch classification of network traffic.

```bash
# Windows
setup\setup_basic\setup_basic.bat

# Linux
./setup/setup_basic/setup_basic.sh
```

See [PROJECT_RUN.md](../PROJECT_RUN.md) for how to use this.

---

## `setup_full/` — ML Model Training

Downloads CICIDS2018 dataset (~6GB) and sets up everything needed to retrain the Random Forest model from scratch. The script guides you through dataset download, CSV fixing, and configuring training for your RAM.

```bash
# Windows
setup\setup_full\setup_full.bat

# Linux
./setup/setup_full/setup_full.sh
```

See [PROJECT_RUN.md](../PROJECT_RUN.md) for how to use this.

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

Run this **ON YOUR MACHINE** (the attacker). Installs attack dependencies (paramiko, etc.) and verifies attack scripts.

Includes:
- `device_attack.py` — main attack launcher (DoS, DDoS, Brute Force, Botnet, Infiltration)
- `discover_and_save.py` — scans network to find target devices
- `config.py` — stores target IP and ports (auto-updated by discovery)
- Individual attack modules (_1_dos_attack.py through _5_botnet_behavior.py)

```bash
# Windows
setup\setup_attacker\setup_attacker.bat

# Linux
./setup/setup_attacker/setup_attacker.sh
```

See [PROJECT_RUN.md](../PROJECT_RUN.md) for how to use this.

