# Running NIDS

**Start here after setup:** First read [setup/README.md](setup/README.md) and choose which setup to run.

---

## What This Project Does

**NIDS** is a machine learning-based Network Intrusion Detection System that detects attacks in network traffic using a Random Forest classifier trained on the CICIDS2018 dataset.

It can:
1. **Classify live traffic** — capture packets in real-time and detect attacks
2. **Classify batch flows** — analyze CSV files of pre-captured network flows
3. **Train custom models** — retrain the Random Forest from scratch using your own data
4. **Simulate attacks** — test detection capability on a target device

---

## Before You Start

Activate the Python virtual environment:

```bash
# Windows
venv\Scripts\activate.bat

# Linux
source venv/bin/activate
```

---

## Features & How to Run

### 1. ML Model Training

**When to use:** After running `setup_full`, retrain the Random Forest classifier from scratch using CICIDS2018 dataset.

**Command:**
```bash
python ml_model.py --full
```

**What happens:**
1. Loads CICIDS2018 dataset (~6GB, 10 CSV files from `data/raw/`)
2. Preprocesses data (cleaning, encoding, SMOTE balancing, feature selection)
3. Trains Random Forest classifier with hyperparameter tuning
4. Evaluates on test set and saves results to `trained_model/`

**Note:** Run `setup/setup_full/setup_full.bat` (or `.sh`) first to download the dataset.

---

### 2. Batch Classification

**When to use:** Classify pre-captured network flows from CSV files (no live packet capture needed).

**Interactive mode (browse and pick file):**
```bash
python classification.py --batch
```

**Explicit file path:**
```
python classification.py --batch data/default/batch_labeled/my_flows.csv
```

**What happens:**
- Scans 4 batch folders:
  - `data/default/batch/` — unlabeled, 5-class model
  - `data/default/batch_labeled/` — labeled, 5-class model  
  - `data/all/batch/` — unlabeled, 6-class model
  - `data/all/batch_labeled/` — labeled, 6-class model
- Auto-detects model and labels based on folder
- Prints predictions; calculates accuracy if labels exist

**Options:**

| Option | Values | What |
|---|---|---|
| `--batch` | path or menu | Interactive (empty) or exact file path |
| `--model` | `default` or `all` | Override model (usually auto-detected) |

**Examples:**
```bash
# Interactive: Browse files and pick one
python classification.py --batch

# Classify specific file
python classification.py --batch data/default/batch_labeled/my_flows.csv

# Force 6-class model
python classification.py --batch data/default/batch/flows.csv --model all
```

---

### 3. Live Network Classification

**When to use:** Capture and classify network traffic in real-time from a live interface.

**Command:**
```bash
python classification.py
```

**What happens:**
- Shows interactive menu to pick network adapter
- Captures packets for 120 seconds (default)
- Classifies flows in real-time
- Prints results to terminal

**Interface Selection**

3 modes to pick a network adapter:

**Interactive menu — default (what you get when you run with no args):**
```bash
python classification.py
```
Shows numbered list of all adapters (WiFi, Ethernet, Other). You pick by number.

**Explicit adapter name:**
```bash
python classification.py --interface "WiFi 6"
```
Uses exact adapter name (get names with `--list-interfaces`, don't show a menu).

**List available adapters:**
```bash
python classification.py --list-interfaces
```
Just shows adapters and exits, doesn't run classification.

**VM mode — actual auto-select:**
```bash
python classification.py --vm
```
Auto-detects VirtualBox/VMware adapter without showing menu (useful for automated testing).

**Options:**

| Option | Values | Default | What |
|---|---|---|---|
| `--interface` | adapter name | none | Explicit adapter name (shows menu if not provided) |
| `--list-interfaces` | flag | off | List adapters and exit |
| `--duration` | seconds | 120 | How long to capture (120s = 2 min) |
| `--model` | `default` or `all` | `default` | 5-class or 6-class model |
| `--vm` | flag | off | Auto-detect VirtualBox/VMware adapter (no menu) |
| `--debug` | flag | off | Print detailed prediction scores |

**Examples:**
```bash
# Interactive menu (default), 2 min capture
python classification.py

# Interactive menu, 5 min, 6-class model
python classification.py --duration 300 --model all

# Specify exact adapter (no menu), 10 min
python classification.py --interface "Ethernet" --duration 600

# List available adapters
python classification.py --list-interfaces

# VM mode auto-select (no menu), 5 min
python classification.py --vm --duration 300

# Debug mode: see prediction scores
python classification.py --debug
```

---

### 4. Attack Simulation

**When to use:** Test NIDS detection by simulating real attacks on a victim device (VM or server).

**Prerequisites:** Before starting attacks, run setup on **attacker machine**:
```bash
# Windows
setup\setup_attacker\setup_attacker.bat

# Linux
./setup/setup_attacker/setup_attacker.sh
```
This installs paramiko, scapy, and other attack dependencies.

**Step 1: Prepare victim device**

Run on the device you want to attack (VM, server, etc.):
```bash
# Windows (Run as Administrator)
setup\setup_victim\setup_victim.bat

# Linux
sudo ./setup/setup_victim/setup_victim.sh
```
This sets up SSH, HTTP, FTP, Firewall, and NIDS project files.

**Step 2: Start NIDS on victim (separate terminal)**

Keep this running while you attack:
```bash
python classification.py --duration 600
```
Captures and classifies for 10 minutes.

**Step 3: Find victim device (attacker machine)**

From your attacker machine, scan the network:
```bash
python setup/setup_attacker/discover_and_save.py
```
Saves victim IP to `setup/setup_attacker/config.py`

**Step 4: Launch attacks (attacker machine)**

From your attacker machine, run attacks:
```bash
python setup/setup_attacker/device_attack.py
```

**Attack options:**

| Option | What |
|---|---|
| `--dos` | DoS attack only |
| `--ddos` | DDoS attack only |
| `--brute` | SSH Brute Force only |
| `--botnet` | Botnet simulation only |
| `--infiltration` | Infiltration/port scan only |
| `--duration` | How long to attack (seconds) |
| `--all` | Run all 6 attacks in sequence |

**Examples:**
```bash
# Run default attacks (shuffled, 120s default)
python setup/setup_attacker/device_attack.py

# Just DoS for 60 seconds
python setup/setup_attacker/device_attack.py --dos --duration 60

# All attacks for 5 minutes
python setup/setup_attacker/device_attack.py --all --duration 300

# Only DDoS and Brute Force
python setup/setup_attacker/device_attack.py --ddos --brute
```

**Result:** NIDS on victim detects and classifies attacks in real-time. View results in terminal where NIDS is running.

---

## Models & Output

**Available Models:**

| Model | Classes | Use When |
|---|---|---|
| **default** (5-class) | Benign, DoS, DDoS, Brute Force, Botnet | Standard classification |
| **all** (6-class) | Benign + 5 above + Infiltration | Need port scanning detection |

**Output:**
- **Live mode** — results printed to terminal in real-time; also saved to `reports/` folder as text files
- **Batch mode** — results printed after all flows are classified

---

## Performance Notes

- **Live capture** requires Npcap (Windows) or libpcap (Linux) — installed by setup scripts
- **Classification speed** depends on network traffic volume (typically 1000-5000 flows/sec)
- **Training** with full dataset takes 30+ minutes depending on RAM and CPU

---

For detailed setup instructions, see [setup/SETUPS.md](setup/SETUPS.md).
