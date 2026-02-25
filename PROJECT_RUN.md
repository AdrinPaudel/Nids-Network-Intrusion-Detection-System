# Running NIDS

## ⚠️ IMPORTANT: Attacks Must Be Launched From Linux

**The NIDS model was trained on attack traffic generated from Linux (Kali). Attacks launched from Windows will be misclassified as Benign (2nd choice shows correct attack type).**

If you're attacking:
1. Use a Linux machine or Linux VM (e.g., Ubuntu in VirtualBox)
2. Set up using: `./setup/setup_attacker/setup_attacker.sh`
3. Use attack tools: hping3, slowhttptest, hydra (matching training data)

---

**Start here:** Choose a setup below, then follow the steps for what you want to do.

---

## What This Project Does

**NIDS** is a machine learning-based Network Intrusion Detection System that detects attacks in network traffic using a Random Forest classifier trained on the CICIDS2018 dataset.

It can:
1. **Classify live traffic** (5-class or 6-class model)
2. **Classify batch flows** from CSV files (5-class or 6-class model)
3. **Train custom models** from scratch (5-class or 6-class)
4. **Simulate attacks** on a victim device

---

## What You Can Do

### 1. **Live Network Classification** (Capture packets in real-time)

Models available:
- **5-class** (default): Benign, DoS, DDoS, Brute Force, Botnet
- **6-class** (with Infilteration): 5-class + Infiltration

Required setup: **setup_basic**

### 2. **Batch Classification** (Classify CSV files of network flows)

Models available:
- **5-class** (default)
- **6-class** (with Infilteration)

Required setup: **setup_basic**

### 3. **Model Training (5-class)** (Retrain from scratch, removes Infilteration class)

Required setup: **setup_full** (downloads ~6GB dataset)

### 4. **Model Training (6-class)** (Retrain from scratch, keeps all classes including Infilteration)

Required setup: **setup_full** (downloads ~6GB dataset)

### 5. **Attack Simulation** (Simulate attacks on a victim device)

Required setup:
- **setup_victim** (on the device to be attacked)
- **setup_attacker** (on your machine launching attacks)

---

## Before You Start

**Windows:**
```bash
venv\Scripts\activate.bat
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

### Linux: When You Need `sudo`

Live packet capture on Linux requires elevated privileges (root). Here are the options:

**Option 1: Use `sudo` for each run (simplest)**
```bash
sudo ./venv/bin/python classification.py
```
Do NOT activate venv first - you can't activate with sudo easily.

**Option 2: Grant capabilities once (recommended)**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```
Then use normally without sudo:
```bash
source venv/bin/activate
python classification.py
```

**Which commands need `sudo`?**
- ✅ **Live classification** — YES (packet capture requires root)
- ✅ **Model training** — NO
- ✅ **Batch classification** — NO
- ✅ **Victim setup** — YES (modifying firewall, SSH, system services)
- ✅ **Attacker setup** — NO
- ✅ **Attack simulation** — YES (crafting/sending packets requires root)

---

## Setup Scripts

### Option 1: setup_basic (for Classification Only)

**What it does:**
- Creates Python virtual environment
- Installs packages for live and batch classification
- Checks for Npcap/libpcap (needed for live capture)
- Does NOT download the 6GB CICIDS2018 dataset

**Use this if:** You want to classify traffic using the pre-trained models.

**Run:**

**Windows (simplest - just click):**
```
Double-click: setup\setup_basic\setup_basic.bat
```

**Linux/macOS:**
```bash
sh ./setup/setup_basic/setup_basic.sh
```

After setup:
```bash
# Windows
venv\Scripts\activate.bat

# Linux/macOS
source venv/bin/activate
```

---

### Option 2: setup_full (for Training Models)

**What it does:**
- Does everything setup_basic does
- Downloads CICIDS2018 dataset (~6GB, 10 CSV files)
- Fixes known issues in Tuesday CSV
- Verifies all CSV files

**Use this if:** You want to retrain the Random Forest model from scratch.

**Run:**

**Windows (simplest - just click):**
```
Double-click: setup\setup_full\setup_full.bat
```

**Linux/macOS:**
```bash
sh ./setup/setup_full/setup_full.sh
```

The script will ask you to:
1. Download the dataset (offers links to UNB or Kaggle)
2. Place all 10 CSV files in `data/raw/`
3. Press Enter when done

After setup:
```bash
# Windows
venv\Scripts\activate.bat

# Linux/macOS
source venv/bin/activate
```

---

## Steps to Run Each Feature

### Feature 1: Live Network Classification

**Requirements:**
- ✅ Completed: `setup_basic`
- Pre-trained models already available (trained_model/, trained_model_all/)
- Npcap (Windows) or libpcap (Linux)

**What happens:**
1. Captures live network traffic for a specified duration
2. Groups packets into flows
3. Extracts features from flows (1000+ network metrics)
4. Classifies each flow as Benign or Attack
5. Prints results to terminal and saves to `reports/`

**Choose your model:**

| Model | Classes | Command |
|---|---|---|
| **Default (5-class)** | Benign, DoS, DDoS, Brute Force, Botnet | `python classification.py` |
| **All (6-class)** | Above + Infilteration | `python classification.py --model all` |

**Basic command:**
```bash
# Interactive mode: menu to pick network adapter
python classification.py

# 5 minutes capture with default model
python classification.py --duration 300

# Use 6-class model
python classification.py --model all

# Use 6-class model for 5 minutes
python classification.py --model all --duration 300
```

**Full options:**

| Option | Values | Default | What |
|---|---|---|---|
| `--duration` | seconds | 120 | How long to capture |
| `--model` | `default` or `all` | `default` | 5-class or 6-class |
| `--interface` | adapter name | interactive menu | Explicit adapter name |
| `--list-interfaces` | flag | off | List adapters and exit |
| `--vm` | flag | off | Auto-detect VirtualBox/VMware adapter |
| `--debug` | flag | off | Print detailed prediction scores |

**Examples:**
```bash
# Interactive menu, 120 seconds (default)
python classification.py

# Specific adapter, 5 minutes, debug mode
python classification.py --interface "Ethernet" --duration 300 --debug

# VM mode, 10 min, 6-class model 
python classification.py --vm --duration 600 --model all

# List adapters
python classification.py --list-interfaces
```

---

### Feature 2: Batch Classification

**Requirements:**
- ✅ Completed: `setup_basic`
- Pre-trained models already available (trained_model/, trained_model_all/)
- CSV files with network flows (`data/default/batch/` or `data/default/batch_labeled/`)

**What happens:**
1. Reads pre-captured network flows from a CSV file
2. Extracts features (same as live mode)
3. Classifies all flows
4. Prints results and accuracy (if file has labels)

**Choose your model:**

| Model | Classes | Use When |
|---|---|---|
| **Default (5-class)** | Benign, DoS, DDoS, Brute Force, Botnet | Standard classification |
| **All (6-class)** | Above + Infilteration | Need port scanning detection |

**Basic command:**
```bash
# Interactive: browse and pick file
python classification.py --batch

# Classify specific file
python classification.py --batch data/default/batch_labeled/file.csv

# Use 6-class model
python classification.py --batch data/default/batch_labeled/file.csv --model all
```

**Full options:**

| Option | Values | What |
|---|---|---|
| `--batch` | path or empty | Leave empty for interactive menu, or provide CSV file path |
| `--model` | `default` or `all` | Override model (usually auto-detected from folder) |

**Examples:**
```bash
# Interactive: select from available files
python classification.py --batch

# Classify unlabeled file with default model
python classification.py --batch data/default/batch/flows.csv

# Classify labeled file with 6-class model
python classification.py --batch data/default/batch_labeled/flows.csv --model all

# Force all model on unlabeled file
python classification.py --batch data/default/batch/flows.csv --model all
```

**Supported batch folders:**
- `data/default/batch/` — unlabeled flows, uses 5-class model
- `data/default/batch_labeled/` — labeled flows, uses 5-class model
- `data/all/batch/` — unlabeled flows, uses 6-class model
- `data/all/batch_labeled/` — labeled flows, uses 6-class model

---

### Feature 3: Model Training (5-class)

**Requirements:**
- ✅ Completed: `setup_full` (downloads 6GB dataset)
- Data/raw/ contains 10 CSV files of CICIDS2018 dataset
- ~30 minutes + 8GB RAM

**What happens:**

**Module 1: Data Loading**
- Loads all 10 CSV files from `data/raw/`
- Combines into single dataset (~5M rows)
- Saves checkpoint to `data/combined/`

**Module 2: Data Exploration**
- Analyzes attack distribution
- Checks for missing values, correlations
- Saves exploration stats to `results/exploration/`

**Module 3: Data Preprocessing**
- Removes Infilteration rows (→ 5 classes)
- Cleans missing values, encodes categorical features
- Balances classes with SMOTE
- Selects top features using Random Forest
- Saves to `data/preprocessed/`

**Module 4: Model Training**
- Train Random Forest with hyperparameter tuning
- Tests on split test set  
- Saves model to `trained_model/`

**Module 5: Model Testing**
- Evaluates on test set
- Computes confusion matrix, precision, recall, F1
- Saves results to `results/training/`

**Training options:**

| Option | What | Time |
|---|---|---|
| `--full` | Run all modules (1-5) | ~40 min |
| `--module 1` | Load data only | ~5 min |
| `--module 2` | Explore data only | ~2 min |
| `--module 3` | Preprocess only | ~15 min |
| `--module 4` | Train model | ~15 min |
| `--module 5` | Test model | ~5 min |
| `--module 3 4 5` | Preprocess + train + test | ~30 min |

**Full training (5-class):**
```bash
python ml_model.py --full
```

**Run specific modules:**
```bash
# Just load data
python ml_model.py --module 1

# Preprocess only
python ml_model.py --module 3

# Preprocess + train
python ml_model.py --module 3 4

# Train + test (uses existing preprocessed data)
python ml_model.py --module 4 5
```

---

### Feature 4: Model Training (6-class)

**Requirements:**
- ✅ Completed: `setup_full`
- Data/raw/ contains 10 CSV files
- Same time as 5-class (~30 minutes + 8GB RAM)

**Difference from 5-class:**
- ✅ Keeps Infilteration class (6 total classes instead of 5)
- ✅ Better for detecting port scanning attacks
- ❌ Slightly lower accuracy on balanced dataset

**Full training (6-class):**
```bash
python ml_model.py --full --all
```

**Run specific modules (6-class):**
```bash
# Preprocess keeping all classes
python ml_model.py --module 3 --all

# Full pipeline with all classes
python ml_model.py --full --all

# Train + test (6-class)
python ml_model.py --module 4 5 --all
```

**Models saved:**
- 5-class: `trained_model/` (default)
- 6-class: `trained_model_all/` (with --all flag)

---

### Feature 5: Attack Simulation

**Requirements:**
- `setup_victim` (on target device - run FIRST)
- `setup_attacker` (on attacking machine - run SECOND)

**Step 1: Prepare victim device**

Run on the device you want to attack (VM, server, etc.):

**Windows (Run as Administrator - right-click and select "Run as administrator"):**
```
Right-click → Run as administrator: setup\setup_victim\setup_victim.bat
```

**Linux:**
```bash
sudo sh ./setup/setup_victim/setup_victim.sh
```

This sets up:
- SSH, HTTP, FTP servers (attack targets)
- Firewall rules (open ports)
- Npcap/libpcap (so NIDS can capture)
- NIDS project files + trained model

---

**Step 2: Prepare attacker machine**

Run setup_attacker on your machine (the one launching attacks):

**Windows (simplest - just click):**
```
Double-click: setup\setup_attacker\setup_attacker.bat
```

**Linux:**
```bash
sh ./setup/setup_attacker/setup_attacker.sh
```

This installs attack dependencies (paramiko, psutil, etc.).

---

**Step 3: Start NIDS on victim (separate terminal on victim machine)**

Keep this running while you attack:

```bash
# Windows
python classification.py --duration 600

# Linux: Use sudo (or grant capabilities - see Prerequisites above)
sudo ./venv/bin/python classification.py --duration 600
```

Captures for 10 minutes (600 seconds).

---

**Step 4: Launch attacks (from attacker machine)**

Run the attack script. **It will prompt you for IP and port:**

```bash
# Windows
python setup/setup_attacker/device_attack.py --dos --duration 100
```

Then enter:
```
[*] NIDS Attack Generator - Interactive Mode

[*] Enter target information:
[?] Enter target IP address: 192.168.1.104
[?] Enter target port (default 80): 80
```

**Attack types and options:**

| Option | What | Example |
|---|---|---|
| (no args) | Default: DoS, DDoS, Brute Force, Botnet (shuffled) | `python device_attack.py` |
| `--default` | 5-class attacks (exclude Infiltration) | `python device_attack.py --default` |
| `--all` | All 6 attacks (include Infiltration) | `python device_attack.py --all` |
| `--dos` | DoS attack only | `python device_attack.py --dos` |
| `--ddos` | DDoS attack only | `python device_attack.py --ddos` |
| `--brute-force` | SSH Brute Force only | `python device_attack.py --brute-force` |
| `--botnet` | Botnet simulation only | `python device_attack.py --botnet` |
| `--infiltration` | Port scanning only | `python device_attack.py --infiltration` |
| `--duration` | How long to attack (seconds) | `python device_attack.py --duration 300` |
| `--no-shuffle` | Don't shuffle attack order | `python device_attack.py --no-shuffle` |

**Examples:**

```bash
# Default attacks (120 seconds) - will prompt for IP and port
python setup/setup_attacker/device_attack.py

# DoS attack only (60 seconds)
python setup/setup_attacker/device_attack.py --dos --duration 60

# All attacks including port scanning (5 minutes)
python setup/setup_attacker/device_attack.py --all --duration 300

# DDoS + Brute Force in order (no shuffle)
python setup/setup_attacker/device_attack.py --ddos --brute-force --no-shuffle --duration 180
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
