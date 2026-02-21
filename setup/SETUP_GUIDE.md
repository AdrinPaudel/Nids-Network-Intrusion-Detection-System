# NIDS — Full Setup Guide

Step-by-step instructions to get the NIDS system running from scratch.  
Run each step in order — commands are copy-paste ready.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the Repository](#2-clone-the-repository)
3. [Python Environment Setup](#3-python-environment-setup)
4. [Verify Python Environment](#4-verify-python-environment)
5. [Download the CICIDS2018 Dataset (For Training)](#5-download-the-cicids2018-dataset-for-training)
6. [Fix the Extra-Column CSV File](#6-fix-the-extra-column-csv-file)
7. [Verify CSV Files](#7-verify-csv-files)
8. [Npcap / libpcap Setup (For Live Capture)](#8-npcap--libpcap-setup-for-live-capture)
9. [Configure Training Parameters (Avoid OOM)](#9-configure-training-parameters-avoid-oom)
10. [Run It](#10-run-it)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

| Requirement | Version | Needed For |
|---|---|---|
| **Python** | 3.12 or higher | Everything |
| **Npcap** (Windows) | Latest | Live network capture only |
| **libpcap-dev** (Linux) | Latest | Live network capture only |

> **Java is NOT required.** Live capture uses the Python `cicflowmeter` package (Scapy-based), which is installed automatically via pip.

---

## 2. Clone the Repository

```bash
git clone <repo_url>
cd NIDS
```

---

## 3. Python Environment Setup

You have two options: **automated** or **manual**.

### Option A: Automated (Setup Script)

The `setup.bat` / `setup.sh` scripts create a virtual environment and install all dependencies in one go.

**What they do:**
1. Check Python is installed
2. Check Npcap (Windows) / libpcap (Linux) is installed
3. Create a `venv/` virtual environment
4. Activate it
5. Run `pip install --upgrade pip`
6. Run `pip install -r requirements.txt` (installs cicflowmeter, scapy, scikit-learn, etc.)
7. Test network interface detection

**Windows** (run from project root):
```bash
setup\setup.bat
```

**Linux** (run from project root):
```bash
chmod +x setup/setup.sh
./setup/setup.sh
```

### Option B: Manual

```bash
# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
```

### Important: Activate venv Every Time

Every time you open a new terminal, you must activate the venv:

```bash
# Windows:
venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate
```

You'll know it's active when you see `(venv)` at the start of your prompt.

---

## 4. Verify Python Environment

Run the verification script to confirm everything is installed:

```bash
python setup/verify_environment.py
```

This checks all required packages (including cicflowmeter and scapy), Python version, venv status, and Npcap/libpcap availability.

---

## 5. Download the CICIDS2018 Dataset (For Training)

> **Skip this step if you only want to run classification using the pre-trained model.**

The dataset is ~6 GB total and is NOT included in the repo.

### Where to Download

- **Official page:** [https://www.unb.ca/cic/datasets/ids-2018.html](https://www.unb.ca/cic/datasets/ids-2018.html)
- **AWS mirror:** Check the official page for the current download link

### What to Download

Download **all 10 CSV files** with `TrafficForML_CICFlowMeter` in their names:

| # | File | Size |
|---|---|---|
| 1 | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | ~336 MB |
| 2 | `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | ~318 MB |
| 3 | `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | ~365 MB |
| 4 | `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | **~3.5 GB** |
| 5 | `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | ~103 MB |
| 6 | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | ~359 MB |
| 7 | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | ~365 MB |
| 8 | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | ~342 MB |
| 9 | `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | ~314 MB |
| 10 | `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | ~200 MB |

### Where to Put Them

Place all 10 CSVs in the `data/raw/` folder (it already exists in the repo):

```
NIDS/
└── data/
    └── raw/
        ├── Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
        ├── ...all 10 files...
        └── Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
```

---

## 6. Fix the Extra-Column CSV File

> **⚠️ IMPORTANT — Do this immediately after downloading the dataset.**

The file **`Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`** (the largest one, ~3.5 GB) has **extra columns** that the other 9 files don't have. All 10 files must have the same 80 columns.

Run the fix script:

```bash
python setup/fix_tuesday_csv.py
```

This will:
1. Read column headers from one of the other 9 files as reference
2. Load the Tuesday file
3. Drop the extra columns (keep only the 80 common ones)
4. Overwrite the file

⏱️ Takes ~1-2 minutes (the file is 3.5 GB).

---

## 7. Verify CSV Files

After fixing, verify all 10 files are correct:

```bash
python setup/verify_csv_files.py
```

All files should show **80 columns** and status **OK**.

---

## 8. Npcap / libpcap Setup (For Live Capture)

> **Skip this if you only need batch classification or ML training.**

Live capture uses **Scapy** (via the `cicflowmeter` pip package) to sniff packets. Scapy requires a packet capture library on your OS.

### Windows: Install Npcap

1. Download Npcap from [https://npcap.com](https://npcap.com)
2. Run the installer
3. **IMPORTANT:** Check **"Install Npcap in WinPcap API-compatible Mode"** during installation
4. Complete the installation

### Linux: Install libpcap

```bash
# Ubuntu/Debian:
sudo apt install libpcap-dev

# Fedora/RHEL:
sudo dnf install libpcap-devel

# Arch Linux:
sudo pacman -S libpcap
```

### Linux: Packet Capture Permissions

On Linux, Scapy needs permission to capture raw packets. Grant capability to your Python binary:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

After this, you can run live capture normally without sudo:

```bash
python classification.py --duration 180
```

> **Note:** The setup script (`setup.sh`) will attempt to do this automatically.

---

## 9. Configure Training Parameters (Avoid OOM)

> **⚠️ READ THIS BEFORE RUNNING THE ML PIPELINE — especially if you have ≤16 GB RAM.**

The training dataset is ~16 million rows. Hyperparameter tuning creates multiple copies of data in memory. On machines with limited RAM, the default settings may cause **Out of Memory (OOM)** errors.

### What to Modify

Open **`config.py`** and adjust these values based on your system:

```
File: config.py
Lines: ~257-280 (MODEL TRAINING SETTINGS section)
```

### Key Settings to Reduce for Low RAM

| Setting | Default | Low RAM (≤16 GB) | What It Does |
|---|---|---|---|
| `N_ITER_SEARCH` | `15` | `5` - `8` | Number of hyperparameter combinations to try. Each iteration loads data into memory. Lower = less RAM, fewer combos tested. |
| `CV_FOLDS` | `3` | `2` | Cross-validation folds. Each fold holds a copy of training data. 2 instead of 3 cuts memory by ~33%. |
| `TUNING_SAMPLE_FRACTION` | `0.2` | `0.1` | Fraction of training data used for tuning. 0.1 = 10% instead of 20%. Halves tuning RAM. |

### Hyperparameter Search Space

You can also shrink the search space in `PARAM_DISTRIBUTIONS`:

```python
# Default (config.py line ~269):
PARAM_DISTRIBUTIONS = {
    'n_estimators': [100, 150],       # Try reducing to [100] only
    'max_depth': [20, 25, 30],        # Try [20, 25] or just [25]
    'min_samples_split': [2, 5, 10],  # Try [5, 10]
    'min_samples_leaf': [1, 2, 4],    # Try [2, 4]
    'max_features': ['sqrt', 'log2'], # Try ['sqrt'] only
    'bootstrap': [True],
    'class_weight': ['balanced_subsample', None]  # Try [None] only
}
```

### Recommended Configs Per RAM Size

**32+ GB RAM** — Use defaults, no changes needed.

**16 GB RAM:**
```python
N_ITER_SEARCH = 8
CV_FOLDS = 2
TUNING_SAMPLE_FRACTION = 0.15
```

**8 GB RAM:**
```python
N_ITER_SEARCH = 5
CV_FOLDS = 2
TUNING_SAMPLE_FRACTION = 0.1
PARAM_DISTRIBUTIONS = {
    'n_estimators': [100],
    'max_depth': [20, 25],
    'min_samples_split': [5, 10],
    'min_samples_leaf': [2, 4],
    'max_features': ['sqrt'],
    'bootstrap': [True],
    'class_weight': [None]
}
```

**Or skip tuning entirely:**
```bash
python ml_model.py --module 4 --hypercache
```
This uses cached/default hyperparameters and skips RandomizedSearchCV completely — uses almost no extra RAM.

---

## 10. Run It

### Batch Classification (Quickest Test — No Dataset Needed)

```bash
python classification.py --batch path/to/flows.csv
```

### Live Classification (Requires Npcap/libpcap)

```bash
python classification.py                     # Auto-detect WiFi, 180 seconds
python classification.py --duration 300      # 5 minutes
python classification.py --list-interfaces   # List interfaces
```

### ML Pipeline (Requires Dataset)

```bash
python ml_model.py --full                    # Full pipeline (5-class)
python ml_model.py --full --all              # Full pipeline (6-class)
python ml_model.py --module 4 --hypercache   # Retrain with cached hyperparams (low RAM safe)
```

---

## 11. Troubleshooting

### "Missing required packages" / "Virtual environment not detected"

Activate the venv:
```bash
# Windows:
venv\Scripts\activate
# Linux:
source venv/bin/activate
```

### "No network interfaces found"

- Windows: Install Npcap from https://npcap.com (check "WinPcap API-compatible Mode")
- Linux: Install `libpcap-dev` and grant Python capture permissions (see [Step 8](#8-npcap--libpcap-setup-for-live-capture))
- Try running as Administrator (Windows) or with sudo (Linux)

### Out of Memory during training

- See [Step 9](#9-configure-training-parameters-avoid-oom) for how to reduce RAM usage
- Or use `--hypercache` to skip tuning entirely

### "Label column not found"

- Make sure your CSVs are the correct `TrafficForML_CICFlowMeter` files
- Run `python setup/verify_csv_files.py` to check

### Wrong column count

- Run `python setup/fix_tuesday_csv.py` to fix the Tuesday file
- Then `python setup/verify_csv_files.py` to confirm

---

## Summary Checklist

- [ ] Python 3.12+ installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Environment verified (`python setup/verify_environment.py`)
- [ ] *(For training)* CICIDS2018 dataset downloaded into `data/raw/`
- [ ] *(For training)* Tuesday CSV fixed (`python setup/fix_tuesday_csv.py`)
- [ ] *(For training)* All CSVs verified (`python setup/verify_csv_files.py`)
- [ ] *(For training)* Training parameters adjusted in `config.py` for your RAM
- [ ] *(For live capture, Windows)* Npcap installed with WinPcap compatibility
- [ ] *(For live capture, Linux)* `libpcap-dev` installed, Python has capture permissions
