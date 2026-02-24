# Running NIDS

**Start here after setup:** First read [setup/README.md](setup/README.md) and choose which setup to run.

---

## What This Project Does

**NIDS** is a machine learning-based Network Intrusion Detection System that detects attacks in network traffic using a Random Forest classifier trained on the CICIDS2018 dataset.

It can:
1. **Classify live traffic** — capture packets in real-time and detect attacks
2. **Classify batch flows** — analyze CSV files of pre-captured network flows
3. **Train custom models** — retrain the Random Forest from scratch using your own data

---

## Activate Virtual Environment

Before running anything, activate the Python virtual environment:

```bash
# Windows
venv\Scripts\activate.bat

# Linux
source venv/bin/activate
```

---

## Live Network Classification

Capture and classify network traffic in real-time:

```bash
python classification.py
```

### Interface Selection

There are typically many WiFi and Ethernet adapters, so the script has three modes:

**Interactive (default):**
```bash
python classification.py --interface
```
The script shows a numbered list of all available adapters grouped by type (WiFi, Ethernet, Other). You pick by number.

**Auto-detect (fastest):**
```bash
python classification.py
```
Auto-selects first available WiFi, then Ethernet if no WiFi found.

**Explicit adapter:**
```bash
python classification.py --interface "WiFi 6"
```
Use exact adapter name. Get names from:
```bash
python classification.py --list-interfaces
```

### Live Classification Options

| Option | Values | Default | What |
|---|---|---|---|
| `--interface` | adapter name or menu | auto-detect | Network adapter (empty = menu, name = exact) |
| `--duration` | seconds | 120 | Capture duration (120s = 2 min) |
| `--model` | `default` or `all` | `default` | 5-class (default) or 6-class (all) model |
| `--vm` | flag | off | Auto-select VirtualBox/VMware adapter |
| `--debug` | flag | off | Print detailed predictions |

### Examples

```bash
# Auto-detect, 2 min capture, print results
python classification.py

# Interactive interface chooser, 5 min, 6-class model
python classification.py --interface --duration 300 --model all

# Specific adapter, 10 min, save results
python classification.py --interface "Ethernet" --duration 600 --save-flows results.csv

# List available adapters
python classification.py --list-interfaces

# VM mode: auto-select VirtualBox adapter (for attack testing)
python classification.py --vm --duration 300

# Debug mode: see prediction scores
python classification.py --debug
```

---

## Batch Classification

Classify CSV files without live capture. Like interface selection, you either browse a menu or provide a specific file.

**Interactive (default):**
```bash
python classification.py --batch
```
The script scans 4 batch folders and displays CSV files grouped by model/labels. You pick by number:
- `data/default/batch/` — unlabeled, 5-class model
- `data/default/batch_labeled/` — labeled, 5-class model  
- `data/all/batch/` — unlabeled, 6-class model
- `data/all/batch_labeled/` — labeled, 6-class model

Model and labels are auto-detected based on which folder the file is in.

**Explicit file path:**
```bash
python classification.py --batch data/default/batch_labeled/my_flows.csv
```
Use exact file path. Model is auto-detected from folder location. If file has labels, accuracy is calculated.

### Batch Options

| Option | Values | What |
|---|---|---|
| `--batch` | path or menu | Interactive selection (empty) or exact file path |
| `--model` | `default` or `all` | Override model (usually auto-detected from folder) |
| `--save-flows` | filename | Save predictions/results to CSV |

### Examples

```bash
# Interactive: Browse files and pick one
python classification.py --batch

# Classify specific file (model auto-detected from folder)
python classification.py --batch data/default/batch_labeled/my_flows.csv

# Classify and save results
python classification.py --batch data/default/batch/flows.csv --save-flows output.csv

# Force 6-class model even if file is in default folder
python classification.py --batch data/default/batch/flows.csv --model all
```

---

## ML Model Training

Retrain the Random Forest model from scratch:

```bash
python ml_model.py --full
```

This command:
1. Loads the CICIDS2018 dataset (~6GB, 10 CSV files from `data/raw/`)
2. Preprocesses data (cleaning, encoding, SMOTE balancing, feature selection)
3. Trains a Random Forest classifier with hyperparameter tuning
4. Evaluates the model and saves results

**Note:** Run `setup/setup_full/setup_full.bat` (or `.sh`) first to download the dataset.

---

## Attack Simulation (Test Network)

To test NIDS detection, simulate attacks on a target machine:

**Step 1: Prepare victim device**
```bash
sudo ./setup/setup_victim/setup_victim.sh
```

**Step 2: Start NIDS on victim (in separate terminal)**
```bash
python classification.py --duration 600
```

**Step 3: From attacker machine, run attacks**
```bash
python setup/setup_attacker/discover_and_save.py          # Find victim
python setup/setup_attacker/device_attack.py --duration 120
```

---

## Model Selection

| Model | Classes | Use When |
|---|---|---|
| **default** (5-class) | Benign, DoS, DDoS, Brute Force, Botnet | Standard classification |
| **all** (6-class) | Benign + 5 above + Infiltration | Need port scanning detection |

```bash
# Use 5-class (default)
python classification.py --model default

# Use 6-class (all)
python classification.py --model all
```

---

## Output Files

- **Live mode** — results printed to terminal in real-time
- **Batch mode** — results printed after all flows are classified
- **--save-flows** — CSV file with predicted labels (if input was labeled, also shows accuracy)

---

## Performance Notes

- **Live capture** requires Npcap (Windows) or libpcap (Linux) — installed by setup scripts
- **Classification speed** depends on network traffic volume (typically 1000-5000 flows/sec)
- **Training** with full dataset takes 30+ minutes depending on RAM and CPU

---

For detailed setup instructions, see [setup/SETUPS.md](setup/SETUPS.md).
