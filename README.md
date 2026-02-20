# NIDS — Network Intrusion Detection System

A machine learning-based Network Intrusion Detection System built on the **CICIDS2018** dataset. Uses a Random Forest classifier to detect network attacks in real-time or from batch CSV files.

## What It Does

- **ML Pipeline** — Loads the CICIDS2018 dataset (10 CSV files, ~6 GB), preprocesses it (cleaning, encoding, SMOTE balancing, feature selection), trains a Random Forest model, and evaluates it
- **Live Classification** — Captures real-time network traffic using CICFlowMeter (Java), converts packets into flow features, and classifies each flow as Benign or one of 5 attack types
- **Batch Classification** — Classifies pre-captured CSV flow files and generates accuracy reports (if labeled)

### Attack Classes

| Model Variant | Classes |
|---|---|
| **Default (5-class)** | Benign, Botnet, Brute Force, DDoS, DoS |
| **All (6-class)** | Benign, Botnet, Brute Force, DDoS, DoS, Infilteration |

## Project Structure

```
NIDS/
├── main.py                       # Main entry point (placeholder)
├── ml_model.py                   # ML pipeline CLI (Modules 1-5)
├── classification.py             # Live & Batch classification CLI
├── config.py                     # All settings & hyperparameters
├── requirements.txt              # Python dependencies
├── setup/                        # Setup & helpers
│   ├── SETUP_GUIDE.md            #   Full step-by-step instructions
│   ├── setup.bat                 #   Automated setup (Windows)
│   ├── setup.sh                  #   Automated setup (Linux)
│   ├── fix_tuesday_csv.py        #   Fixes extra columns in Tuesday CSV
│   ├── verify_csv_files.py       #   Verifies all 10 CSVs are correct
│   └── verify_environment.py     #   Checks Python packages & Java
│
├── ml_model/                     # ML pipeline modules
│   ├── data_loader.py            #   Module 1: Load CICIDS2018 CSVs
│   ├── explorer.py               #   Module 2: EDA & visualizations
│   ├── preprocessor.py           #   Module 3: Clean, encode, SMOTE, feature selection
│   ├── trainer.py                #   Module 4: Random Forest + hyperparameter tuning
│   ├── tester.py                 #   Module 5: Evaluation & metrics
│   └── utils.py                  #   Shared utilities
│
├── classification/               # Live classification pipeline (threaded)
│   ├── cicflowmeter_source.py    #   Manages CICFlowMeter Java subprocess
│   ├── preprocessor.py           #   Real-time feature preprocessing
│   ├── classifier.py             #   Model inference (top-3 predictions)
│   ├── threat_handler.py         #   Color-coded terminal threat alerts
│   ├── report_generator.py       #   Per-session report files
│   └── batch_source.py           #   CSV row-by-row input for live pipeline
│
├── classification_batch/         # Fast vectorized batch classification
│   ├── batch_source.py           #   Loads entire CSV at once
│   ├── batch_preprocessor.py     #   Vectorized preprocessing
│   ├── batch_classifier.py       #   Vectorized inference
│   ├── batch_report.py           #   Batch report generation
│   ├── batch_classify.py         #   Batch pipeline orchestrator
│   └── batch_utils.py            #   File discovery & selection helpers
│
├── CICFlowMeter/                 # Modified CICFlowMeter (Java)
│   ├── src/main/java/            #   Java source (LiveCapture, FlowGenerator, etc.)
│   ├── jnetpcap/                 #   Native pcap libraries (win + linux)
│   ├── build.gradle              #   Gradle build config
│   └── gradlew / gradlew.bat     #   Gradle wrapper
│
├── trained_model/                # Pre-trained 5-class model (included in repo)
│   ├── random_forest_model.joblib
│   ├── scaler.joblib
│   ├── label_encoder.joblib
│   ├── selected_features.joblib
│   └── training_metadata.json
│
└── data/raw/                     # ← YOU download CICIDS2018 CSVs here
```

## Quick Start

> **Full step-by-step instructions:** See **[setup/SETUP_GUIDE.md](setup/SETUP_GUIDE.md)**

### 1. Clone & Setup Python Environment

```bash
git clone <repo_url>
cd NIDS

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Live Classification (Works Immediately — Requires Java + Npcap)

The pre-trained 5-class model is included, so live classification works right after setup:

```bash
python classification.py                          # Auto-detect WiFi, 180s
python classification.py --duration 300           # 5 minutes
python classification.py --model all              # 6-class model (must train first)
python classification.py --list-interfaces        # List interfaces
```

### 3. Run Batch Classification

Classify a CSV file of network flows using the pre-trained model:

```bash
python classification.py --batch path/to/your_flows.csv
```

See [Batch CSV Format](#batch-csv-format) below for the expected file format.

### 4. Train Your Own Model (Requires Dataset)

```bash
# Download CICIDS2018 CSVs into data/raw/ first (see SETUP_GUIDE.md)

python ml_model.py --full                         # Full pipeline (5-class)
python ml_model.py --full --all                   # Full pipeline (6-class)
python ml_model.py --module 4 --hypercache        # Retrain with cached hyperparams
```

## What Are `setup.bat` / `setup.sh`?

These are **automated setup scripts** that do Steps 1 above for you in one click:

- **`setup.bat`** (Windows) — Creates the venv, activates it, installs all pip dependencies
- **`setup.sh`** (Linux) — Same thing, plus installs system packages (`libpcap-dev`) via apt/yum

You can either run the setup script OR do it manually — they do the same thing. The scripts just save time so you don't have to type each command yourself.

```bash
# Windows: double-click or run from project root:
setup\setup.bat

# Linux:
chmod +x setup/setup.sh
./setup/setup.sh
```

After running the setup script, you still need to activate the venv in each new terminal:
```bash
# Windows:
venv\Scripts\activate

# Linux:
source venv/bin/activate
```

## Requirements

| Requirement | Needed For | How to Get |
|---|---|---|
| **Python 3.8+** | Everything | [python.org](https://www.python.org/downloads/) |
| **Java 8+ (JDK)** | Live capture only | [adoptium.net](https://adoptium.net/) |
| **Npcap** (Windows) | Live capture only | **Included in repo** (`CICFlowMeter/jnetpcap/`) + install [Npcap driver](https://npcap.com) |
| **libpcap** (Linux) | Live capture only | `sudo apt-get install libpcap-dev` |
| **CICIDS2018 dataset** | ML training only | [UNB CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) |

## ML Pipeline Modules

| Module | Command | What It Does |
|---|---|---|
| **1 - Data Loading** | `--module 1` | Loads 10 CSVs from `data/raw/`, concatenates, validates, saves checkpoint |
| **2 - Exploration** | `--module 2` | EDA: class distribution, correlations, imbalance analysis, visualizations |
| **3 - Preprocessing** | `--module 3` | Cleans data, encodes labels, scales features, SMOTE balancing, feature selection (80→40) |
| **4 - Training** | `--module 4` | RandomizedSearchCV hyperparameter tuning + Random Forest training |
| **5 - Testing** | `--module 5` | Confusion matrix, per-class F1, ROC curves, binary (Benign vs Attack) evaluation |

## Batch CSV Format

To run batch classification, your CSV file must have the **79 columns** that CICFlowMeter outputs (without Flow ID, Src IP, Dst IP, Src Port, or Label).

A sample file is included at `setup/sample_batch.csv` for reference.

### Required Columns (79 total)

```
Dst Port, Protocol, Timestamp, Flow Duration, Tot Fwd Pkts, Tot Bwd Pkts,
TotLen Fwd Pkts, TotLen Bwd Pkts, Fwd Pkt Len Max, Fwd Pkt Len Min,
Fwd Pkt Len Mean, Fwd Pkt Len Std, Bwd Pkt Len Max, Bwd Pkt Len Min,
Bwd Pkt Len Mean, Bwd Pkt Len Std, Flow Byts/s, Flow Pkts/s,
Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min, Fwd IAT Tot,
Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min, Bwd IAT Tot,
Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min, Fwd PSH Flags,
Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Len,
Bwd Header Len, Fwd Pkts/s, Bwd Pkts/s, Pkt Len Min, Pkt Len Max,
Pkt Len Mean, Pkt Len Std, Pkt Len Var, FIN Flag Cnt, SYN Flag Cnt,
RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt, URG Flag Cnt, CWE Flag Count,
ECE Flag Cnt, Down/Up Ratio, Pkt Size Avg, Fwd Seg Size Avg,
Bwd Seg Size Avg, Fwd Byts/b Avg, Fwd Pkts/b Avg, Fwd Blk Rate Avg,
Bwd Byts/b Avg, Bwd Pkts/b Avg, Bwd Blk Rate Avg, Subflow Fwd Pkts,
Subflow Fwd Byts, Subflow Bwd Pkts, Subflow Bwd Byts, Init Fwd Win Byts,
Init Bwd Win Byts, Fwd Act Data Pkts, Fwd Seg Size Min, Active Mean,
Active Std, Active Max, Active Min, Idle Mean, Idle Std, Idle Max, Idle Min
```

### Example Row

```csv
Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,...
443,6,15/02/2018 10:30:00,654929,5,3,1024.0,512.0,256.0,128.0,...
```

> **Tip:** If your CSV also has a `Label` column (ground-truth), place it in `data/default/batch_labeled/` or `data/all/batch_labeled/` and the batch classifier will automatically compute accuracy.

## What Can You Do Without Training?

| Task | Needs Dataset? | Needs Training? | Works Out of Box? |
|---|---|---|---|
| **Live classification (5-class)** | No | No | Yes (model included) |
| **Batch classification (5-class)** | No | No | Yes (model included) |
| **Live/Batch classification (6-class)** | Yes | Yes | No — run `ml_model.py --full --all` first |
| **Retrain with custom data** | Yes | Yes | No — run `ml_model.py --full` |

## License

This project uses a modified version of [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) (see `CICFlowMeter/LICENSE.txt`).
