# NIDS — Network Intrusion Detection System

A machine learning-based Network Intrusion Detection System trained on the [CICIDS2018 dataset](https://www.unb.ca/cic/datasets/ids-2018.html). Classifies network traffic flows into attack categories in real-time, from a batch CSV, or via simulation.

---

## Traffic Classes

| Class | Description |
|-------|-------------|
| Benign | Normal traffic |
| DDoS | Distributed Denial of Service (LOIC HTTP/UDP, HOIC) |
| DoS | Denial of Service (Hulk, SlowHTTPTest, GoldenEye, Slowloris) |
| Brute Force | FTP/SSH brute force, Patator, Web/XSS |
| Botnet | Bot/C2 traffic |
| Infilteration | Network infiltration *(6-class model only)* |

Two model variants:
- **Default (5-class)** — ready to use, included in this repo
- **All (6-class)** — includes Infilteration, requires training yourself (see [ml_model_readme.md](ml_model_readme.md))

---

## Prerequisites

- Python 3.12+
- Node.js 18+ (frontend)
- **Windows**: [Npcap](https://npcap.com/) for live capture — run as Administrator
- **Linux/macOS**: libpcap + run as root

---

## Installation

```bash
# 1. Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install frontend dependencies
cd frontend && npm install && cd ..
```

---

## Running

### Production (built frontend, single port)

```bash
cd frontend && npm run build && cd ..
python main.py
```

Opens at http://localhost:8000

### Development (hot reload)

```bash
python main.py --dev
```

- Backend: http://localhost:8000
- Frontend: http://localhost:3000 (React hot reload)

### Options

```bash
python main.py --port 9000      # custom port
python main.py --no-browser     # skip auto-open
```

---

## Classification Modes

### Batch — upload a CICFlowMeter CSV

Via the web UI, or:

```bash
python classification.py --batch data/data_model_use/default/batch/traffic.csv
```

If the CSV has a `Label` column, accuracy metrics are computed automatically.

### Live capture

Requires Npcap (Windows) or root (Linux/macOS).

```bash
python classification.py --list-interfaces
python classification.py --live --duration 120
python classification.py --live --model all --duration 300 --interface "Wi-Fi"
```

### Simulation — replay pre-recorded traffic

First time only (requires ~15-20 GB RAM):
```bash
python -m classification.classification_simulated.shuffler
```

Then:
```bash
python classification.py --simul
python classification.py --simul --labeled --model all
```

All modes are also accessible through the web UI.

---

## Threat Levels

| Level | Condition |
|-------|-----------|
| RED | Top predicted class is an attack |
| YELLOW | Benign predicted, but 2nd-class confidence >= 25% |
| GREEN | Clearly benign |

---

## Project Structure

```
Nids/
├── app.py                 # FastAPI application
├── main.py                # Unified launcher
├── classification.py      # Classification CLI
├── ml_model.py            # Training pipeline CLI
├── config.py              # All configuration
├── requirements.txt
├── routes/                # 9 API route modules
├── classification/        # Batch, live, simulated pipelines
├── ml_model/              # Training pipeline (5 modules)
├── data/                  # Training data + batch CSVs
├── trained_models/        # Model artifacts
├── results/               # Training/evaluation plots and reports
├── reports/               # Classification session reports
├── temp/                  # Temp files + pre-shuffled simulation data
└── frontend/              # React frontend
```

- [Classification engine](classification_readme.md)
- [ML training pipeline](ml_model_readme.md)
- [Frontend](frontend_readme.md)
- [Full API reference](#api-reference)

---

## API Reference

### Health & Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/dashboard-stats` | Model accuracy, dataset count, uptime |
| GET | `/api/models` | List available trained models |

### Batch Classification

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/batch/folders` | List batch CSV files |
| POST | `/api/batch/upload/{model}/{folder_type}` | Upload CSV (`model`: default/all, `folder_type`: batch/batch_labeled) |
| POST | `/api/batch/classify-folder` | Classify a file from a batch folder |
| DELETE | `/api/batch/delete/{model}/{folder_type}/{filename}` | Delete a batch file |

### Live Classification

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/live/interfaces` | List network interfaces |
| POST | `/api/live/start` | Start live session `{interface, model_variant, duration_seconds}` |
| POST | `/api/live/stop/{session_id}` | Stop session |
| GET | `/api/live/status/{session_id}` | Session status |
| GET | `/api/live/events/{session_id}?from=N` | Poll for new events |

### Simulation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/simulation/datasets` | List simulation datasets |
| POST | `/api/simulation/start` | Start simulation `{model, labeled, duration_seconds, flow_rate}` |
| POST | `/api/simulation/stop/{session_id}` | Stop simulation |
| GET | `/api/simulation/status/{session_id}` | Session status |
| GET | `/api/simulation/events/{session_id}?from=N` | Poll for new events |

### Data Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/data/list-raw` | List uploaded CSVs |
| GET | `/api/data/preview/{filename}` | First 20 rows |
| GET | `/api/data/inspect/{filename}` | Column stats, dtypes, null counts |
| POST | `/api/data/archive/{filename}` | Move to archive |
| POST | `/api/data/restore/{filename}` | Restore from archive |
| DELETE | `/api/data/delete/{filename}?confirm=true` | Permanently delete |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports` | List reports (`?type=batch/live/simul/training&model=default/all`) |
| GET | `/api/reports/{name}` | All files in a report folder |
| GET | `/api/reports/{name}/batch-results` | Parse batch results file |
| GET | `/api/reports/{name}/minutes` | List minute-by-minute files |
| GET | `/api/reports/{name}/minute/{HH-MM}` | Parse a minute file |

### Training Pipeline

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/training/start` | Start training job |
| GET | `/api/training/status/{job_id}` | Progress (module, percent) |
| POST | `/api/training/cancel/{job_id}` | Cancel job |
| GET | `/api/training/results/{job_id}` | Final accuracy/F1 |

---

## Configuration

All settings in `config.py`. Key knobs:

| Setting | Default | Description |
|---------|---------|-------------|
| `FLOWMETER_IDLE_THRESHOLD` | 15s | Emit live flow after N idle seconds |
| `FLOWMETER_AGE_THRESHOLD` | 30s | Emit live flow after N total seconds |
| `CLASSIFICATION_DEFAULT_DURATION` | 120s | Default live session duration |
| `CLASSIFICATION_SUSPICIOUS_THRESHOLD` | 0.25 | Confidence threshold for YELLOW alert |
| `CLASSIFICATION_SIMUL_FLOWS_PER_SECOND` | 5 | Simulation feed rate |
