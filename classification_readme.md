# Classification Engine

Three modes share the same preprocessing and classification logic — only the data source differs.

```
BATCH:   CSV file    → BatchPreprocessor  → BatchClassifier  → BatchReportGenerator
LIVE:    Scapy/Npcap → flow_queue → Preprocessor → classifier_queue → Classifier → threat_queue + report_queue → ThreatHandler + ReportGenerator
SIMUL:   CSV replay  → flow_queue → (same as live)
```

---

## Batch Mode (`classification_batch/`)

### Running

```bash
# Interactive file picker
python classification.py --batch

# Specific file (5-class model)
python classification.py --batch data/data_model_use/default/batch/traffic.csv

# 6-class model
python classification.py --batch --model all data/data_model_use/all/batch/traffic.csv
```

If the CSV has a `Label` column it is treated as labeled — accuracy, precision, recall, F1, and confusion matrix are computed automatically.

### Pipeline

1. **BatchSource** — reads the full CSV; separates identifier columns (Flow ID, IPs, ports, Timestamp, Protocol) from feature columns
2. **BatchPreprocessor** — vectorized over the whole DataFrame:
   - Replace inf/NaN with 0
   - One-hot encode Protocol
   - Align to the 80-column scaler order (zero-fill missing columns)
   - `scaler.transform()` → scale all 80
   - Select ~40 features from `selected_features.joblib`
3. **BatchClassifier** — single `model.predict_proba(X_ready)` call over all rows; returns top-3 classes and confidences per flow
4. **BatchReportGenerator** — writes to `reports/batch_{model}[_labeled]_{filename}_{datetime}/`:
   - `batch_results.txt` — full ASCII table of every flow
   - `batch_summary.txt` — totals, threat/suspicious/clean counts, accuracy if labeled

### Threat levels (batch)

Results are tagged but not displayed in real-time:
- **Threat**: predicted class is not Benign
- **Suspicious**: Benign predicted, but 2nd-class confidence >= 25%
- **Clean**: clearly benign

---

## Live Mode (`classification_live/`)

### Running

Requires Npcap on Windows or root on Linux/macOS.

```bash
python classification.py --list-interfaces

python classification.py --live
python classification.py --live --model all --duration 300 --interface "Wi-Fi"
python classification.py --live --save-flows    # also writes raw flows to CSV
```

Or use the **Live Detection** page in the web UI.

### Pipeline

All stages run as separate threads connected by queues:

1. **FlowMeterSource** (wraps cicflowmeter) — captures packets with Scapy; emits completed flows when:
   - Flow idle for 15 seconds (`FLOWMETER_IDLE_THRESHOLD`)
   - Flow age reaches 30 seconds (`FLOWMETER_AGE_THRESHOLD`)
   - GC interval every 5 seconds
2. **QueueWriter** (bridges cicflowmeter → pipeline):
   - Maps cicflowmeter snake_case keys → CICIDS2018 training column names
   - Converts 22 time-based fields from seconds → microseconds (× 1,000,000)
   - Extracts identifiers into a `__identifiers__` key
   - Pushes mapped dict to `flow_queue`
3. **Preprocessor** — same 7-step pipeline as batch, but queue-based:
   - Batches up to 50 flows at a time (500ms timeout)
   - Pushes preprocessed batches to `classifier_queue`
4. **Classifier** — batches up to 50, runs `predict_proba`, pushes results to:
   - `threat_queue` → ThreatHandler
   - `report_queue` → ReportGenerator
5. **ThreatHandler** — assesses each result and displays:
   - RED: prints ANSI-colored `THREAT DETECTED` block with top-3 predictions
   - YELLOW: prints `SUSPICIOUS ACTIVITY` block
   - GREEN: silently counted
6. **ReportGenerator** — writes per-minute files and a session summary to `reports/live_{model}_{datetime}/`

### Shutdown

When the session ends (duration reached or stopped), a `None` sentinel propagates through all queues so every in-flight flow is fully processed before any thread exits.

---

## Simulation Mode (`classification_simulated/`)

Replays pre-shuffled traffic through the live pipeline without needing a network interface. Useful for testing and demos.

### Setup (first time only)

```bash
# Reads data/simul/, shuffles in memory (~15-20 GB RAM), writes to temp/simul/
python -m classification.classification_simulated.shuffler
```

### Running

```bash
python classification.py --simul
python classification.py --simul --labeled                   # include ground truth labels
python classification.py --simul --model all --labeled
python classification.py --simul --duration 300 --flow-rate 10  # 10 flows/sec
```

Or use the **Simulation** page in the web UI.

### How it differs from live

- **SimulationSource** reads from `temp/simul/` line-by-line (never loads the whole file)
- Feeds rows at a configurable rate (default 5 flows/sec, 0.2s sleep between rows)
- If `--labeled`, the `Label` column is passed through as `actual_label` so the report can compute accuracy
- Everything downstream (Preprocessor → Classifier → ThreatHandler → ReportGenerator) is identical to live mode

Reports go to `reports/simul_{model}_{datetime}/`.

---

## Reports

All session reports share the same structure:

| File | Contents |
|------|----------|
| `session_summary.txt` | Total flows, RED/YELLOW/GREEN counts, per-minute breakdown, accuracy if labeled |
| `minute_HH-MM.txt` | ASCII table of all flows classified in that calendar minute |

Batch reports use:

| File | Contents |
|------|----------|
| `batch_results.txt` | Full flow table (all rows) |
| `batch_summary.txt` | Totals and accuracy if labeled |

---

## Key Implementation Notes

**80 → 40 feature pipeline**: The scaler was fitted on 80 features. All preprocessing must build a full 80-feature DataFrame, scale it, then select the ~40 model features. Never scale only the selected features.

**Protocol encoding**: Protocol column values (0, 6, 17) are one-hot encoded to `Protocol_0`, `Protocol_6`, `Protocol_17` using `drop_first=False`, matching the training pipeline exactly.

**Time unit conversion**: cicflowmeter outputs time values in seconds. The CICIDS2018 training data uses microseconds. The `QueueWriter` multiplies 22 time-based fields by 1,000,000 before pushing to the queue.

**Web UI integration**: The live and simulation routes in `routes/live_routes.py` and `routes/simulation_routes.py` spawn `classification.py` as a subprocess and parse its stdout with a stateful line parser. The frontend polls `/api/live/events/{session_id}?from=N` every 500ms.
