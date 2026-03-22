# ML Training Pipeline

Trains a Random Forest classifier on the [CICIDS2018 dataset](https://www.unb.ca/cic/datasets/ids-2018.html) to classify network traffic into 5 or 6 classes.

---

## Quick Start

```bash
# Place CICIDS2018 CSV files in:
data/data_model_training/raw/

# Run the full 5-class pipeline
python ml_model.py --module 1 2 3 4 5

# Run the full 6-class pipeline (includes Infilteration)
python ml_model.py --module 1 2 3 4 5 --all
```

Run modules individually if needed:

```bash
python ml_model.py --module 1          # Load raw CSVs → checkpoint
python ml_model.py --module 2          # Exploratory data analysis
python ml_model.py --module 3          # Preprocess (clean, encode, SMOTE, feature select)
python ml_model.py --module 4          # Train Random Forest
python ml_model.py --module 4 --hypercache  # Train using cached hyperparameters (faster)
python ml_model.py --module 5          # Evaluate (confusion matrix, ROC, F1)
```

---

## Pipeline Modules

### Module 1 — Data Loading (`data_loader.py`)

- Reads all CSV files from `data/data_model_training/raw/`
- Parallel loading via `ThreadPoolExecutor` → `pd.concat`
- Auto-detects the label column and protocol column by scanning candidate names
- Saves checkpoint: `data/data_model_training/combined/data_loader_checkpoint.joblib`

Subsequent modules load from the checkpoint — you only need to re-run Module 1 if the raw data changes.

### Module 2 — Exploration (`explorer.py`)

- Class distribution analysis (counts, percentages, Gini coefficient)
- Pearson correlation matrix on all numeric features
- Flags feature pairs with |r| > 0.9
- Outputs plots and reports to `results/exploration/`

Exploration data is shared between the default and all-class variants — it only runs once.

### Module 3 — Preprocessing (`preprocessor.py`)

Steps applied in order:

1. **Clean** — drop identifier columns (Flow ID, IPs, ports, Timestamp), remove header-row artifacts, apply label consolidation, drop `__DROP__` classes, remove duplicates and NaN/Inf rows
2. **Label consolidation** — many raw CICIDS2018 sub-labels → 5 or 6 consolidated classes:
   - `DDoS-LOIC-HTTP`, `DDoS-HOIC`, `DDoS-LOIC-UDP` → `DDoS`
   - `DoS-Hulk`, `DoS-SlowHTTPTest`, `DoS-GoldenEye`, `DoS-Slowloris` → `DoS`
   - `FTP-BruteForce`, `SSH-Bruteforce`, `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection` → `Brute Force` (SQL Injection dropped in 5-class)
   - `Bot` → `Botnet`
   - `Infilteration` → kept only in 6-class variant
3. **Encode protocol** — one-hot encode Protocol (0/6/17) → `Protocol_0`, `Protocol_6`, `Protocol_17`
4. **Encode labels** — `LabelEncoder` → integer classes; saves `label_encoder.joblib`
5. **Split** — 80/20 train/test, stratified, `random_state=42`
6. **Scale** — `StandardScaler` fit on train only → transform both; saves `scaler.joblib`
7. **Feature selection** — `RandomForestClassifier(n_estimators=100, max_depth=15)` on train set; keep features with importance >= 0.005 (targets 40-45 features); saves `selected_features.joblib`
8. **SMOTE** — dynamic strategy: for each minority class, target = current + (2nd_largest - current) / 2; `k_neighbors=5`

Outputs:
- `data/data_model_training/preprocessed/` (default) or `preprocessed_all/` (6-class)
- `train_final.parquet` — SMOTE-balanced train set, Label as last column
- `test_final.parquet` — original distribution test set, Label as last column
- `scaler.joblib`, `label_encoder.joblib`, `selected_features.joblib`

### Module 4 — Training (`trainer.py`)

- Loads preprocessed parquets
- **Hyperparameter tuning**: `RandomizedSearchCV` on 20% sample of training data, `n_iter=15`, `cv=3`, scoring=macro F1, parallel via `loky`
- Best params cached to `best_hyperparameters.joblib` — use `--hypercache` on re-runs to skip tuning
- **Final model**: `RandomForestClassifier(**best_params, n_jobs=-1, max_samples=0.5)` trained on all post-SMOTE data
- Saves to `trained_models/trained_model_default/` (or `trained_model_all/`):
  - `random_forest_model.joblib`
  - `scaler.joblib`, `label_encoder.joblib`, `selected_features.joblib` (copies from preprocessed)
  - `best_hyperparameters.joblib`
  - `training_metadata.json` — accuracy, F1, training date, n_estimators, classes

### Module 5 — Evaluation (`tester.py`)

- Loads model + test parquet
- Computes: accuracy, macro F1, weighted F1, per-class precision/recall/F1
- ROC curves (one-vs-rest, `label_binarize`) + AUC
- Target: macro F1 >= 0.85
- Outputs to `results/testing/` (or `results/testing_all/`):
  - `confusion_matrix_multiclass.png`
  - `roc_curves.png`
  - `classification_report.txt`, `accuracy_summary.txt`

---

## Model Artifacts

After training, `trained_models/trained_model_default/` contains everything needed for inference:

| File | Description |
|------|-------------|
| `random_forest_model.joblib` | Trained RandomForestClassifier |
| `scaler.joblib` | StandardScaler fitted on 80 features |
| `label_encoder.joblib` | LabelEncoder (5 or 6 classes) |
| `selected_features.joblib` | List of ~40 selected feature names |
| `best_hyperparameters.joblib` | Hyperparameter search result |
| `training_metadata.json` | Accuracy, F1, training date |

The **5-class (default) model is included** in this repo and ready to use without training. The 6-class model must be trained from the raw CICIDS2018 data.

---

## Feature Pipeline

All inference code must follow the same pipeline order:

1. Build a DataFrame with the ~80 raw CICFlowMeter feature columns
2. One-hot encode Protocol → `Protocol_0`, `Protocol_6`, `Protocol_17`
3. Align to `scaler.feature_names_in_` (80 columns, zero-fill missing)
4. `scaler.transform()` → scaled 80 features
5. Select columns from `selected_features.joblib` → ~40 features
6. `model.predict_proba()` → class probabilities

---

## Results

Training outputs go to:

| Directory | Contents |
|-----------|----------|
| `results/exploration/` | EDA plots and reports (shared) |
| `results/preprocessing/` | Preprocessing plots (default variant) |
| `results/preprocessing_all/` | Preprocessing plots (6-class variant) |
| `results/training/` | Feature importance, CV scores (default) |
| `results/training_all/` | Same for 6-class |
| `results/testing/` | Confusion matrix, ROC curves (default) |
| `results/testing_all/` | Same for 6-class |
