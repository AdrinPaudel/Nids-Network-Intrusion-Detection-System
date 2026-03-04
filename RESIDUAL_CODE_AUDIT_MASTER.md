# Residual / Unused Code — Master Audit

> **Date:** 2026-03-04
> **Scope:** All `.py` files in the project (excluding `venv/`)
> **Purpose:** Document-only — no code has been modified.
> **Consolidated from:** CODE_AUDIT.md, resedue code.md, resedue code2.md, resedue code3.md, RESIDUAL_CODE_AUDIT_2026-03-04.md

---

## 1. Dead Config Constants (`config.py`)

Constants defined in `config.py` that are **never imported or referenced** by any other Python file.

| # | Constant | ~Line | Why It's Dead |
|---|----------|-------|---------------|
| 1 | `TARGET_ACCURACY` | 385 | Defined as `0.99`, never imported anywhere |
| 2 | `TARGET_INFILTRATION_F1` | 386 | Defined as `0.89`, never imported anywhere |
| 3 | `TARGET_MACRO_F1_SCORE` | 384 | Defined as `0.96`, never imported anywhere |
| 4 | `APPLY_CORRELATION_ELIMINATION` | 379 | Flag (`True`) but no code checks it — preprocessor always runs correlation elimination regardless |
| 5 | `BACKEND_HOST` | 371 | No backend/API server exists in the project |
| 6 | `BACKEND_PORT` | 372 | Same — no backend exists |
| 7 | `BACKEND_WORKERS` | 373 | Same — no backend exists |
| 8 | `DEFAULT_RF_PARAMS` | 280 | Default RF params dict, never imported by `trainer.py` or anything else |
| 9 | `CLASSIFICATION_REPORT_DIGITS` | 298 | `tester.py` hardcodes `digits=4` instead of reading this |
| 10 | `CONFUSION_MATRIX_NORMALIZE` | 299 | `tester.py` hardcodes its own normalization logic instead |
| 11 | `ROC_MICRO_AVERAGE` | 302 | Never imported — `tester.py` never checks this flag |
| 12 | `ROC_MACRO_AVERAGE` | 303 | Never imported — `tester.py` never checks this flag |
| 13 | `CLASSIFICATION_BATCH_PROGRESS_INTERVAL` | 499 | Never imported by any classification module |
| 14 | `CLASSIFICATION_SESSION_FOLDER_FORMAT` | 550 | Never imported — report generators build folder names with inline f-strings |
| 15 | `CLASSIFICATION_BATCH_DIR` | 545 | Backward-compat alias for `CLASSIFICATION_BATCH_DEFAULT_DIR`, never imported outside `config.py` |
| 16 | `CLASSIFICATION_BATCH_LABELED_DIR` | 546 | Backward-compat alias for `CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR`, never imported outside `config.py` |
| 17 | `LOW_MEMORY` | 363 | Computed from `SYSTEM_RAM_GB` but never imported or checked by any module |
| 18 | `STRATIFY` | 208 | Defined as `True` but never imported — `ml_model/preprocessor.py` hardcodes `stratify=y` directly |
| 19 | `VERBOSE` | 367 | Defined as `True` but never imported by any module |
| 20 | `TUNING_SCORING` | 262 | Defined as `'f1_macro'` but never imported — `trainer.py` receives scoring via function param, not from config |
| 21 | `HYPERPARAMETER_TUNING` | 258 | Defined as `True` but never checked — `trainer.py` always tunes unconditionally |
| 22 | `GARBAGE_COLLECTION_INTERVAL` | 265 | Defined as `5` but never imported — `trainer.py` does not implement periodic gc based on this |
| 23 | `ENABLE_MEMORY_OPTIMIZATION` | 266 | Defined as `True` but never imported — no module checks this flag |

### Transitively Dead (only used internally by `config.py` to compute other dead constants)

| # | Constant | ~Line | Notes |
|---|----------|-------|-------|
| 24 | `SYSTEM_RAM_GB` | 357 | Only used within `config.py` to compute `LOW_MEMORY` (dead) and `BACKEND_WORKERS` (dead) |
| 25 | `SYSTEM_CPU_COUNT` | 310 | Only used within `config.py` to compute `BACKEND_WORKERS` (dead). Other modules use `os.cpu_count()` directly. |

### Conditionally Dead (depend on SMOTE strategy — currently `'dynamic'`)

| # | Constant | ~Line | Notes |
|---|----------|-------|-------|
| 26 | `SMOTE_TIERED_TARGETS` | 229 | Only reachable if `SMOTE_STRATEGY='tiered'` — currently dead path |
| 27 | `SMOTE_TARGET_PERCENTAGE` | 241 | Only reachable if `SMOTE_STRATEGY='uniform'` — currently dead path |

### Internal-Only Config Constants (could be inlined)

These are only referenced within `config.py` itself to build `CLASSIFICATION_BATCH_FOLDERS`. No other file imports them.

| # | Constant | ~Line |
|---|----------|-------|
| 28 | `CLASSIFICATION_BATCH_DEFAULT_DIR` | 507 |
| 29 | `CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR` | 508 |
| 30 | `CLASSIFICATION_BATCH_ALL_DIR` | 509 |
| 31 | `CLASSIFICATION_BATCH_ALL_LABELED_DIR` | 510 |

### Confirmed NOT Dead (corrections)

| Constant | ~Line | Status |
|----------|-------|--------|
| `CLASSIFICATION_LABEL_COLUMN` | 547 | **USED** — imported in `classification/classification_batch/batch_source.py` |

---

## 2. Config Constants Bypassed by Hardcoded Alternatives

These constants exist and ARE imported, but a hardcoded value in the consumer means the config is partially or fully bypassed.

| # | Config Constant | ~Line | Consumer | Issue |
|---|----------------|-------|----------|-------|
| 1 | `CLASSIFICATION_REPORT_FLUSH_INTERVAL` | 500 | `classification_live/report_generator.py` | Imported but line ~328 hardcodes `if self.report_count % 10 == 0` instead of using the constant. The simulated version uses it correctly. |
| 2 | `HYPERPARAMETER_TUNING` | 258 | `ml_model/trainer.py` | Defined as `True` but trainer never checks it — tuning always runs. |
| 3 | `TUNING_SCORING` | 262 | `ml_model/trainer.py` | Defined but trainer receives scoring metric via function param from `ml_model.py`, not from config. |

---

## 3. Unreferenced Computation Chain

`config.py` defines `_detect_ram_gb()` (private function, ~lines 313–356) which computes `SYSTEM_RAM_GB` (~line 357). The entire chain leads to dead constants:

```
_detect_ram_gb() → SYSTEM_RAM_GB → LOW_MEMORY (dead)
                                  → (only internal use)
```

The function runs on import but its output feeds only dead constants — effectively wasted computation at import time.

---

## 4. Phantom Config Section

| Location | ~Line | Issue |
|----------|-------|-------|
| `config.py` | 441–442 | Comment `# Debug mode settings (reserved)` with nothing after it. Dead placeholder — either implement or remove. |

---

## 5. Unused Imports

### 5a. `ml_model/trainer.py`

| # | Import | ~Line | Notes |
|---|--------|-------|-------|
| 1 | `import sys` | 14 | Never used anywhere in the file |
| 2 | `accuracy_score` | 31 | Imported from sklearn but never called |
| 3 | `precision_score` | 31 | Same — never called |
| 4 | `recall_score` | 31 | Same — never called |
| 5 | `classification_report` | 32 | Same — never called |
| 6 | `confusion_matrix` | 32 | Same — never called |

### 5b. Unused `import threading` — 8 classification files

All 8 files import `threading` at module level but only reference it in docstrings (`stop_event: threading.Event`). They receive `threading.Event` objects as params and call `.is_set()`, `.wait()` etc. without needing the module itself.

| # | File | ~Line |
|---|------|-------|
| 1 | `classification/classification_live/classifier.py` | 11 |
| 2 | `classification/classification_live/preprocessor.py` | 10 |
| 3 | `classification/classification_live/threat_handler.py` | 15 |
| 4 | `classification/classification_live/report_generator.py` | 22 |
| 5 | `classification/classification_simulated/classifier.py` | 11 |
| 6 | `classification/classification_simulated/preprocessor.py` | 10 |
| 7 | `classification/classification_simulated/threat_handler.py` | 15 |
| 8 | `classification/classification_simulated/report_generator.py` | 22 |

> **Note:** `threading` IS legitimately used in `flowmeter_source.py` and `simulation_source.py`. Those are fine.

### 5c. Unused Config Imports

| # | File | Unused Import | Notes |
|---|------|--------------|-------|
| 1 | `classification/classification_live/report_generator.py` | `CLASSIFICATION_REPORT_FLUSH_INTERVAL` | Imported but hardcoded `10` used instead (see §2) |
| 2 | `classification/classification_simulated/report_generator.py` | `CLASSIFICATION_BATCH_QUEUE_TIMEOUT` | Imported but never referenced — simulated mode has no batch queue logic |
| 3 | `classification/classification_live/flowmeter_source.py` | `COLOR_BLUE` | Imported from config but never used in any print/f-string |

### 5d. Unused `import time`

| # | File | ~Line | Notes |
|---|------|-------|-------|
| 1 | `classification/classification_live/threat_handler.py` | 17 | Imported but `time.` never appears in the file |
| 2 | `classification/classification_simulated/threat_handler.py` | 17 | Same — imported but never used |

### Confirmed NOT Unused (corrections)

| Import | File | Status |
|--------|------|--------|
| `precision_score`, `recall_score`, `f1_score` | `ml_model/tester.py` | **USED** — called on lines 350-352 for binary evaluation metrics |

---

## 6. Unused Variables

| # | Variable | File | ~Line | Notes |
|---|----------|------|-------|-------|
| 1 | `top_conf` | `classification/classification_live/threat_handler.py` | 65 | Assigned `top3[0][1]` but never read — method only checks `top_class`, not confidence |
| 2 | `top_conf` | `classification/classification_simulated/threat_handler.py` | 65 | Same — assigned but never read |

---

## 7. Dead / Unreachable Function

| # | Function | File | ~Line | Notes |
|---|----------|------|-------|-------|
| 1 | `select_simul_file()` | `classification/classification_simulated/simulation_source.py` | 53–100 | ~40-line interactive file-selection function. Comment says "kept for manual / debug use". **Never called** anywhere. File selection handled by `classification.py` via `CLASSIFICATION_SIMUL_FILES` config dict. |

---

## 8. Unnecessary Backward-Compatibility Aliases

Module-level aliases that rename a config constant to a shorter name. They add indirection without benefit — the config constant could be used directly.

| # | Alias | File | ~Line | Aliases To |
|---|-------|------|-------|-----------|
| 1 | `DEFAULT_DURATION` | `classification.py` | 127 | `CLASSIFICATION_DEFAULT_DURATION` |
| 2 | `DEFAULT_MODEL` | `classification.py` | 128 | `CLASSIFICATION_DEFAULT_MODEL` |
| 3 | `IDENTIFIER_COLUMNS` | `classification/classification_live/flowmeter_source.py` | 40 | `CLASSIFICATION_IDENTIFIER_COLUMNS` |
| 4 | `DROP_COLUMNS` | `classification/classification_live/preprocessor.py` | 27 | `CLASSIFICATION_DROP_COLUMNS` |
| 5 | `DROP_COLUMNS` | `classification/classification_simulated/preprocessor.py` | 27 | `CLASSIFICATION_DROP_COLUMNS` |
| 6 | `BENIGN_CLASS` | `classification/classification_live/threat_handler.py` | 30 | `CLASSIFICATION_BENIGN_CLASS` |
| 7 | `SUSPICIOUS_THRESHOLD` | `classification/classification_live/threat_handler.py` | 31 | `CLASSIFICATION_SUSPICIOUS_THRESHOLD` |
| 8 | `BENIGN_CLASS` | `classification/classification_simulated/threat_handler.py` | 30 | `CLASSIFICATION_BENIGN_CLASS` |
| 9 | `SUSPICIOUS_THRESHOLD` | `classification/classification_simulated/threat_handler.py` | 31 | `CLASSIFICATION_SUSPICIOUS_THRESHOLD` |

> **Note:** These aliases ARE used within their respective files — the fix is to replace usages with the full config constant name and remove the alias.

---

## 9. Duplicate / Redundant Functions

### 9a. `ml_model/trainer.py` — local duplicates of `ml_model/utils.py`

| # | Local Function | trainer.py ~Line | Duplicates | In `utils.py` |
|---|---------------|-----------------|------------|----------------|
| 1 | `log_step()` | 46 | `log_message()` | `utils.py` ~L9 |
| 2 | `save_figure()` | 62 | `save_figure()` | `utils.py` ~L150 |

- `log_step()` is called 20+ times in `trainer.py` instead of the shared `log_message()`.
- `save_figure()` is called multiple times instead of the identical utility in `utils.py`.

### 9b. Duplicate `check_venv()` Function

| # | File | ~Lines | Notes |
|---|------|--------|-------|
| 1 | `classification.py` | 42–98 | Full venv-checking function |
| 2 | `ml_model.py` | 13–72 | Identical logic, copy-pasted |

Should be extracted into a shared utility.

---

## 10. Massive Code Duplication — `classification_simulated/` vs `classification_live/`

Three modules in `classification_simulated/` are near-identical copies of their `classification_live/` counterparts:

| # | Simulated File | Live File | Similarity | Key Difference |
|---|---------------|-----------|-----------|----------------|
| 1 | `preprocessor.py` (~280 lines) | `preprocessor.py` (~280 lines) | ~95% | Simulated uses `np.where()` for one-hot; live uses `.astype(int)`. Same result. |
| 2 | `classifier.py` (~246 lines) | `classifier.py` (~247 lines) | ~95% | Simulated always pushes to `threat_queue`; live skips when `mode == "batch"`. One-line difference. |
| 3 | `threat_handler.py` (~175 lines) | `threat_handler.py` (~175 lines) | ~99% | **Zero functional difference.** Only docstring says "(Simulated)". |

**~700 lines of duplication.** These simulated modules could import and reuse the live classes.

### Classifier Inconsistency (potential bug)

- **Simulated** `classifier.py` always pushes results to `threat_queue` regardless of mode
- **Live** `classifier.py` gates `threat_queue.put()` behind `if self.mode != "batch"`

This means the simulated classifier pushes to `threat_queue` even in batch mode, while the live classifier skips it.

---

## 11. Dead Batch Code in Live Report Generator

`classification_live/report_generator.py` contains full batch report logic even though batch mode uses `classification_batch/report.py`:

| # | Dead Code | ~Lines | Notes |
|---|----------|--------|-------|
| 1 | `_write_batch_reports()` method | 280–370 | Only reachable if `ReportGenerator(mode="batch")` is created from live module — never done by orchestrator |
| 2 | `_batch_results_file`, `_batch_log_rows` attributes | — | Only initialized when `mode == "batch"` — dead path |

---

## 12. `batch_completion_event` Stored But Never Used (Simulated Report Generator)

| File | ~Lines | Issue |
|------|--------|-------|
| `classification/classification_simulated/report_generator.py` | 48, 68 | Accepts `batch_completion_event` parameter (comment: "unused in simul, kept for API compat"). Stored as `self.batch_completion_event` but never set or checked. Could simply not be passed. |

---

## 13. Hardcoded Values That Should Use Config Constants

| # | File | ~Line | Issue | Fix |
|---|------|-------|-------|-----|
| 1 | `classification/classification_live/report_generator.py` | 328 | `if self.report_count % 10 == 0:` — hardcoded `10` for flush interval | Use `CLASSIFICATION_REPORT_FLUSH_INTERVAL` (already imported but unused) |
| 2 | `classification/classification_live/classifier.py` | 146 | `print(f"\033[93m...\033[0m")` — hardcoded ANSI codes | Use `COLOR_YELLOW` / `COLOR_RESET` (already imported) |
| 3 | `classification/classification_simulated/classifier.py` | 145 | Same hardcoded `\033[93m` and `\033[0m` | Same fix — use imported color constants |

---

## 14. `COLOR_BLUE` — Defined But Zero Consumers

| Location | ~Line | Issue |
|----------|-------|-------|
| `config.py` | 470 | `COLOR_BLUE = "\033[94m"` defined but has zero consumers across the entire project. The only import (`flowmeter_source.py` L36) never uses it. |

---

## 15. Placeholder File — `main.py`

`main.py` (~68 lines) is a non-functional placeholder:
- Defines `--pipeline` and `--backend` flags
- Both flags just print help messages pointing to `ml_model.py` or `classification.py`
- Does not start any pipeline or backend service

Users must run `classification.py` or `ml_model.py` directly. The file serves no purpose.

---

## 16. Code Cleanliness (Confirmed Clean)

| Check | Result |
|-------|--------|
| Commented-out code blocks | **None found** — all `#` lines are documentation/section headers |
| TODO / FIXME / HACK / XXX comments | **None found** in project files (only in `venv/` third-party) |

---

## Summary

| Category | Count | Estimated Impact |
|----------|-------|-----------------|
| Dead config constants | 23 (+2 conditional, +4 internal-only, +2 transitively dead) | ~30 lines removable |
| Config bypassed by hardcoded values | 3 | Fix, not remove |
| Unused imports (all files) | 19 total | ~19 lines removable |
| Unused variables | 2 | ~2 lines removable |
| Dead function (`select_simul_file`) | 1 | ~40 lines removable |
| Unnecessary backward-compat aliases | 9 | ~9 lines removable |
| Duplicate functions (trainer.py) | 2 | ~40 lines removable (use `utils.py`) |
| Duplicate utility (`check_venv`) | 1 (in 2 files) | ~55 lines removable (extract shared) |
| Duplicated modules (simul = copy of live) | 3 files | **~700 lines** eliminable by reuse |
| Dead batch code in live report generator | 1 block | ~90 lines removable |
| Unused `batch_completion_event` param | 1 | Cosmetic |
| Hardcoded values (should use constants) | 3 | Fix, not remove |
| Dead color constant (`COLOR_BLUE`) | 1 | ~1 line removable |
| Placeholder file (`main.py`) | 1 | ~68 lines removable |
| Phantom config placeholder comment | 1 | ~2 lines removable |
| Unreferenced computation chain (`_detect_ram_gb`) | 1 | ~45 lines removable |
| **TOTAL distinct residual items** | **~63+** | **~1100 lines removable/consolidatable** |
