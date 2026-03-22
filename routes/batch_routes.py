"""
Batch folder API routes (Phase 3).

Endpoints:
  GET    /api/batch/folders
  POST   /api/batch/upload/{model}/{folder_type}
  POST   /api/batch/classify-folder
  DELETE /api/batch/delete/{model}/{folder_type}/{filename}
"""

import io
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

router = APIRouter()

# ---------------------------------------------------------------------------
# Reports directory — overrideable in tests via patch("routes.batch_routes._REPORTS_DIR", ...)
# ---------------------------------------------------------------------------
try:
    from config import CLASSIFICATION_REPORTS_DIR as _REPORTS_DIR
except ImportError:
    logging.warning("config.CLASSIFICATION_REPORTS_DIR not found — falling back to <project>/reports/")
    _REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")

# Injected classifier references (set by app startup or tests)
_classifier_default = None
_classifier_all = None

# Injected preprocessor references (set by app startup or tests)
_preprocessor_default = None
_preprocessor_all = None

# Base data directory — overridden in tests
DATA_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)

_VALID_MODELS = ("default", "all")
_VALID_FOLDER_TYPES = ("batch", "batch_labeled")


# ---------------------------------------------------------------------------
# Injection helpers
# ---------------------------------------------------------------------------

def set_classifiers(default_clf: Any, all_clf: Any) -> None:
    """Inject classifier instances (called at startup and in tests)."""
    global _classifier_default, _classifier_all
    _classifier_default = default_clf
    _classifier_all = all_clf


def set_preprocessors(default_prep: Any, all_prep: Any) -> None:
    """Inject preprocessor instances (called at startup and in tests)."""
    global _preprocessor_default, _preprocessor_all
    _preprocessor_default = default_prep
    _preprocessor_all = all_prep


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ClassifyFolderRequest(BaseModel):
    model: Literal["default", "all"]
    folder_type: Literal["batch", "batch_labeled"]
    filename: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_filename(name: str) -> None:
    """Reject filenames that attempt path traversal."""
    # Extract just the base name component
    clean = os.path.basename(name)
    if clean != name or ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal detected")


def _validate_model(model: str) -> None:
    if model not in _VALID_MODELS:
        raise HTTPException(status_code=400, detail=f"Invalid model: {model!r}. Must be one of {_VALID_MODELS}")


def _validate_folder_type(folder_type: str) -> None:
    if folder_type not in _VALID_FOLDER_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid folder_type: {folder_type!r}. Must be one of {_VALID_FOLDER_TYPES}",
        )


def _batch_dir(model: str, folder_type: str) -> Path:
    return Path(DATA_DIR) / "data_model_use" / model / folder_type


def _format_modified(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()


def _count_csv_rows_cols(path: Path):
    """Return (row_count, col_count) for a CSV file, or (None, None) on error."""
    try:
        import csv
        with open(str(path), newline="", encoding="utf-8", errors="ignore") as fh:
            reader = csv.reader(fh)
            header = next(reader, [])
            row_count = sum(1 for _ in reader)
        return row_count, len(header)
    except Exception:
        return None, None


def _list_folder(model: str, folder_type: str) -> List[Dict[str, Any]]:
    """Return a list of file-info dicts for a batch sub-folder."""
    d = _batch_dir(model, folder_type)
    if not d.exists():
        return []
    entries = []
    for entry in sorted(d.iterdir()):
        if entry.is_file() and entry.suffix == ".csv":
            stat = entry.stat()
            rows, cols = _count_csv_rows_cols(entry)
            entries.append({
                "filename": entry.name,
                "size": stat.st_size,
                "modified": _format_modified(stat.st_mtime),
                "rows": rows,
                "cols": cols,
            })
    return entries


def _compute_accuracy_metrics(
    true_labels: List[str],
    predicted_labels: List[str],
) -> Dict[str, Any]:
    """Compute accuracy, precision, recall, F1, and confusion matrix."""
    try:
        from sklearn.metrics import (
            accuracy_score,
            classification_report,
            confusion_matrix,
        )
        import numpy as np

        labels = sorted(set(true_labels) | set(predicted_labels))
        acc = float(accuracy_score(true_labels, predicted_labels))
        report = classification_report(
            true_labels, predicted_labels,
            output_dict=True,
            zero_division=0,
        )
        cm = confusion_matrix(true_labels, predicted_labels, labels=labels).tolist()

        return {
            "accuracy": round(acc, 4),
            "precision": round(report.get("weighted avg", {}).get("precision", 0.0), 4),
            "recall": round(report.get("weighted avg", {}).get("recall", 0.0), 4),
            "f1": round(report.get("weighted avg", {}).get("f1-score", 0.0), 4),
            "confusion_matrix": cm,
            "labels": labels,
        }
    except Exception as exc:
        # sklearn may not be available or inputs malformed — return safe defaults
        return {
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "confusion_matrix": None,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Report saving helper
# ---------------------------------------------------------------------------

def save_batch_report(
    results_list: list,
    classify_stats: dict,
    model: str,
    folder_type: str,
    filename: str,
) -> str:
    """
    Save batch_results.txt and batch_summary.txt to the reports/ directory.

    Never raises — returns empty string if saving fails so the API response
    is not affected by I/O errors.
    """
    try:
        from classification.classification_batch.report import BatchReportGenerator

        has_label = folder_type == "batch_labeled"

        # Ensure every result dict has the 'identifiers' key expected by BatchReportGenerator
        safe_results = [{**r, "identifiers": r.get("identifiers", {})} for r in results_list]

        # Normalise classify_stats — the injected live Classifier may use different key names
        safe_stats = {
            "total_flows":      classify_stats.get("total_flows", len(results_list)),
            "elapsed_seconds":  classify_stats.get("elapsed_seconds", 0.0),
            "flows_per_second": classify_stats.get("flows_per_second", 0.0),
        }

        reporter = BatchReportGenerator(
            model_name=model,
            batch_filename=filename,
            has_label=has_label,
            report_dir=_REPORTS_DIR,
        )
        reporter.generate(safe_results, safe_stats)
        return reporter.report_path
    except Exception:
        logging.exception("Failed to save batch classification report")
        return ""


# ---------------------------------------------------------------------------
# GET /api/batch/folders
# ---------------------------------------------------------------------------

@router.get("/api/batch/folders")
async def batch_folders() -> Dict[str, Any]:
    """Return the file listing for all 4 batch sub-folders."""
    return {
        "default": {
            "batch": _list_folder("default", "batch"),
            "batch_labeled": _list_folder("default", "batch_labeled"),
        },
        "all": {
            "batch": _list_folder("all", "batch"),
            "batch_labeled": _list_folder("all", "batch_labeled"),
        },
    }


# ---------------------------------------------------------------------------
# POST /api/batch/upload/{model}/{folder_type}
# ---------------------------------------------------------------------------

@router.post("/api/batch/upload/{model}/{folder_type}")
async def batch_upload(
    model: str,
    folder_type: str,
    file: UploadFile = File(...),
) -> Dict[str, Any]:
    """Upload a CSV file into the specified batch sub-folder."""
    _validate_model(model)
    _validate_folder_type(folder_type)

    filename = file.filename or ""
    _validate_filename(filename)

    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    target_dir = _batch_dir(model, folder_type)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / filename

    try:
        contents = await file.read()
        target_path.write_bytes(contents)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write file: {exc}") from exc

    return {
        "filename": filename,
        "size": len(contents),
    }


# ---------------------------------------------------------------------------
# POST /api/batch/classify-folder
# ---------------------------------------------------------------------------

@router.post("/api/batch/classify-folder")
async def batch_classify_folder(body: ClassifyFolderRequest) -> Dict[str, Any]:
    """
    Classify a CSV file from a batch sub-folder using the appropriate classifier.

    For batch_labeled folders, also computes accuracy metrics against the
    true Label column.
    """
    if _classifier_default is None:
        raise HTTPException(status_code=503, detail="Classifiers not loaded")
    if _preprocessor_default is None:
        raise HTTPException(status_code=503, detail="Preprocessors not loaded")

    _validate_filename(body.filename)

    file_path = _batch_dir(body.model, body.folder_type) / body.filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {body.filename}")

    try:
        import pandas as pd
        df = pd.read_csv(str(file_path))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read CSV: {exc}") from exc

    # Detect likely headerless CSV — column names that look like float/int data values
    def _col_looks_numeric(col: str) -> bool:
        try:
            float(col)
            return True
        except (ValueError, TypeError):
            return False

    sample_cols = list(df.columns[:min(10, len(df.columns))])
    if sample_cols and all(_col_looks_numeric(str(c)) for c in sample_cols):
        raise HTTPException(
            status_code=400,
            detail=(
                "Your CSV file appears to have no header row. "
                "The first row must contain the CICFlowMeter feature names (column names), "
                "not data values. Please add a header row to your CSV file."
            ),
        )

    classifier = _classifier_all if body.model == "all" else _classifier_default
    preprocessor = _preprocessor_all if body.model == "all" else _preprocessor_default

    # For labeled data: extract and remove the label column before classifying
    true_labels: Optional[List[str]] = None
    if body.folder_type == "batch_labeled":
        label_col = None
        # Accept last column named 'Label' (case-insensitive) or the literal last column
        for col in reversed(df.columns.tolist()):
            if col.strip().lower() == "label":
                label_col = col
                break
        if label_col is None and len(df.columns) > 0:
            label_col = df.columns[-1]

        if label_col is not None:
            true_labels = df[label_col].astype(str).tolist()
            df = df.drop(columns=[label_col])

    try:
        import pandas as pd
        # Preprocess raw CSV → model-ready features (one-hot encoding, scaling, feature selection)
        X_ready = preprocessor.preprocess(df)
        # Classify and unpack tuple return (results_list, stats_dict)
        # Pass true_labels so actual_label is populated in each result record
        labels_series = pd.Series(true_labels) if true_labels is not None else None
        results_list, classify_stats = classifier.classify(X_ready, labels=labels_series)
    except Exception as exc:
        err_str = str(exc)
        # Detect sklearn feature-name mismatch and produce a user-readable message
        if "feature names" in err_str.lower() or "feature name" in err_str.lower():
            missing = [ln.strip("- \t") for ln in err_str.splitlines() if ln.strip().startswith("-")]
            hint = (
                "Column mismatch: the CSV columns do not match the model's expected features. "
                f"Make sure the file was generated by CICFlowMeter for the "
                f"{'5-class Default' if body.model == 'default' else '6-class All'} model "
                "and that no columns were renamed, added, or removed."
            )
            if missing:
                hint += f" Missing columns: {', '.join(missing[:10])}"
                if len(missing) > 10:
                    hint += f" … and {len(missing) - 10} more"
            raise HTTPException(status_code=400, detail=hint) from exc
        raise HTTPException(status_code=400, detail=f"Classification failed: {exc}") from exc

    # Convert list of dicts to DataFrame with the column names the rest of the route expects
    results = pd.DataFrame({
        "prediction":      [r["predicted_class"] for r in results_list],
        "confidence":      [r["confidence"]       for r in results_list],
        "top2_prediction": [
            r["top3"][1][0] if len(r.get("top3", [])) >= 2 else ""
            for r in results_list
        ],
        "top2_confidence": [
            r["top3"][1][1] if len(r.get("top3", [])) >= 2 else 0.0
            for r in results_list
        ],
        "timestamp":       [r.get("timestamp", "") for r in results_list],
        "actual_label":    [r.get("actual_label")  for r in results_list],
    })

    threat_count = int(len(results[results["prediction"] != "Benign"]))
    total_flows = len(results)
    threat_percentage = (threat_count / total_flows) * 100 if total_flows > 0 else 0.0

    # Suspicious: predicted Benign but top-2 confidence >= 0.25
    benign_mask = results["prediction"] == "Benign"
    if "top2_confidence" in results.columns:
        suspicious_mask = benign_mask & (results["top2_confidence"].fillna(0.0) >= 0.25)
        suspicious_count = int(suspicious_mask.sum())
    else:
        suspicious_count = 0
    clean_count = int(benign_mask.sum()) - suspicious_count

    response: Dict[str, Any] = {
        "success": True,
        "filename": body.filename,
        "model": body.model,
        "folder_type": body.folder_type,
        "total_flows": total_flows,
        "threat_count": threat_count,
        "threat_percentage": round(threat_percentage, 2),
        "suspicious_count": suspicious_count,
        "clean_count": clean_count,
        "results": results.to_dict(orient="records")[:100],
    }

    if true_labels is not None:
        predicted_labels = results["prediction"].astype(str).tolist()
        response["accuracy_metrics"] = _compute_accuracy_metrics(true_labels, predicted_labels)

    # Save report files (batch_results.txt + batch_summary.txt) — never raises
    response["report_path"] = save_batch_report(
        results_list=results_list,
        classify_stats=classify_stats,
        model=body.model,
        folder_type=body.folder_type,
        filename=body.filename,
    )

    return response


# ---------------------------------------------------------------------------
# DELETE /api/batch/delete/{model}/{folder_type}/{filename}
# ---------------------------------------------------------------------------

@router.delete("/api/batch/delete/{model}/{folder_type}/{filename}")
async def batch_delete(model: str, folder_type: str, filename: str) -> Dict[str, Any]:
    """Delete a file from a batch sub-folder."""
    _validate_model(model)
    _validate_folder_type(folder_type)
    _validate_filename(filename)

    file_path = _batch_dir(model, folder_type) / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    try:
        file_path.unlink()
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {exc}") from exc

    return {"deleted": True, "filename": filename}
