"""
System routes — health, dashboard stats, models list.

Task 5: dashboard stats are now dynamic (real model count, dataset count,
accuracy from training metadata, system uptime via psutil).
"""

import json
import os
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

router = APIRouter()

PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR: str = os.path.join(PROJECT_ROOT, "data")
TRAINED_MODELS_DIR: str = os.path.join(PROJECT_ROOT, "trained_models")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/api/health")
async def health_check():
    return {
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
    }


# ---------------------------------------------------------------------------
# Dashboard stats (dynamic — Task 5)
# ---------------------------------------------------------------------------

def _count_datasets() -> int:
    default_dir = Path(DATA_DIR) / "data_model_use" / "default"
    if not default_dir.exists():
        return 0
    return sum(1 for f in default_dir.iterdir() if f.suffix == ".csv")


def _count_models() -> int:
    if not os.path.exists(TRAINED_MODELS_DIR):
        return 0
    return sum(
        1 for d in os.listdir(TRAINED_MODELS_DIR)
        if os.path.isdir(os.path.join(TRAINED_MODELS_DIR, d))
        and d.startswith("trained_model_")
    )


def _read_model_metrics() -> dict:
    """
    Try to read accuracy/F1 from the default model's training_metadata.json.
    Returns defaults when the file is absent or malformed.
    """
    metadata_path = Path(TRAINED_MODELS_DIR) / "trained_model_default" / "training_metadata.json"
    if not metadata_path.exists():
        return {"model_accuracy": None, "f1_score": None, "last_training": None}

    try:
        with open(metadata_path, "r", encoding="utf-8") as fh:
            meta = json.load(fh)

        return {
            "model_accuracy": meta.get("accuracy") or meta.get("model_accuracy"),
            "f1_score": meta.get("f1_score") or meta.get("f1"),
            "last_training": meta.get("training_date") or meta.get("timestamp"),
        }
    except Exception:
        return {"model_accuracy": None, "f1_score": None, "last_training": None}


def _system_uptime_seconds() -> float:
    if _PSUTIL_AVAILABLE:
        return round(datetime.now().timestamp() - psutil.boot_time(), 1)
    return 0.0


@router.get("/api/dashboard-stats")
async def dashboard_stats():
    metrics = _read_model_metrics()
    dataset_count = _count_datasets()
    model_count = _count_models()
    uptime = _system_uptime_seconds()

    # Compute total size in GB of default datasets
    default_dir = Path(DATA_DIR) / "data_model_use" / "default"
    total_bytes = sum(
        f.stat().st_size
        for f in default_dir.iterdir()
        if f.is_file() and f.suffix == ".csv"
    ) if default_dir.exists() else 0
    total_gb = round(total_bytes / 1024 / 1024 / 1024, 2)

    return {
        "active_model": "5-Class",
        "model_count": model_count,
        "total_flows": 0,
        "threats_detected": 0,
        "threat_percentage": 0.0,
        "model_accuracy": metrics["model_accuracy"],
        "f1_score": metrics["f1_score"],
        "last_training": metrics["last_training"],
        "datasets_available": dataset_count,
        "datasets_size_gb": total_gb,
        "live_capture_status": "Inactive",
        "uptime_seconds": uptime,
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Models list
# ---------------------------------------------------------------------------

@router.get("/api/models")
async def list_models():
    models = []

    if os.path.exists(TRAINED_MODELS_DIR):
        for folder in os.listdir(TRAINED_MODELS_DIR):
            folder_path = os.path.join(TRAINED_MODELS_DIR, folder)
            if not os.path.isdir(folder_path) or not folder.startswith("trained_model_"):
                continue
            models.append({
                "name": folder,
                "type": "all" if "all" in folder else "default",
            })

    return {"models": models}
