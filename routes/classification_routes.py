"""
Classification routes — batch classify and simulation endpoints.

Task 1 fix: /api/simulate now accepts a JSON request body (Pydantic model)
instead of query parameters, matching what the React frontend sends.
"""

import io
import os
from datetime import datetime
from typing import Optional

import pandas as pd
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

router = APIRouter()

# Module-level classifier references — injected by the app on startup
_classifier_default = None
_classifier_all = None

# DATA_DIR can be overridden by tests via the patch mechanism or set_data_dir
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def set_classifiers(default_clf, all_clf) -> None:
    """Inject classifier instances (called at startup and in tests)."""
    global _classifier_default, _classifier_all
    _classifier_default = default_clf
    _classifier_all = all_clf


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SimulateRequest(BaseModel):
    dataset_name: str
    model_type: str = Field(default="default", pattern="^(default|all)$")
    flow_rate: int = Field(default=5, ge=1, le=20)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_filename(name: str) -> None:
    """Reject filenames that attempt path traversal."""
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal detected")


# ---------------------------------------------------------------------------
# Batch classification
# ---------------------------------------------------------------------------

@router.post("/api/batch-classify")
async def batch_classify(
    file: UploadFile = File(...),
    model_type: str = Query(default="default"),
):
    """Classify a batch of flows from an uploaded CSV file."""
    if not _classifier_default:
        raise HTTPException(status_code=503, detail="Classifiers not loaded")

    try:
        contents = await file.read()
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))

        classifier = _classifier_all if model_type == "all" else _classifier_default
        results = classifier.classify(df)

        threat_count = int(len(results[results["prediction"] != "Benign"]))
        threat_percentage = (threat_count / len(results)) * 100 if len(results) > 0 else 0.0

        return {
            "success": True,
            "filename": file.filename,
            "total_flows": len(results),
            "threat_count": threat_count,
            "threat_percentage": round(threat_percentage, 2),
            "model_type": model_type,
            "timestamp": datetime.now().isoformat(),
            "results": results.to_dict(orient="records")[:100],
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Classification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Simulation — FIXED: body is now a JSON Pydantic model, not query params
# ---------------------------------------------------------------------------

@router.post("/api/simulate")
async def simulate(body: SimulateRequest):
    """
    Run a simulation on a dataset.

    The request body must be JSON:
        { "dataset_name": "...", "model_type": "default", "flow_rate": 5 }

    Previously this endpoint used query parameters, which the React frontend
    does not send — this is the bug fix described in Task 1.
    """
    if not _classifier_default:
        raise HTTPException(status_code=503, detail="Classifiers not loaded")

    _validate_filename(body.dataset_name)

    simul_dir = os.path.join(DATA_DIR, "simul")
    dataset_path = os.path.join(simul_dir, body.dataset_name)

    if not os.path.exists(dataset_path):
        raise HTTPException(
            status_code=400,
            detail=f"Dataset not found: {body.dataset_name}",
        )

    try:
        df = pd.read_csv(dataset_path)
        classifier = _classifier_all if body.model_type == "all" else _classifier_default
        results = classifier.classify(df)

        total_flows = len(results)
        estimated_duration = total_flows / max(body.flow_rate, 1)

        threat_mask = results["prediction"] != "Benign"
        threat_counts = (
            results.loc[threat_mask, "prediction"].value_counts().to_dict()
        )

        return {
            "success": True,
            "dataset": body.dataset_name,
            "model_type": body.model_type,
            "flow_rate": body.flow_rate,
            "total_flows": total_flows,
            "estimated_duration_seconds": round(estimated_duration),
            "benign_flows": int(len(results[~threat_mask])),
            "threat_flows": int(len(results[threat_mask])),
            "threat_breakdown": threat_counts,
            "results": results.to_dict(orient="records"),
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Simulation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Simulation dataset listing
# ---------------------------------------------------------------------------

@router.get("/api/simulation-datasets")
async def list_simulation_datasets():
    """List available simulation datasets."""
    simul_dir = os.path.join(DATA_DIR, "simul")
    datasets = []

    if os.path.exists(simul_dir):
        for name in os.listdir(simul_dir):
            if name.endswith(".csv"):
                fp = os.path.join(simul_dir, name)
                datasets.append({
                    "name": name,
                    "size_mb": round(os.path.getsize(fp) / 1024 / 1024, 2),
                })

    return {"datasets": datasets}
