"""
Training pipeline routes.

Endpoints:
  POST /api/training/start
  GET  /api/training/status/{job_id}
  POST /api/training/cancel/{job_id}
  GET  /api/training/results/{job_id}

Background training is run via subprocess (python ml_model.py) so that this
module never imports ml_model directly.  Job state is kept in TRAINING_JOBS.
"""

import os
import subprocess
import threading
import uuid
from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

TRAINING_JOBS: dict = {}

# ---------------------------------------------------------------------------
# Module definitions (mirrors ml_model.py pipeline phases)
# ---------------------------------------------------------------------------

MODULES = [
    (1, "Data Loading"),
    (2, "Exploration"),
    (3, "Preprocessing"),
    (4, "Training"),
    (5, "Testing"),
]

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class TrainingStartRequest(BaseModel):
    datasets: List[str]
    model_variant: str = Field(..., pattern="^(default|all)$")
    use_smote: bool = True
    use_feature_selection: bool = True
    use_hyperparameter_tuning: bool = False


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------


def _run_training(job_id: str, request: TrainingStartRequest) -> None:
    """
    Execute ml_model.py in a subprocess and parse stdout to track progress.
    Runs in a daemon Thread so it does not block the server.
    """
    job = TRAINING_JOBS[job_id]

    cmd = [
        "python",
        os.path.join(PROJECT_ROOT, "ml_model.py"),
        "--variant", request.model_variant,
    ]
    if request.use_smote:
        cmd.append("--smote")
    if request.use_feature_selection:
        cmd.append("--feature-selection")
    if request.use_hyperparameter_tuning:
        cmd.append("--hyperparameter-tuning")
    if request.datasets:
        cmd.extend(["--datasets"] + request.datasets)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=PROJECT_ROOT,
        )
        job["process"] = proc

        # Parse stdout lines for progress markers
        # ml_model.py is expected to print lines like:
        #   [MODULE 1] Data Loading
        #   [MODULE 2] Exploration
        #   ...
        #   accuracy=0.97
        #   f1_score=0.96
        results_acc: dict = {}
        for line in proc.stdout:
            if job["status"] == "cancelled":
                proc.kill()
                return

            line = line.rstrip()

            # Detect module progress
            for mod_num, mod_name in MODULES:
                if (
                    f"[MODULE {mod_num}]" in line
                    or f"Module {mod_num}" in line
                    or mod_name.lower() in line.lower()
                ):
                    job["current_module"] = mod_num
                    job["module_name"] = mod_name
                    job["progress_pct"] = round((mod_num - 1) / len(MODULES) * 100, 1)
                    job["message"] = line
                    break

            # Detect key metric lines
            if line.startswith("accuracy="):
                try:
                    results_acc["accuracy"] = float(line.split("=")[1])
                except ValueError:
                    pass
            if line.startswith("f1_score="):
                try:
                    results_acc["f1_score"] = float(line.split("=")[1])
                except ValueError:
                    pass

        proc.wait()
        if proc.returncode == 0:
            job["status"] = "completed"
            job["current_module"] = len(MODULES)
            job["module_name"] = MODULES[-1][1]
            job["progress_pct"] = 100.0
            job["message"] = "Training completed successfully"
            job["results"] = {
                "model_variant": request.model_variant,
                **results_acc,
            }
        else:
            if job["status"] != "cancelled":
                job["status"] = "failed"
                job["message"] = f"Training process exited with code {proc.returncode}"

    except Exception as exc:
        job["status"] = "failed"
        job["message"] = f"Training error: {exc}"


# ---------------------------------------------------------------------------
# POST /api/training/start
# ---------------------------------------------------------------------------


@router.post("/api/training/start")
async def training_start(body: TrainingStartRequest):
    """Start a training job in the background. Returns {job_id, status}."""
    job_id = str(uuid.uuid4())

    TRAINING_JOBS[job_id] = {
        "job_id": job_id,
        "status": "running",
        "current_module": 0,
        "module_name": "Initializing",
        "progress_pct": 0.0,
        "message": "Training job queued",
        "results": None,
        "process": None,
    }

    thread = threading.Thread(
        target=_run_training,
        args=(job_id, body),
        daemon=True,
    )
    thread.start()

    return {"job_id": job_id, "status": "started"}


# ---------------------------------------------------------------------------
# GET /api/training/status/{job_id}
# ---------------------------------------------------------------------------


@router.get("/api/training/status/{job_id}")
async def training_status(job_id: str):
    """Return current status of a training job."""
    job = TRAINING_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    return {
        "job_id": job_id,
        "status": job["status"],
        "current_module": job["current_module"],
        "module_name": job["module_name"],
        "progress_pct": job["progress_pct"],
        "message": job["message"],
    }


# ---------------------------------------------------------------------------
# POST /api/training/cancel/{job_id}
# ---------------------------------------------------------------------------


@router.post("/api/training/cancel/{job_id}")
async def training_cancel(job_id: str):
    """Cancel a running training job."""
    job = TRAINING_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    job["status"] = "cancelled"
    job["message"] = "Training cancelled by user"

    proc = job.get("process")
    if proc is not None:
        try:
            proc.kill()
        except Exception:
            pass

    return {"cancelled": True, "job_id": job_id}


# ---------------------------------------------------------------------------
# GET /api/training/results/{job_id}
# ---------------------------------------------------------------------------


@router.get("/api/training/results/{job_id}")
async def training_results(job_id: str):
    """Return training results for a completed job."""
    job = TRAINING_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

    return {
        "job_id": job_id,
        "status": job["status"],
        "results": job["results"],
        "message": job["message"],
    }
