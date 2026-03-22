"""
NIDS FastAPI Backend
====================
Entry point — mounts all route modules.

Provides REST API endpoints for:
- Batch Classification (CSV upload)
- Simulation
- Data Management
- Reports
- System / Dashboard
- Training Pipeline
- Live Classification (WebSocket)
"""

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from routes.classification_routes import router as classification_router
from routes.classification_routes import set_classifiers
from routes.data_routes import router as data_router
from routes.data_routes import set_data_dir
from routes.reports_routes import router as reports_router
from routes.results_routes import router as results_router
from routes.system_routes import router as system_router
from routes.training_routes import router as training_router
from routes.live_routes import router as live_router
from routes.batch_routes import router as batch_router
from routes.batch_routes import set_classifiers as set_batch_classifiers
from routes.batch_routes import set_preprocessors as set_batch_preprocessors
from routes.simulation_routes import router as simulation_router

# ============================================================================
# APP SETUP
# ============================================================================

app = FastAPI(
    title="NIDS API",
    description="Network Intrusion Detection System API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# GLOBALS
# ============================================================================

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")

# Point data_routes at our actual data directory
set_data_dir(DATA_DIR)

# ============================================================================
# STARTUP — load classifiers
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Load ML models on startup and inject into classification routes."""
    try:
        print("[STARTUP] Loading classifiers...")
        from classification.classification_batch.classifier import BatchClassifier
        clf_default = BatchClassifier(use_all_classes=False)
        clf_all = BatchClassifier(use_all_classes=True)
        set_classifiers(clf_default, clf_all)
        set_batch_classifiers(clf_default, clf_all)
        print("[STARTUP] Classifiers loaded successfully")
    except Exception as exc:
        print(f"[STARTUP] Warning: Could not load classifiers: {exc}")
        set_classifiers(None, None)
        set_batch_classifiers(None, None)

    try:
        print("[STARTUP] Loading batch preprocessors...")
        from classification.classification_batch.preprocessor import BatchPreprocessor
        prep_default = BatchPreprocessor(use_all_classes=False)
        prep_all = BatchPreprocessor(use_all_classes=True)
        set_batch_preprocessors(prep_default, prep_all)
        print("[STARTUP] Batch preprocessors loaded successfully")
    except Exception as exc:
        print(f"[STARTUP] Warning: Could not load batch preprocessors: {exc}")
        set_batch_preprocessors(None, None)

# ============================================================================
# ROUTERS
# ============================================================================

app.include_router(system_router)
app.include_router(data_router)
app.include_router(classification_router)
app.include_router(reports_router)
app.include_router(results_router)
app.include_router(training_router)
app.include_router(live_router)
app.include_router(batch_router)
app.include_router(simulation_router)

# Serve PNG/image files from results/ as static files
# Frontend can load e.g. /results-static/testing/confusion_matrix_multiclass.png
if os.path.isdir(RESULTS_DIR):
    app.mount(
        "/results-static",
        StaticFiles(directory=RESULTS_DIR),
        name="results",
    )

# ============================================================================
# DEV ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
