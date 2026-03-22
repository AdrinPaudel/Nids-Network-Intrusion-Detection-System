"""
Data management routes — Task 3.

Endpoints:
  GET  /api/data/list-raw
  GET  /api/data/list-archived
  POST /api/data/archive/{filename}
  POST /api/data/restore/{filename}
  DELETE /api/data/delete/{filename}
  DELETE /api/data/delete-archived/{filename}
  GET  /api/data/preview/{filename}
  GET  /api/data/inspect/{filename}
  GET  /api/datasets                  (existing — kept for compatibility)
  POST /api/upload-dataset            (existing — kept for compatibility)
"""

import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import pandas as pd
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi import Path as FPath

router = APIRouter()

# DATA_DIR is set at startup (or overridden in tests via set_data_dir)
_data_dir: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
)


def set_data_dir(path: str) -> None:
    """Override the data directory — used in tests."""
    global _data_dir
    _data_dir = path


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def _default_dir() -> Path:
    p = Path(_data_dir) / "data_model_use" / "default"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _archived_dir() -> Path:
    p = Path(_data_dir) / "data_model_use" / "archived"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_filename(name: str) -> None:
    """Reject names that attempt directory traversal."""
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid filename: path traversal detected")


def _file_info(filepath: Path) -> Dict[str, Any]:
    stat = filepath.stat()
    return {
        "name": filepath.name,
        "size_mb": round(stat.st_size / 1024 / 1024, 4),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


# ---------------------------------------------------------------------------
# GET /api/data/list-raw
# ---------------------------------------------------------------------------

@router.get("/api/data/list-raw")
async def list_raw():
    """List CSV files in data/data_model_use/default/."""
    d = _default_dir()
    files = [_file_info(f) for f in sorted(d.iterdir()) if f.suffix == ".csv"]
    return {"files": files}


# ---------------------------------------------------------------------------
# GET /api/data/list-archived
# ---------------------------------------------------------------------------

@router.get("/api/data/list-archived")
async def list_archived():
    """List CSV files in data/data_model_use/archived/ (creates dir if needed)."""
    d = _archived_dir()
    files = [_file_info(f) for f in sorted(d.iterdir()) if f.suffix == ".csv"]
    return {"files": files}


# ---------------------------------------------------------------------------
# POST /api/data/archive/{filename}
# ---------------------------------------------------------------------------

@router.post("/api/data/archive/{filename}")
async def archive_file(filename: str = FPath(...)):
    """Move a file from default/ to archived/."""
    _validate_filename(filename)

    src = _default_dir() / filename
    if not src.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    dst = _archived_dir() / filename
    shutil.move(str(src), str(dst))

    return {"success": True, "filename": filename, "message": f"Archived {filename}"}


# ---------------------------------------------------------------------------
# POST /api/data/restore/{filename}
# ---------------------------------------------------------------------------

@router.post("/api/data/restore/{filename}")
async def restore_file(filename: str = FPath(...)):
    """Move a file from archived/ back to default/."""
    _validate_filename(filename)

    src = _archived_dir() / filename
    if not src.exists():
        raise HTTPException(status_code=404, detail=f"Archived file not found: {filename}")

    dst = _default_dir() / filename
    shutil.move(str(src), str(dst))

    return {"success": True, "filename": filename, "message": f"Restored {filename}"}


# ---------------------------------------------------------------------------
# DELETE /api/data/delete/{filename}
# ---------------------------------------------------------------------------

@router.delete("/api/data/delete/{filename}")
async def delete_file(
    filename: str = FPath(...),
    confirm: bool = Query(default=False),
):
    """Permanently delete a file from default/. Requires ?confirm=true."""
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Pass ?confirm=true to permanently delete a file",
        )

    _validate_filename(filename)

    target = _default_dir() / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    target.unlink()
    return {"success": True, "filename": filename, "message": f"Deleted {filename}"}


# ---------------------------------------------------------------------------
# DELETE /api/data/delete-archived/{filename}
# ---------------------------------------------------------------------------

@router.delete("/api/data/delete-archived/{filename}")
async def delete_archived_file(
    filename: str = FPath(...),
    confirm: bool = Query(default=False),
):
    """Permanently delete a file from archived/. Requires ?confirm=true."""
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Pass ?confirm=true to permanently delete an archived file",
        )

    _validate_filename(filename)

    target = _archived_dir() / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Archived file not found: {filename}")

    target.unlink()
    return {"success": True, "filename": filename, "message": f"Deleted archived {filename}"}


# ---------------------------------------------------------------------------
# GET /api/data/preview/{filename}
# ---------------------------------------------------------------------------

@router.get("/api/data/preview/{filename}")
async def preview_file(filename: str = FPath(...)):
    """Return the first 20 rows of a CSV as JSON."""
    _validate_filename(filename)

    target = _default_dir() / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    try:
        df = pd.read_csv(str(target), nrows=20)
        return {
            "filename": filename,
            "columns": list(df.columns),
            "rows": df.to_dict(orient="records"),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {exc}") from exc


# ---------------------------------------------------------------------------
# GET /api/data/inspect/{filename}
# ---------------------------------------------------------------------------

@router.get("/api/data/inspect/{filename}")
async def inspect_file(filename: str = FPath(...)):
    """Return column statistics (row count, columns, dtypes, null counts)."""
    _validate_filename(filename)

    target = _default_dir() / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")

    try:
        df = pd.read_csv(str(target))
        return {
            "filename": filename,
            "row_count": len(df),
            "columns": list(df.columns),
            "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
            "null_counts": {col: int(count) for col, count in df.isnull().sum().items()},
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to inspect file: {exc}") from exc


# ---------------------------------------------------------------------------
# Existing endpoints — kept for backwards compatibility
# ---------------------------------------------------------------------------

@router.get("/api/datasets")
async def list_datasets():
    """List available datasets (legacy endpoint)."""
    default_dir = _default_dir()
    archived_dir = _archived_dir()

    active = [
        {
            "name": f.name,
            "size_mb": round(f.stat().st_size / 1024 / 1024, 2),
            "path": str(f),
        }
        for f in sorted(default_dir.iterdir())
        if f.suffix == ".csv"
    ]

    archived = [
        {
            "name": f.name,
            "size_mb": round(f.stat().st_size / 1024 / 1024, 2),
            "path": str(f),
        }
        for f in sorted(archived_dir.iterdir())
        if f.suffix == ".csv"
    ]

    return {"active": active, "archived": archived}


@router.post("/api/upload-dataset")
async def upload_dataset(file: UploadFile = File(...)):
    """Upload a new dataset CSV to data/data_model_use/default/."""
    target_dir = _default_dir()
    filepath = target_dir / file.filename

    try:
        contents = await file.read()
        filepath.write_bytes(contents)
        size_mb = len(contents) / 1024 / 1024
        return {
            "success": True,
            "filename": file.filename,
            "size_mb": round(size_mb, 4),
            "path": str(filepath),
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Upload failed: {exc}") from exc
