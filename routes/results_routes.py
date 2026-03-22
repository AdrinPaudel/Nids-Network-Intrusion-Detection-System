"""
Results routes — serve ML pipeline output files.

Endpoints:
  GET /api/results/structure    — JSON tree of what exists in results/
  GET /api/results/file         — read a text file from results/
  GET /api/results/image-url    — resolve static URL for an image file

Directory layout under RESULTS_DIR:
  results/
    exploration/          (shared by both variants)
    preprocessing/        (5-class / default variant)
    training/             (5-class / default variant)
    testing/              (5-class / default variant)
    preprocessing_all/    (6-class / all variant)
    training_all/         (6-class / all variant)
    testing_all/          (6-class / all variant)

Query param ?variant=default|all selects which subdirectory names to use.
exploration/ is always exploration/ regardless of variant.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

_SAFE_FILENAME_RE = re.compile(r'^[\w][\w\-\.]{0,253}$')

router = APIRouter()

# Base directory — overridden in tests
RESULTS_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results"
)

# ---------------------------------------------------------------------------
# Variant → subdirectory name mapping
# ---------------------------------------------------------------------------

# Sections that differ per variant (logical_name -> actual_subdir)
_VARIANT_SUBDIRS: Dict[str, Dict[str, str]] = {
    "default": {
        "exploration":    "exploration",
        "preprocessing":  "preprocessing",
        "training":       "training",
        "testing":        "testing",
    },
    "all": {
        "exploration":    "exploration",
        "preprocessing":  "preprocessing_all",
        "training":       "training_all",
        "testing":        "testing_all",
    },
}

# Logical section order
_SECTION_ORDER = ("exploration", "preprocessing", "training", "testing")

# Image extensions
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".svg", ".gif"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_section(base: Path, subdir: str) -> tuple:
    """
    Walk a single result sub-directory and return two lists:
      - text files (everything that is NOT an image)
      - image files (.png/.jpg/.jpeg/.svg/.gif)
    """
    d = base / subdir
    text_files: List[str] = []
    image_files: List[str] = []

    if not d.is_dir():
        return text_files, image_files

    for entry in sorted(d.iterdir()):
        if entry.is_file():
            if entry.suffix.lower() in _IMAGE_EXTS:
                image_files.append(entry.name)
            else:
                text_files.append(entry.name)

    return text_files, image_files


def _build_variant_structure(base: Path, variant: str) -> Dict[str, Any]:
    """
    Build the JSON section structure for one variant (default or all).

    Returns a dict with logical section names as keys, plus an 'images' sub-dict.
    """
    subdir_map = _VARIANT_SUBDIRS[variant]
    sections: Dict[str, Any] = {}
    images: Dict[str, List[str]] = {}

    for logical_name in _SECTION_ORDER:
        actual_subdir = subdir_map[logical_name]
        text_files, image_files = _collect_section(base, actual_subdir)
        sections[logical_name] = text_files
        if image_files:
            images[logical_name] = image_files

    if images:
        sections["images"] = images

    return sections


def _resolve_subdir(section: str, variant: str) -> str:
    """Return the actual filesystem subdirectory name for a logical section + variant."""
    mapping = _VARIANT_SUBDIRS.get(variant, _VARIANT_SUBDIRS["default"])
    return mapping.get(section, section)


def _validate_path(path: str) -> None:
    """Reject path traversal attempts."""
    if not path:
        raise HTTPException(status_code=400, detail="Path parameter is required")
    if path.startswith("/") or path.startswith("\\"):
        raise HTTPException(status_code=400, detail="Absolute paths are not allowed")
    if ".." in path.split("/") or ".." in path.split("\\"):
        raise HTTPException(status_code=400, detail="Path traversal is not allowed")
    # Catch encoded traversal
    if ".." in path:
        raise HTTPException(status_code=400, detail="Path traversal is not allowed")


# ---------------------------------------------------------------------------
# GET /api/results/structure
# ---------------------------------------------------------------------------

@router.get("/api/results/structure")
async def results_structure(
    variant: Optional[str] = Query(default=None, description="'default' or 'all'; omit for both"),
) -> Dict[str, Any]:
    """
    Return a JSON tree describing which result files exist.

    ?variant=default  — return only default variant structure
    ?variant=all      — return only all-class variant structure
    (no param)        — return both variants

    Shape:
    {
      "default": {
        "exploration": [...], "preprocessing": [...],
        "training": [...], "testing": [...],
        "images": {"testing": ["confusion_matrix.png", ...]}
      },
      "all": {
        "exploration": [...], "preprocessing": [...from preprocessing_all/],
        "training": [...from training_all/], "testing": [...from testing_all/],
        "images": {...}
      }
    }
    """
    base = Path(RESULTS_DIR)

    if variant == "default":
        return {"default": _build_variant_structure(base, "default")}
    if variant == "all":
        return {"all": _build_variant_structure(base, "all")}

    # Return both variants
    return {
        "default": _build_variant_structure(base, "default"),
        "all": _build_variant_structure(base, "all"),
    }


# ---------------------------------------------------------------------------
# GET /api/results/file
# ---------------------------------------------------------------------------

@router.get("/api/results/file")
async def results_file(
    path: str = Query(..., description="Relative path, e.g. testing/results.txt"),
    variant: str = Query(default="default", description="'default' or 'all'"),
) -> Dict[str, Any]:
    """
    Read and return the content of a text file from the results directory.

    The ?variant param remaps subdirectory names:
      variant=default: testing/ → testing/
      variant=all:     testing/ → testing_all/

    exploration/ is always exploration/ regardless of variant.

    Returns:
      {"path": "...", "content": "...", "size": N}
    """
    _validate_path(path)

    if variant not in ("default", "all"):
        variant = "default"

    # Remap the first path component based on variant
    parts = path.replace("\\", "/").split("/", 1)
    section = parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    actual_subdir = _resolve_subdir(section, variant)
    resolved_rel = f"{actual_subdir}/{rest}" if rest else actual_subdir

    candidate = Path(RESULTS_DIR) / resolved_rel

    if not candidate.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")

    # Safety check — resolved path must still be inside RESULTS_DIR
    resolved_abs = candidate.resolve()
    results_root = Path(RESULTS_DIR).resolve()
    if not resolved_abs.is_relative_to(results_root):
        raise HTTPException(status_code=400, detail="Path traversal is not allowed")

    try:
        content = resolved_abs.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not a readable text file")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read file: {exc}") from exc

    return {
        "path": path,
        "content": content,
        "size": len(content.encode("utf-8")),
    }


# ---------------------------------------------------------------------------
# GET /api/results/image-url
# ---------------------------------------------------------------------------

@router.get("/api/results/image-url")
async def results_image_url(
    section: str = Query(..., description="Logical section name, e.g. 'testing'"),
    filename: str = Query(..., description="Image filename, e.g. 'confusion_matrix.png'"),
    variant: str = Query(default="default", description="'default' or 'all'"),
) -> Dict[str, str]:
    """
    Resolve and return the static URL for an image file.

    Returns:
      {"url": "/results-static/{actual_subdir}/{filename}"}

    The actual_subdir is determined by the variant mapping:
      variant=default, section=testing  → testing
      variant=all,     section=testing  → testing_all
      any variant,     section=exploration → exploration
    """
    if variant not in ("default", "all"):
        variant = "default"

    known_sections = set(_VARIANT_SUBDIRS["default"].keys())
    if section not in known_sections:
        raise HTTPException(status_code=400, detail="Unknown section name")

    if not _SAFE_FILENAME_RE.match(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    actual_subdir = _resolve_subdir(section, variant)
    url = f"/results-static/{actual_subdir}/{filename}"

    return {"url": url}
