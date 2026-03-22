"""
Reports routes.

GET /api/reports
  Optional query params:
    ?type=simul|batch|live|training  — filter by report type
    ?model=default|all               — filter by model variant
    ?limit=N                         — max results (default 50)
    ?offset=N                        — skip first N results (default 0)

GET /api/reports/{report_name}
  Returns all text files inside the named report folder.

GET /api/reports/{report_name}/minutes
  Lists all minute_*.txt files in the report folder.

GET /api/reports/{report_name}/minute/{time}
  Reads one minute file and returns parsed row data.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

router = APIRouter()

REPORTS_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports"
)

# ---------------------------------------------------------------------------
# Known type prefixes (in priority order)
# ---------------------------------------------------------------------------

# Longer prefixes must appear before shorter ones (e.g. "simulation" before "simul")
_TYPE_PREFIXES = ("simulation", "training", "batch", "live", "simul")

# Folder name pattern: {type}_{model}[_extra...]_{date}_{time}
# e.g. simul_default_2026-03-05_17-23-17
#      simul_all_labeled_2026-03-21_00-52-16
#      batch_all_batch_3_2026-03-21_00-40-07
#      batch_default_labeled_batch_2_2026-03-21_00-39-56
_FOLDER_RE = re.compile(
    r"^(?P<type>[a-z]+)_(?P<model>default|all)"
    r"(?P<extra>(?:_(?!\d{4}-)[^_]+)*)"
    r"_(?P<date>\d{4}-\d{2}-\d{2})_(?P<time>\d{2}-\d{2}-\d{2})$"
)

# Legacy patterns without model segment:
# e.g. training_20240101_120000_default  or  batch_20240102_080000
_LEGACY_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2}|\d{8}[_-]\d{6}|\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})")

# Minute-file pattern: minute_HH-MM.txt
_MINUTE_RE = re.compile(r"^minute_(\d{2}-\d{2})\.txt$")

# Summary extraction patterns
_FLOWS_RE = re.compile(r"Total Flows Classified[:\s]+(\d+)", re.IGNORECASE)
_THREATS_RE = re.compile(r"Threats Detected[:\s]+(\d+)", re.IGNORECASE)
_SUSPICIOUS_RE = re.compile(r"Suspicious Flows[:\s]+(\d+)", re.IGNORECASE)
_CLEAN_RE = re.compile(r"Clean Flows[:\s]+(\d+)", re.IGNORECASE)

# Per-minute breakdown patterns (indented lines in session_summary.txt)
_MINUTE_THREATS_RE = re.compile(r"^\s{4,}Threats:\s+(\d+)", re.MULTILINE)
_MINUTE_SUSPICIOUS_RE = re.compile(r"^\s{4,}Suspicious:\s+(\d+)", re.MULTILINE)
_MINUTE_CLEAN_RE = re.compile(r"^\s{4,}Clean:\s+(\d+)", re.MULTILINE)


# ---------------------------------------------------------------------------
# Helpers — folder-name parsing
# ---------------------------------------------------------------------------

def _parse_folder_name(name: str) -> Dict[str, Optional[str]]:
    """
    Extract type, model, and ISO date from a folder name.

    Supported formats:
      simul_default_2026-03-05_17-23-17
      batch_all_2026-03-05_18-00-00
      live_default_2026-03-05_19-00-00
      training_20240101_120000_default   (legacy)
      batch_20240102_080000              (legacy)
    """
    m = _FOLDER_RE.match(name)
    if m:
        folder_type = m.group("type")
        date_part = m.group("date")
        time_part = m.group("time").replace("-", ":")
        date_iso = f"{date_part}T{time_part}"
        extra = m.group("extra") or ""
        is_labeled = "labeled" in extra.lower()
        return {
            "type": folder_type,
            "model": m.group("model"),
            "date": date_part,
            "date_iso": date_iso,
            "is_labeled": is_labeled,
        }

    # Legacy fallback — derive type from prefix
    lower = name.lower()
    folder_type = "unknown"
    for prefix in _TYPE_PREFIXES:
        if lower.startswith(prefix):
            folder_type = prefix
            break

    # Try to find model
    model = None
    if "_default" in lower:
        model = "default"
    elif "_all" in lower:
        model = "all"

    # Try to find date
    date_match = _LEGACY_DATE_RE.search(name)
    date_iso = None
    date_str = None
    if date_match:
        raw = date_match.group(0)
        date_str = raw
        # Normalise to ISO
        date_iso = raw.replace("_", "T").replace("-", "-")

    return {
        "type": folder_type,
        "model": model,
        "date": date_str,
        "date_iso": date_iso,
        "is_labeled": "labeled" in lower,
    }


def _parse_summary_counts(summary: Optional[str]) -> Dict[str, Optional[int]]:
    """Extract total flows, threats, suspicious, and clean counts from summary text."""
    empty = {"flows": None, "threats": None, "suspicious": None, "clean": None}
    if not summary:
        return empty

    flows = None
    threats = None
    suspicious = None
    clean = None

    fm = _FLOWS_RE.search(summary)
    if fm:
        try:
            flows = int(fm.group(1))
        except ValueError:
            pass

    tm = _THREATS_RE.search(summary)
    if tm:
        try:
            threats = int(tm.group(1))
        except ValueError:
            pass

    sm = _SUSPICIOUS_RE.search(summary)
    if sm:
        try:
            suspicious = int(sm.group(1))
        except ValueError:
            pass

    cm = _CLEAN_RE.search(summary)
    if cm:
        try:
            clean = int(cm.group(1))
        except ValueError:
            pass

    return {"flows": flows, "threats": threats, "suspicious": suspicious, "clean": clean}


def _parse_metrics(summary: Optional[str]) -> dict:
    """Parse simple key=value lines from a summary string."""
    if not summary:
        return {}
    metrics: dict = {}
    for line in summary.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key in (
                "accuracy", "f1_score", "model_variant",
                "total_flows", "threat_percentage", "model_accuracy",
            ):
                metrics[key] = value
    return metrics


def _validate_report_name(name: str) -> None:
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid report name")


# ---------------------------------------------------------------------------
# Minute-file parsing
# ---------------------------------------------------------------------------

def _parse_minute_rows(content: str) -> List[Dict[str, Any]]:
    """
    Parse the ASCII table from a minute report file.

    Table header:
      Timestamp | Src IP | Src Port | Dst IP | Dst Port | Protocol |
      Class 1 | Conf 1 | Class 2 | Conf 2 | Class 3 | Conf 3

    Returns a list of dicts with snake_case keys.
    """
    rows: List[Dict[str, Any]] = []
    in_table = False

    for line in content.splitlines():
        stripped = line.strip()

        # Detect header separator line (dashes with + signs)
        if re.match(r"^-{4,}.*\+-.*$", stripped):
            in_table = True
            continue

        # Skip non-data lines before table
        if not in_table:
            continue

        # Skip separator and header lines
        if stripped.startswith("-") or stripped.startswith("="):
            continue
        if not stripped or "Timestamp" in stripped:
            continue

        # Split on | and strip each cell
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 12:
            continue

        # Parts: timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
        #        class1, conf1, class2, conf2, class3, conf3
        def _parse_conf(raw: str) -> Optional[float]:
            raw = raw.replace("%", "").strip()
            try:
                return round(float(raw) / 100.0, 6) if float(raw) > 1.0 else float(raw)
            except (ValueError, TypeError):
                return None

        rows.append({
            "timestamp": parts[0],
            "src_ip": parts[1],
            "src_port": parts[2],
            "dst_ip": parts[3],
            "dst_port": parts[4],
            "protocol": parts[5],
            "class1": parts[6],
            "conf1": _parse_conf(parts[7]),
            "class2": parts[8] if len(parts) > 8 else None,
            "conf2": _parse_conf(parts[9]) if len(parts) > 9 else None,
            "class3": parts[10] if len(parts) > 10 else None,
            "conf3": _parse_conf(parts[11]) if len(parts) > 11 else None,
            "actual_label": parts[12].strip() if len(parts) > 12 and parts[12].strip() not in ('', '-') else None,
        })

    return rows


# ---------------------------------------------------------------------------
# Fallback: compute counts from minute files when session_summary.txt is absent
# ---------------------------------------------------------------------------

def _compute_counts_from_minutes(folder_path: str) -> Dict[str, Optional[int]]:
    """
    When session_summary.txt is missing (e.g. simul session stopped early),
    estimate total flows and threats by parsing all minute_*.txt files.
    """
    total_flows = 0
    total_threats = 0
    found_any = False

    try:
        for fname in sorted(os.listdir(folder_path)):
            if not _MINUTE_RE.match(fname):
                continue
            fpath = os.path.join(folder_path, fname)
            try:
                with open(fpath, encoding="utf-8") as fh:
                    content = fh.read()
            except OSError:
                continue
            rows = _parse_minute_rows(content)
            if rows:
                found_any = True
            total_flows   += len(rows)
            total_threats += sum(1 for r in rows if r.get("class1", "Benign") != "Benign")
    except OSError:
        return {"flows": None, "threats": None}

    if not found_any:
        return {"flows": None, "threats": None}

    return {"flows": total_flows, "threats": total_threats}


# ---------------------------------------------------------------------------
# Per-class precision parser (for labeled summaries)
# ---------------------------------------------------------------------------

# Line format: "  ClassName    :  XX.XX% (correct/predicted) | Predicted:  NNN"
_PER_CLASS_LINE_RE = re.compile(
    r"^\s+(?P<cls>\S[^:\n]+?)\s*:\s*[\d.]+%\s*\((?P<correct>\d+)/\d+\)\s*\|\s*Predicted:\s*(?P<predicted>\d+)",
    re.MULTILINE,
)


def _sum_minute_counts(summary: Optional[str]) -> Dict[str, Optional[int]]:
    """
    For labeled simul/live sessions: sum per-minute Threats/Suspicious/Clean
    from the MINUTE-BY-MINUTE BREAKDOWN section of session_summary.txt.

    Matches indented lines like:
        Threats:    24
        Suspicious: 0
        Clean:      93
    """
    if not summary:
        return {"threats": None, "suspicious": None, "clean": None}

    def _sum_pattern(pattern: re.Pattern) -> Optional[int]:
        vals = [int(m.group(1)) for m in pattern.finditer(summary)]
        return sum(vals) if vals else None

    return {
        "threats": _sum_pattern(_MINUTE_THREATS_RE),
        "suspicious": _sum_pattern(_MINUTE_SUSPICIOUS_RE),
        "clean": _sum_pattern(_MINUTE_CLEAN_RE),
    }


def _compute_threats_from_per_class(summary: Optional[str]) -> Dict[str, Optional[int]]:
    """
    For labeled sessions: derive threat count from Per-Class Precision section.
    Threats = sum of 'Predicted:' values for all non-Benign classes.
    """
    if not summary:
        return {"flows": None, "threats": None}

    fm = re.search(r"Total Flows Classified[:\s]+(\d[\d,]*)", summary, re.IGNORECASE)
    total = int(fm.group(1).replace(",", "")) if fm else None

    threats = 0
    found_any = False
    for m in _PER_CLASS_LINE_RE.finditer(summary):
        cls_name = m.group("cls").strip()
        predicted = int(m.group("predicted"))
        found_any = True
        if cls_name.lower() != "benign":
            threats += predicted

    if not found_any:
        return {"flows": total, "threats": None}

    return {"flows": total, "threats": threats}


# ---------------------------------------------------------------------------
# GET /api/reports
# ---------------------------------------------------------------------------

@router.get("/api/reports")
async def list_reports(
    type: Optional[str] = Query(default=None),
    model: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List available report folders with optional filters and pagination."""
    reports = []

    if os.path.exists(REPORTS_DIR):
        for folder in sorted(os.listdir(REPORTS_DIR), reverse=True):
            folder_path = os.path.join(REPORTS_DIR, folder)
            if not os.path.isdir(folder_path):
                continue

            parsed = _parse_folder_name(folder)

            # Type filter
            if type is not None and parsed["type"] != type.lower():
                continue

            # Model filter
            if model is not None and parsed["model"] != model.lower():
                continue

            is_labeled: bool = parsed.get("is_labeled", False)

            # Read session_summary.txt first; fall back to batch_summary.txt
            summary: Optional[str] = None
            for candidate in ("session_summary.txt", "batch_summary.txt"):
                candidate_path = os.path.join(folder_path, candidate)
                if os.path.exists(candidate_path):
                    with open(candidate_path, "r", encoding="utf-8") as fh:
                        summary = fh.read()
                    break

            counts = _parse_summary_counts(summary)

            if is_labeled and counts.get("threats") is None:
                # Labeled summaries omit Threats/Suspicious/Clean — derive from per-class precision
                label_counts = _compute_threats_from_per_class(summary)
                if label_counts["threats"] is not None:
                    counts["threats"] = label_counts["threats"]
                if counts.get("flows") is None and label_counts["flows"] is not None:
                    counts["flows"] = label_counts["flows"]
                # Also try minute files as fallback (simul/live labeled sessions)
                if counts.get("flows") is None or counts.get("threats") is None:
                    minute_counts = _compute_counts_from_minutes(folder_path)
                    if counts.get("flows") is None:
                        counts["flows"] = minute_counts["flows"]
                    if counts.get("threats") is None:
                        counts["threats"] = minute_counts["threats"]

            # For labeled sessions with missing suspicious/clean: sum per-minute breakdown
            # (simul/live session_summary.txt has per-minute Suspicious:/Clean: lines)
            if is_labeled and (counts.get("suspicious") is None or counts.get("clean") is None):
                minute_totals = _sum_minute_counts(summary)
                if counts.get("suspicious") is None and minute_totals["suspicious"] is not None:
                    counts["suspicious"] = minute_totals["suspicious"]
                if counts.get("clean") is None and minute_totals["clean"] is not None:
                    counts["clean"] = minute_totals["clean"]
                # Also fill threats from minute sums if still missing
                if counts.get("threats") is None and minute_totals["threats"] is not None:
                    counts["threats"] = minute_totals["threats"]
            elif summary is None and counts["flows"] is None:
                # No summary at all — estimate from minute files
                counts = _compute_counts_from_minutes(folder_path)

            # Parse accuracy string for labeled sessions (e.g. "86.50")
            accuracy_str: Optional[str] = None
            if is_labeled and summary:
                am = re.search(r"Accuracy:\s+([\d.]+)%", summary, re.IGNORECASE)
                if am:
                    accuracy_str = am.group(1)

            # Compute total size of all files in the report folder (bytes)
            folder_size = 0
            try:
                for entry in os.scandir(folder_path):
                    if entry.is_file(follow_symlinks=False):
                        folder_size += entry.stat().st_size
            except OSError:
                pass

            reports.append({
                "name": folder,
                "path": folder_path,
                # New structured fields
                "type": parsed["type"],
                "model": parsed["model"],
                "date": parsed["date"],
                "date_iso": parsed["date_iso"],
                "is_labeled": is_labeled,
                "accuracy": accuracy_str,
                "flows": counts["flows"],
                "threats": counts["threats"],
                "suspicious": counts.get("suspicious"),
                "clean": counts.get("clean"),
                # Legacy / compatibility fields
                "report_type": parsed["type"],
                "size": folder_size,
                "summary": summary,
                "summary_preview": summary[:200] if summary else None,
                "metrics": _parse_metrics(summary),
            })

    return {"reports": reports[offset: offset + limit]}


# ---------------------------------------------------------------------------
# GET /api/reports/{report_name}
# ---------------------------------------------------------------------------

@router.get("/api/reports/{report_name}")
async def get_report(report_name: str) -> Dict[str, Any]:
    """Return all text files in a report folder."""
    _validate_report_name(report_name)

    report_path = os.path.join(REPORTS_DIR, report_name)
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        files: dict = {}
        for fname in os.listdir(report_path):
            fpath = os.path.join(report_path, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    files[fname] = fh.read()
            except UnicodeDecodeError:
                files[fname] = "<binary file>"

        return {"name": report_name, "files": files}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read report: {exc}") from exc


# ---------------------------------------------------------------------------
# GET /api/reports/{report_name}/minutes
# ---------------------------------------------------------------------------

@router.get("/api/reports/{report_name}/minutes")
async def list_minutes(report_name: str) -> Dict[str, Any]:
    """List all minute_*.txt files in a report folder."""
    _validate_report_name(report_name)

    report_path = Path(REPORTS_DIR) / report_name
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    minute_files = sorted(
        f.name for f in report_path.iterdir()
        if f.is_file() and _MINUTE_RE.match(f.name)
    )

    minutes = []
    for filename in minute_files:
        # Extract time token from e.g. "minute_17-23.txt" -> "17-23"
        m = _MINUTE_RE.match(filename)
        time_token = m.group(1) if m else filename
        minutes.append({
            "filename": filename,
            "url": f"/api/reports/{report_name}/minute/{time_token}",
        })

    return {"minutes": minutes}


# ---------------------------------------------------------------------------
# GET /api/reports/{report_name}/minute/{time}
# ---------------------------------------------------------------------------

@router.get("/api/reports/{report_name}/minute/{time}")
async def get_minute(report_name: str, time: str) -> Dict[str, Any]:
    """Read and parse a single minute report file."""
    _validate_report_name(report_name)

    # Validate time token — allow only HH-MM format or simple safe chars
    if not re.match(r"^[\d]{2}-[\d]{2}$", time):
        raise HTTPException(status_code=400, detail="Invalid time format; expected HH-MM")

    filename = f"minute_{time}.txt"
    report_path = Path(REPORTS_DIR) / report_name
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    file_path = report_path / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Minute file not found: {filename}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read file: {exc}") from exc

    rows = _parse_minute_rows(content)

    return {
        "filename": filename,
        "content": content,
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# GET /api/reports/{report_name}/batch-results
# ---------------------------------------------------------------------------

@router.get("/api/reports/{report_name}/batch-results")
async def get_batch_results(report_name: str) -> Dict[str, Any]:
    """Read and parse batch_results.txt for a batch report folder."""
    _validate_report_name(report_name)

    report_path = Path(REPORTS_DIR) / report_name
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    file_path = report_path / "batch_results.txt"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="batch_results.txt not found")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read file: {exc}") from exc

    rows = _parse_minute_rows(content)

    return {
        "filename": "batch_results.txt",
        "rows": rows,
        "total": len(rows),
    }
