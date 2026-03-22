"""
Simulation routes — polling-based (no WebSocket).

Endpoints:
  GET  /api/simulation/datasets
  POST /api/simulation/start
  POST /api/simulation/stop/{session_id}
  GET  /api/simulation/status/{session_id}
  GET  /api/simulation/events/{session_id}?from=0

Runs: python -u classification.py --simul --model {default|all} [--labeled] --duration {N}

The subprocess stdout is parsed by a background thread; results are stored in
SIMUL_SESSIONS[session_id]["events"].  The frontend polls /events every 500 ms
via plain fetch() through the CRA proxy — no WebSocket needed.
"""

import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()

BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# In-memory session store
SIMUL_SESSIONS: Dict[str, Dict[str, Any]] = {}

# Strip ANSI colour codes written by classification.py
_ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

# ---------------------------------------------------------------------------
# Static dataset catalogue
# ---------------------------------------------------------------------------

DATASETS: List[Dict[str, Any]] = [
    {"id": "default_unlabeled", "label": "5 Class (Default) — Unlabeled", "model": "default", "labeled": False},
    {"id": "default_labeled",   "label": "5 Class (Default) — Labeled",   "model": "default", "labeled": True},
    {"id": "all_unlabeled",     "label": "6 Class (All) — Unlabeled",     "model": "all",     "labeled": False},
    {"id": "all_labeled",       "label": "6 Class (All) — Labeled",       "model": "all",     "labeled": True},
]

# ---------------------------------------------------------------------------
# Stateful stdout line parser
#
# Simul status format (classification.py):
#   [SESSION] 30s elapsed | Source: yes | Flows fed: 1,234/9,036,367 | Classified: 1,234 | Remaining: 4s
#
# Threat block (multi-line):
#   ⚡ THREAT DETECTED ─────────────────────────────────
#     Flow: 192.168.1.1:12345 → 8.8.8.8:80 (Proto:6)
#     Attack: DDoS  Confidence: 95.3%  [2026-03-21 12:45:00]
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(
    r"\[SESSION\]\s+(\d+)s elapsed.*?Flows fed:\s+([\d,]+)[^|]*\|\s*Classified:\s+([\d,]+).*?Remaining:\s+(\d+)s"
)
_COMPLETE_RE = re.compile(r"\[SESSION\]\s+FINAL Classified:\s+(\d+)")

# Threat block sub-patterns
_FLOW_RE   = re.compile(
    r"[Ff]low\s*[:\-]\s*([\d.]+):(\d+)\s+\S+\s+([\d.]+):(\d+)\s+\(?[Pp]roto[:\s]*(\d+)"
)
_ATTACK_RE = re.compile(
    r"(?:[Aa]ttack|[Ll]abel)\s*[:\-]\s*(.+?)\s+\(?[Cc]onf(?:idence)?\s*[:\-]\s*([\d.]+)%?\)?"
)
_CONF_RE   = re.compile(r"[Cc]onf(?:idence)?\s*[:\-]\s*([\d.]+)%?")
_LABEL_RE  = re.compile(r"(?:[Aa]ttack|[Ll]abel|[Pp]rediction)\s*[:\-]\s*(\S[^\n\|]*?)\s*(?:\||$)")
_TS_RE     = re.compile(r"\[(\d{4}-\d{2}-\d{2}[\s_T]\d{2}:\d{2}:\d{2})\]")

_MAX_THREAT_LINES = 10  # Safety flush after this many lines inside a threat block


class _LineParser:
    """Stateful stdout line parser. One instance per simulation session."""

    def __init__(self) -> None:
        self._pending: Optional[Dict[str, Any]] = None
        self._pending_lines: int = 0
        # Running totals for complete event enrichment
        self.last_flows:      int = 0
        self.last_classified: int = 0
        self.red_count:       int = 0
        self.yellow_count:    int = 0

    # ------------------------------------------------------------------
    def _flush_pending(self) -> List[Dict[str, Any]]:
        """Emit the accumulated threat event (if any) and reset state."""
        if self._pending is None:
            return []
        event = dict(self._pending)
        self._pending = None
        self._pending_lines = 0
        if event.get("level") == "RED":
            self.red_count += 1
        else:
            self.yellow_count += 1
        return [event]

    # ------------------------------------------------------------------
    def feed(self, line: str) -> List[Dict[str, Any]]:
        """Parse one stdout line. Returns a list of 0 or more events."""
        if not line:
            return []
        clean = _ANSI_ESCAPE.sub("", line)
        stripped = clean.strip()

        # --- status ---
        m = _STATUS_RE.search(clean)
        if m:
            result = self._flush_pending()  # close any open threat block
            flows      = int(m.group(2).replace(",", ""))
            classified = int(m.group(3).replace(",", ""))
            self.last_flows      = flows
            self.last_classified = classified
            result.append({
                "type":       "status",
                "elapsed":    int(m.group(1)),
                "packets":    0,
                "flows":      flows,
                "classified": classified,
                "remaining":  int(m.group(4)),
            })
            return result

        # --- complete (fired on "[SESSION] FINAL Classified: N" after pipeline drain) ---
        m = _COMPLETE_RE.search(clean)
        if m:
            final_classified = int(m.group(1))
            self.last_classified = final_classified
            result = self._flush_pending()
            green = max(0, final_classified - self.red_count - self.yellow_count)
            result.append({
                "type":   "complete",
                "flows":  final_classified,
                "red":    self.red_count,
                "yellow": self.yellow_count,
                "green":  green,
            })
            return result

        # --- threat block header ---
        if "THREAT DETECTED" in stripped:
            result = self._flush_pending()
            self._pending = {"type": "threat", "level": "RED"}
            self._pending_lines = 0
            return result

        if "SUSPICIOUS ACTIVITY" in stripped:
            result = self._flush_pending()
            self._pending = {"type": "threat", "level": "YELLOW"}
            self._pending_lines = 0
            return result

        # --- inside a threat block ---
        if self._pending is not None:
            self._pending_lines += 1

            # Flow line: src_ip:src_port → dst_ip:dst_port (Proto:N)
            m = _FLOW_RE.search(clean)
            if m:
                self._pending.update({
                    "src_ip":   m.group(1),
                    "src_port": int(m.group(2)),
                    "dst_ip":   m.group(3),
                    "dst_port": int(m.group(4)),
                    "protocol": int(m.group(5)),
                })
                return []

            # Attack + Confidence on one line: "Attack: DDoS  Confidence: 95.3%  [ts]"
            m = _ATTACK_RE.search(clean)
            if m:
                confidence = float(m.group(2))
                if confidence > 1.0:
                    confidence /= 100.0
                self._pending["prediction"] = m.group(1).strip()
                self._pending["confidence"] = round(confidence, 4)
                tm = _TS_RE.search(clean)
                if tm:
                    self._pending["timestamp"] = tm.group(1)
                return self._flush_pending()

            # Prediction label on its own line
            ml = _LABEL_RE.search(clean)
            if ml and "prediction" not in self._pending:
                self._pending["prediction"] = ml.group(1).strip()

            # Confidence on its own line
            mc = _CONF_RE.search(clean)
            if mc and "confidence" not in self._pending:
                confidence = float(mc.group(1))
                if confidence > 1.0:
                    confidence /= 100.0
                self._pending["confidence"] = round(confidence, 4)
                tm = _TS_RE.search(clean)
                if tm:
                    self._pending["timestamp"] = tm.group(1)
                # Emit if we already have the label too
                if "prediction" in self._pending:
                    return self._flush_pending()

            # Safety: flush after too many lines to avoid holding events forever
            if self._pending_lines >= _MAX_THREAT_LINES:
                return self._flush_pending()

        return []


# ---------------------------------------------------------------------------
# Background stdout reader
# ---------------------------------------------------------------------------

def _read_stdout(session_id: str) -> None:
    session = SIMUL_SESSIONS.get(session_id)
    if session is None:
        return

    proc = session.get("process")
    if proc is None:
        return

    parser = _LineParser()
    finished = False

    try:
        while True:
            # Intentionally break as soon as status leaves "running".
            # Simulation stop uses proc.kill() (hard kill), so there is no graceful
            # flush window — unlike live_routes._read_stdout which drains after stop.
            if session.get("status") not in ("running",):
                break

            line = proc.stdout.readline()

            if line == "" and proc.poll() is not None:
                break

            if not line:
                time.sleep(0.05)
                continue

            for event in parser.feed(line.rstrip("\n")):
                if len(session["events"]) < 2000:
                    session["events"].append(event)

                if event["type"] == "complete":
                    session["status"] = "completed"
                    finished = True
                    break

            if finished:
                break

    except Exception as exc:
        logging.exception("Simulation stdout reader crashed: %s", exc)
        session["events"].append({"type": "error", "message": "Reader thread error"})
    finally:
        if session.get("status") == "running":
            session["status"] = "completed"


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class SimulStartRequest(BaseModel):
    model:            str = Field(default="default", pattern="^(default|all)$")
    labeled:          bool = False
    duration_seconds: int  = Field(default=120, ge=10, le=3600)
    flow_rate:        int  = Field(default=5,   ge=1,  le=100)


# ---------------------------------------------------------------------------
# GET /api/simulation/datasets
# ---------------------------------------------------------------------------

@router.get("/api/simulation/datasets")
def list_simulation_datasets() -> List[Dict[str, Any]]:
    return DATASETS


# ---------------------------------------------------------------------------
# POST /api/simulation/start
# ---------------------------------------------------------------------------

@router.post("/api/simulation/start")
def start_simulation(body: SimulStartRequest) -> Dict[str, Any]:
    """Spawn classification.py as a subprocess and return a session_id."""
    session_id = str(uuid.uuid4())

    cmd = [
        sys.executable,
        "-u",
        os.path.join(BASE_DIR, "classification.py"),
        "--simul",
        "--model",      body.model,
        "--duration",   str(body.duration_seconds),
        "--flow-rate",  str(body.flow_rate),
    ]
    if body.labeled:
        cmd.append("--labeled")

    # Force UTF-8 so classification.py can write ⚠/⚡ on Windows without
    # crashing (default Windows pipe encoding = cp1252 which rejects U+26A0).
    utf8_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=utf8_env,
            cwd=BASE_DIR,
        )
    except OSError as exc:
        logging.exception("Failed to start simulation subprocess: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start simulation process") from exc

    session: Dict[str, Any] = {
        "session_id":       session_id,
        "status":           "running",
        "model":            body.model,
        "labeled":          body.labeled,
        "duration_seconds": body.duration_seconds,
        "flow_rate":        body.flow_rate,
        "started_at":       datetime.now().isoformat(),
        "process":          proc,
        "events":           [],
    }
    SIMUL_SESSIONS[session_id] = session

    thread = threading.Thread(target=_read_stdout, args=(session_id,), daemon=True)
    thread.start()

    return {"session_id": session_id, "status": "started"}


# ---------------------------------------------------------------------------
# POST /api/simulation/stop/{session_id}
# ---------------------------------------------------------------------------

@router.post("/api/simulation/stop/{session_id}")
def stop_simulation(session_id: str) -> Dict[str, Any]:
    session = SIMUL_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    session["status"] = "stopped"
    proc = session.get("process")
    if proc is not None:
        try:
            proc.kill()
        except OSError:
            pass

    return {"stopped": True}


# ---------------------------------------------------------------------------
# GET /api/simulation/status/{session_id}
# ---------------------------------------------------------------------------

@router.get("/api/simulation/status/{session_id}")
def get_simulation_status(session_id: str) -> Dict[str, Any]:
    session = SIMUL_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "session_id":  session_id,
        "status":      session["status"],
        "event_count": len(session["events"]),
        "model":       session["model"],
        "labeled":     session["labeled"],
        "started_at":  session["started_at"],
    }


# ---------------------------------------------------------------------------
# GET /api/simulation/events/{session_id}?from=0
#
# Returns events since index `from`.  Frontend polls this every 500 ms.
# ---------------------------------------------------------------------------

@router.get("/api/simulation/events/{session_id}")
def get_simulation_events(
    session_id: str,
    from_index: int = Query(default=0, alias="from", ge=0),
) -> Dict[str, Any]:
    session = SIMUL_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    all_events = session["events"]
    new_events  = all_events[from_index:]
    next_from   = from_index + len(new_events)
    done        = session["status"] in ("completed", "stopped")

    return {
        "events":    new_events,
        "next_from": next_from,
        "done":      done,
        "status":    session["status"],
    }
