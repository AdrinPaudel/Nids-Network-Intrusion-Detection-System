"""
Live classification routes — polling-based (no WebSocket).

Endpoints:
  GET  /api/live/interfaces
  POST /api/live/start
  POST /api/live/stop/{session_id}
  GET  /api/live/status/{session_id}
  GET  /api/live/events/{session_id}?from=0

Runs: python -u classification.py --live --model <variant> --duration <secs> --interface <iface>

Admin / Npcap is required for live packet capture on Windows.  If the subprocess
exits with a permission error the error event is stored and returned on the next poll.
"""

import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

router = APIRouter()

BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

_ANSI_ESCAPE   = re.compile(r'\x1b\[[0-9;]*m')
_SAFE_IFACE_RE = re.compile(r'^[\w\s\{\}\-\.]{1,100}$')

# ---------------------------------------------------------------------------
# Stateful stdout line parser
#
# Live status format (classification.py):
#   [SESSION] Xs elapsed | Sniffer: yes | Packets: N | Flows: N | Classified: N | Remaining: Xs
#
# Threat block (multi-line):
#   ⚡ THREAT DETECTED ─────────────────────────────────
#     Flow: 192.168.1.1:12345 → 8.8.8.8:80 (Proto:6)
#     Attack: DDoS  Confidence: 95.3%  [2026-03-21 12:45:00]
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(
    r"\[SESSION\]\s+(\d+)s elapsed.*?Packets:\s+([\d,]+).*?Flows:\s+([\d,]+).*?Classified:\s+([\d,]+).*?Remaining:\s+(\d+)s"
)
_COMPLETE_RE = re.compile(r"\[SESSION\]\s+Duration reached")

# Threat block sub-patterns (shared with simulation parser)
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
    """Stateful stdout line parser. One instance per live session."""

    def __init__(self) -> None:
        self._pending: Optional[Dict[str, Any]] = None
        self._pending_lines: int = 0
        # Running totals for complete event enrichment
        self.last_packets:    int = 0
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
            packets    = int(m.group(2).replace(",", ""))
            flows      = int(m.group(3).replace(",", ""))
            classified = int(m.group(4).replace(",", ""))
            remaining  = int(m.group(5))
            self.last_packets    = packets
            self.last_flows      = flows
            self.last_classified = classified
            result.append({
                "type":       "status",
                "elapsed":    int(m.group(1)),
                "packets":    packets,
                "flows":      flows,
                "classified": classified,
                "remaining":  remaining,
            })
            return result

        # --- complete ---
        if _COMPLETE_RE.search(clean):
            result = self._flush_pending()
            green = max(0, self.last_classified - self.red_count - self.yellow_count)
            result.append({
                "type":    "complete",
                "packets": self.last_packets,
                "flows":   self.last_classified,
                "red":     self.red_count,
                "yellow":  self.yellow_count,
                "green":   green,
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
    session = LIVE_SESSIONS.get(session_id)
    if session is None:
        return

    proc = session.get("process")
    if proc is None:
        return

    parser = _LineParser()
    # Drain deadline: set when status changes to "stopped" so we don't block forever
    # if the subprocess pipe never closes (e.g. pipe stall on Windows after CTRL_C_EVENT).
    drain_deadline: Optional[float] = None

    try:
        while True:
            # Enforce drain timeout — bail if subprocess pipe hasn't closed in time
            if drain_deadline is not None and time.monotonic() > drain_deadline:
                logging.warning("Live stdout drain timed out for session %s", session_id)
                break

            line = proc.stdout.readline()

            # Process has exited and stdout is fully drained — stop reading
            if line == "" and proc.poll() is not None:
                break

            if not line:
                # Set drain deadline the first time we see an empty read after stop
                if session.get("status") == "stopped" and drain_deadline is None:
                    drain_deadline = time.monotonic() + _GRACEFUL_STOP_TIMEOUT + 5
                time.sleep(0.05)
                continue

            for event in parser.feed(line.rstrip("\n")):
                if len(session["events"]) < 2000:
                    session["events"].append(event)

                if event["type"] == "complete":
                    session["status"] = "completed"
                    # Do NOT break here — keep draining stdout so that flows flushed
                    # during graceful shutdown (after "Duration reached") are captured.

    except Exception as exc:
        logging.exception("Live stdout reader crashed: %s", exc)
        session["events"].append({"type": "error", "message": "Reader thread error"})
    finally:
        if session.get("status") == "running":
            session["status"] = "stopped"


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class LiveStartRequest(BaseModel):
    interface:        str
    model_variant:    str = Field(..., pattern="^(default|all)$")
    duration_seconds: int = Field(..., ge=1, le=86400)


# ---------------------------------------------------------------------------
# GET /api/live/interfaces
# ---------------------------------------------------------------------------

@router.get("/api/live/interfaces")
async def live_interfaces() -> Dict[str, Any]:
    if _PSUTIL_AVAILABLE:
        interfaces = list(psutil.net_if_addrs().keys())
    else:
        interfaces = ["eth0", "lo"]
    return {"interfaces": interfaces}


# ---------------------------------------------------------------------------
# POST /api/live/start
# ---------------------------------------------------------------------------

@router.post("/api/live/start")
async def live_start(body: LiveStartRequest) -> Dict[str, Any]:
    # Validate interface name
    if not _SAFE_IFACE_RE.match(body.interface):
        raise HTTPException(status_code=400, detail="Invalid interface name")
    if _PSUTIL_AVAILABLE:
        known = set(psutil.net_if_addrs().keys())
        if body.interface not in known:
            raise HTTPException(status_code=400, detail="Unknown network interface")

    session_id = str(uuid.uuid4())

    cmd = [
        sys.executable,
        "-u",
        os.path.join(BASE_DIR, "classification.py"),
        "--live",
        "--model",     body.model_variant,
        "--duration",  str(body.duration_seconds),
        "--interface", body.interface,
    ]

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
        logging.exception("Failed to start live subprocess: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to start classification process") from exc

    session: Dict[str, Any] = {
        "session_id":       session_id,
        "status":           "running",
        "interface":        body.interface,
        "model_variant":    body.model_variant,
        "duration_seconds": body.duration_seconds,
        "started_at":       datetime.now(timezone.utc).isoformat(),
        "process":          proc,
        "events":           [],
    }
    LIVE_SESSIONS[session_id] = session

    thread = threading.Thread(target=_read_stdout, args=(session_id,), daemon=True)
    thread.start()

    return {"session_id": session_id}


# ---------------------------------------------------------------------------
# POST /api/live/stop/{session_id}
# ---------------------------------------------------------------------------

_GRACEFUL_STOP_TIMEOUT = 15  # seconds to wait for subprocess to flush flows before hard kill


def _graceful_terminate(proc) -> None:
    """
    Send a graceful stop signal to the subprocess so it can flush in-flight flows,
    then wait for it to exit. Falls back to SIGKILL if the process hangs.

    On Windows, proc.terminate() == TerminateProcess() (instant kill) so we use
    CTRL_C_EVENT instead, which Python receives as KeyboardInterrupt and triggers
    the clean shutdown path in ClassificationSession.
    On Unix, SIGTERM is received as KeyboardInterrupt by Python's signal handler.
    """
    try:
        if sys.platform == "win32":
            # CTRL_C_EVENT sends Ctrl+C to the process, triggering KeyboardInterrupt
            os.kill(proc.pid, signal.CTRL_C_EVENT)
        else:
            proc.terminate()  # SIGTERM → KeyboardInterrupt in the subprocess
        proc.wait(timeout=_GRACEFUL_STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        # Subprocess didn't exit cleanly — hard kill as last resort
        logging.warning("Live subprocess did not stop within %ss — sending SIGKILL", _GRACEFUL_STOP_TIMEOUT)
        try:
            proc.kill()
        except OSError:
            pass
    except OSError:
        pass


@router.post("/api/live/stop/{session_id}")
async def live_stop(session_id: str) -> Dict[str, Any]:
    session = LIVE_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    session["status"] = "stopped"
    proc = session.get("process")
    if proc is not None:
        # Use graceful shutdown in a daemon thread so the HTTP response is immediate.
        # The reader thread (_read_stdout) will drain remaining stdout until the process exits.
        t = threading.Thread(target=_graceful_terminate, args=(proc,), daemon=True)
        t.start()

    return {"stopped": True, "session_id": session_id}


# ---------------------------------------------------------------------------
# GET /api/live/status/{session_id}
# ---------------------------------------------------------------------------

@router.get("/api/live/status/{session_id}")
async def live_status(session_id: str) -> Dict[str, Any]:
    session = LIVE_SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    events = session["events"]
    status_events = [e for e in events if e.get("type") == "status"]
    threat_events  = [e for e in events if e.get("type") == "threat"]

    return {
        "session_id":   session_id,
        "status":       session["status"],
        "interface":    session["interface"],
        "model_variant": session["model_variant"],
        "total_flows":  status_events[-1]["flows"] if status_events else 0,
        "classified":   status_events[-1]["classified"] if status_events else 0,
        "threats":      len(threat_events),
        "started_at":   session["started_at"],
    }


# ---------------------------------------------------------------------------
# GET /api/live/events/{session_id}?from=0
#
# Returns events since index `from`.  Frontend polls this every 500 ms.
# ---------------------------------------------------------------------------

@router.get("/api/live/events/{session_id}")
async def live_events(
    session_id: str,
    from_index: int = Query(default=0, alias="from", ge=0),
) -> Dict[str, Any]:
    session = LIVE_SESSIONS.get(session_id)
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
