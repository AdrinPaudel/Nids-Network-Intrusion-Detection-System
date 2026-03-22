"""
main.py — NIDS unified launcher
================================
Starts the backend and frontend with a single command.

Usage
-----
    python main.py            # production: serves built frontend from FastAPI (port 8000)
    python main.py --dev      # dev mode: backend on :8000 + npm start on :3000 (hot reload)
    python main.py --port 9000  # change backend port (default: 8000)
    python main.py --no-browser # skip auto-opening the browser
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
BUILD_DIR    = os.path.join(FRONTEND_DIR, "build")

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(description="NIDS unified launcher")
    p.add_argument("--dev",        action="store_true", help="Dev mode: run npm start alongside backend")
    p.add_argument("--port",       type=int, default=8000, help="Backend port (default: 8000)")
    p.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    return p.parse_args()

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _banner(mode, port):
    print()
    print("=" * 55)
    print("  NIDS — Network Intrusion Detection System")
    print("=" * 55)
    if mode == "prod":
        print(f"  Mode    : Production  (built frontend via FastAPI)")
        print(f"  URL     : http://localhost:{port}")
    else:
        print(f"  Mode    : Development  (hot reload)")
        print(f"  Backend : http://localhost:{port}")
        print(f"  Frontend: http://localhost:3000")
    print("=" * 55)
    print("  Press Ctrl+C to stop")
    print("=" * 55)
    print()

# ---------------------------------------------------------------------------
# Production mode — mount frontend/build inside FastAPI, single process
# ---------------------------------------------------------------------------

def run_production(port: int, open_browser: bool):
    if not os.path.isdir(BUILD_DIR):
        print("[ERROR] frontend/build/ not found.")
        print("        Run:  cd frontend && npm run build")
        print("        Then re-run main.py")
        sys.exit(1)

    # Import the FastAPI app and mount the built frontend
    sys.path.insert(0, BASE_DIR)
    from app import app
    from fastapi.staticfiles import StaticFiles

    # Serve the React build: all unknown paths fall through to index.html
    # Mount static assets first (JS, CSS, media), then catch-all for React Router
    app.mount(
        "/static",
        StaticFiles(directory=os.path.join(BUILD_DIR, "static")),
        name="react-static",
    )

    # Catch-all: return index.html for any path the API didn't handle
    from fastapi.responses import FileResponse
    from fastapi import Request

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react(request: Request, full_path: str):
        index = os.path.join(BUILD_DIR, "index.html")
        return FileResponse(index)

    import uvicorn

    if open_browser:
        threading.Thread(
            target=_open_browser_after_delay,
            args=(f"http://localhost:{port}", 2),
            daemon=True,
        ).start()

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


# ---------------------------------------------------------------------------
# Dev mode — spawn npm start + uvicorn as subprocesses
# ---------------------------------------------------------------------------

_procs = []

def _stop_all(signum=None, frame=None):
    print("\n[NIDS] Shutting down...")
    for p in _procs:
        try:
            if sys.platform == "win32":
                p.send_signal(signal.CTRL_C_EVENT)
            else:
                p.terminate()
        except Exception:
            pass
    time.sleep(1)
    for p in _procs:
        try:
            p.kill()
        except Exception:
            pass
    print("[NIDS] Stopped.")
    sys.exit(0)


def run_dev(port: int, open_browser: bool):
    signal.signal(signal.SIGINT,  _stop_all)
    signal.signal(signal.SIGTERM, _stop_all)

    # Start backend
    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app",
         "--host", "0.0.0.0", "--port", str(port), "--reload"],
        cwd=BASE_DIR,
    )
    _procs.append(backend)
    print(f"[NIDS] Backend started  (pid {backend.pid})")

    # Start frontend
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend = subprocess.Popen(
        [npm_cmd, "start"],
        cwd=FRONTEND_DIR,
    )
    _procs.append(frontend)
    print(f"[NIDS] Frontend started (pid {frontend.pid})")

    if open_browser:
        threading.Thread(
            target=_open_browser_after_delay,
            args=("http://localhost:3000", 5),
            daemon=True,
        ).start()

    # Wait — exit if either process dies
    while True:
        if backend.poll() is not None:
            print("[NIDS] Backend exited unexpectedly — stopping.")
            _stop_all()
        if frontend.poll() is not None:
            print("[NIDS] Frontend exited unexpectedly — stopping.")
            _stop_all()
        time.sleep(1)


# ---------------------------------------------------------------------------
# Browser helper
# ---------------------------------------------------------------------------

def _open_browser_after_delay(url: str, delay: float):
    time.sleep(delay)
    print(f"[NIDS] Opening browser → {url}")
    webbrowser.open(url)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = _parse_args()
    mode = "dev" if args.dev else "prod"
    _banner(mode, args.port)

    if mode == "prod":
        run_production(port=args.port, open_browser=not args.no_browser)
    else:
        run_dev(port=args.port, open_browser=not args.no_browser)
