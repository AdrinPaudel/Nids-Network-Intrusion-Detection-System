#!/bin/bash
# Wrapper script to run capture_flows.py with proper Python environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_PYTHON="$SCRIPT_DIR/venv/bin/python3"

# Check if venv exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "[ERROR] Virtual environment not found at: $VENV_PYTHON"
    echo "[ERROR] Please activate your venv first or create it"
    exit 1
fi

# Run capture_flows.py with full path to venv Python
sudo "$VENV_PYTHON" "$SCRIPT_DIR/capture_flows.py" "$@"
