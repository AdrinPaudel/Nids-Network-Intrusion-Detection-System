#!/bin/sh
# ==============================================================================
# Victim Device Setup - Linux (All Distros)
# ==============================================================================
# Run this ON THE TARGET DEVICE (VM or server) to check readiness for attacks.
# Works on: Ubuntu/Debian, Fedora/RHEL/CentOS, Arch, openSUSE, Alpine
#
# Usage:
#   chmod +x setup/setup_victim/setup_victim.sh
#   sudo ./setup/setup_victim/setup_victim.sh
# ==============================================================================

# Navigate to project root (two levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT" || { echo "[ERROR] Cannot cd to project root"; exit 1; }

echo ""
echo "================================================================================"
echo "  Victim Device Setup - Linux"
echo "================================================================================"
echo "  Checks if this device is ready to receive attacks."
echo "  Will NOT change anything without asking first."
echo "================================================================================"
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    echo "  [ERROR] This script must be run as root."
    echo "    sudo ./setup/setup_victim/setup_victim.sh"
    exit 1
fi
echo "  [OK] Running as root"
echo ""

# Find Python (venv first, then system)
PYTHON=""

if [ -x "$PROJECT_ROOT/venv/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/venv/bin/python3"
elif [ -x "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON="$PROJECT_ROOT/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "  [ERROR] Python not found."
    echo "  Install Python 3.10+ using your package manager."
    exit 1
fi

echo "  Using Python: $PYTHON"
echo ""

# Activate venv if it exists (so imports work)
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    . "$PROJECT_ROOT/venv/bin/activate" 2>/dev/null
fi

# Run the setup script
"$PYTHON" "$PROJECT_ROOT/setup/setup_victim/setup_victim.py"
exit_code=$?

echo ""
echo "================================================================================"
if [ $exit_code -eq 0 ]; then
    echo "  [OK] Victim setup check complete."
else
    echo "  [!] Some issues were found - see above."
fi
echo "================================================================================"
echo ""
