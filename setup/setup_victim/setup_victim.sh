#!/bin/sh
# ==============================================================================
# Victim Device Setup - Linux
# ==============================================================================
# Run this ON THE TARGET DEVICE (VM or server) to check readiness for attacks.
#
# Usage:
#   chmod +x setup/setup_victim/setup_victim.sh
#   sudo ./setup/setup_victim/setup_victim.sh
# ==============================================================================

cd "$(dirname "$0")/../.."  || exit 1

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
    echo "  [ERROR] Run with sudo:"
    echo "    sudo ./setup/setup_victim/setup_victim.sh"
    exit 1
fi

echo "  [OK] Running as root"
echo ""

# Use venv python if available, otherwise system python
if [ -f "venv/bin/python3" ]; then
    echo "  Using venv Python..."
    . venv/bin/activate 2>/dev/null
    python3 setup/setup_victim/setup_victim.py
    exit_code=$?
elif [ -f "venv/bin/python" ]; then
    echo "  Using venv Python..."
    . venv/bin/activate 2>/dev/null
    python setup/setup_victim/setup_victim.py
    exit_code=$?
else
    echo "  Using system Python (venv not found)..."
    python3 setup/setup_victim/setup_victim.py
    exit_code=$?
fi

echo ""
echo "================================================================================"
if [ $exit_code -eq 0 ]; then
    echo "  [OK] Victim setup check complete"
else
    echo "  [!] Some issues were found (see above)"
fi
echo "================================================================================"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Start NIDS on this device to detect attacks:"
echo "       See: PROJECT_RUN.md (in project root)"
echo ""
echo "  2. To understand all setup options:"
echo "       See: setup/SETUPS.md"
echo ""
echo "  3. For project overview:"
echo "       See: README.md (in project root)"
echo ""
