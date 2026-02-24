#!/bin/sh
# ==============================================================================
# NIDS Attacker Setup - Linux
# ==============================================================================
# Sets up the attacker machine with dependencies to launch attacks
# against the target device.
#
# Usage: Run from project root:
#   chmod +x setup/setup_attacker/setup_attacker.sh
#   ./setup/setup_attacker/setup_attacker.sh
# ==============================================================================

set -e

cd "$(dirname "$0")/../.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "  NIDS Attacker Setup - Linux"
echo "================================================================================"
echo "  Sets up your machine to launch attacks against a target device."
echo "================================================================================"
echo ""

# ==================================================================
# Step 1: Check Python
# ==================================================================
echo "Step 1: Checking Python..."

if ! command -v python3 > /dev/null 2>&1; then
    echo "  [ERROR] Python3 is not installed."
    echo "    Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "    Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "    Arch Linux:     sudo pacman -S python"
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "  [OK] Python $python_version"
echo ""

# ==================================================================
# Step 2: Create/Check venv
# ==================================================================
echo "Step 2: Checking virtual environment..."

if [ -d "venv" ]; then
    echo "  [OK] venv already exists"
else
    echo "  Creating virtual environment..."
    python3 -m venv venv
    if [ ! -d "venv" ]; then
        echo "  [ERROR] Failed to create venv"
        exit 1
    fi
    echo "  [OK] venv created"
fi
echo ""

# ==================================================================
# Step 3: Install dependencies
# ==================================================================
echo "Step 3: Installing dependencies..."

. venv/bin/activate

pip install --upgrade pip --quiet

echo "  Installing base packages (requirements.txt)..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [!] Base requirements install failed"
fi

echo "  Installing attack dependencies..."
if [ -f "setup/setup_attacker/requirements.txt" ]; then
    pip install -r setup/setup_attacker/requirements.txt
    if [ $? -ne 0 ]; then
        echo "  [!] Attack requirements install failed"
    else
        echo "  [OK] Attack dependencies installed"
    fi
else
    echo "  [!] setup/setup_attacker/requirements.txt not found"
fi
echo ""

# ==================================================================
# Step 4: Verify packages and scripts
# ==================================================================
echo "Step 4: Verifying installation..."
echo ""

verify_ok=1

echo "  Checking attack packages:"
if python3 -c "import paramiko" 2>/dev/null; then
    echo "    [OK] paramiko (SSH attacks)"
else
    echo "    [!] paramiko MISSING"
    verify_ok=0
fi

for pkg in requests psutil; do
    if python3 -c "import $pkg" 2>/dev/null; then
        echo "    [OK] $pkg"
    else
        echo "    [!] $pkg MISSING"
        verify_ok=0
    fi
done

echo ""
echo "  Checking attack scripts:"
for script in setup/setup_attacker/device_attack.py setup/setup_attacker/discover_and_save.py setup/setup_attacker/config.py; do
    if [ -f "$script" ]; then
        echo "    [OK] $(basename $script)"
    else
        echo "    [!] $(basename $script) not found"
        verify_ok=0
    fi
done

echo ""
if [ "$verify_ok" -eq 0 ]; then
    echo "  WARNING: Some packages or scripts are missing"
    echo "  Try: pip install paramiko"
    echo ""
else
    echo "  [OK] All packages and scripts verified!"
    echo ""
fi

# ==================================================================
# Done
# ==================================================================
echo "================================================================================"
echo "  Attacker Setup Complete!"
echo "================================================================================"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Activate venv:"
echo "       source venv/bin/activate"
echo ""
echo "  2. Discover target devices on the network:"
echo "       python setup/setup_attacker/discover_and_save.py"
echo ""
echo "  3. Update target IP in setup/setup_attacker/config.py"
echo ""
echo "  4. Launch attacks:"
echo "       python setup/setup_attacker/device_attack.py"
echo ""
echo "  Make sure the victim device is set up first!"
echo "  Run: sudo ./setup/setup_victim/setup_victim.sh on the target device."
echo ""
echo "================================================================================"
echo ""
