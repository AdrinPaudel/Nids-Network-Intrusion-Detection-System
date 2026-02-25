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
# Step 1: Enable TCP Timestamps (CRITICAL for classification)
# ==================================================================
echo "Step 1: Verifying TCP Timestamps..."
echo ""
echo "  TCP timestamps add 12 bytes to the TCP header (20 -> 32 bytes)."
echo "  This is CRITICAL because the CICIDS2018 training data was generated"
echo "  from Linux attackers that always include TCP timestamps."
echo "  The model's #1 feature (Fwd Seg Size Min) depends on this."
echo ""

if [ -f /proc/sys/net/ipv4/tcp_timestamps ]; then
    ts_val=$(cat /proc/sys/net/ipv4/tcp_timestamps)
    if [ "$ts_val" = "1" ]; then
        echo "  [OK] TCP timestamps already enabled"
    else
        echo "  [ACTION] TCP timestamps disabled! Enabling and persisting..."
        sudo sysctl -w net.ipv4.tcp_timestamps=1
        sudo sysctl -p
        echo "  [OK] TCP timestamps enabled"
    fi
else
    echo "  [INFO] Cannot check TCP timestamps (not on Linux)"
fi
echo ""

# ==================================================================
# Step 2: Check Python
# ==================================================================
echo "Step 2: Checking Python..."

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

echo "  Installing base packages (from project root)..."
pip install -r requirements.txt 2>&1 | grep -v "already satisfied" || true
if [ $? -ne 0 ]; then
    echo "  [!] Base requirements install had issues"
fi
echo ""

echo "  Installing attack dependencies (paramiko + psutil)..."
if [ -f "setup/setup_attacker/requirements.txt" ]; then
    pip install -r setup/setup_attacker/requirements.txt 2>&1 | grep -v "already satisfied" || true
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Attack requirements install failed"
        echo ""
        echo "  Try manually:"
        echo "    pip install -r setup/setup_attacker/requirements.txt"
        echo ""
    else
        echo "  [OK] Attack dependencies installed"
    fi
else
    echo "  [ERROR] setup/setup_attacker/requirements.txt not found!"
    echo ""
    echo "  Trying individual packages..."
    pip install paramiko psutil
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
for script in setup/setup_attacker/device_attack.py setup/setup_attacker/config.py; do
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
echo "  1. Activate venv (every new terminal):"
echo "       source venv/bin/activate"
echo ""
echo "  2. For details on running features:"
echo "       See: PROJECT_RUN.md (in project root)"
echo ""
echo "  3. To set up other components:"
echo "       See: setup/SETUPS.md"
echo ""
echo "  4. For project overview:"
echo "       See: README.md (in project root)"
echo ""
echo "================================================================================"
echo ""
