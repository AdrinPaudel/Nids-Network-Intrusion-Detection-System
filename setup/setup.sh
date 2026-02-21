#!/bin/sh
# Setup script for NIDS Project on Linux
# Checks prerequisites, creates venv, installs deps, tests interface detection
# POSIX-compatible — works with sh (dash), bash, zsh, etc.

set -e  # Exit on error

# Navigate to project root (one level up from setup/)
cd "$(dirname "$0")/.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "NIDS Project Setup - Linux"
echo "================================================================================"
echo ""

# ==================================================================
# Step 1: Check Python & libpcap
# ==================================================================
echo "Step 1: Checking required software..."
echo ""

FAIL=false

# --- Python ---
if command -v python3 > /dev/null 2>&1; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python $python_version"

    # Check for venv module (separate package on Debian/Ubuntu)
    if ! python3 -c "import ensurepip" > /dev/null 2>&1; then
        echo "  [ERROR] Python 'venv' module is not installed."
        echo "          On Debian/Ubuntu, venv is a separate package."
        echo ""
        echo "    Run this command (copy-paste the WHOLE line):"
        echo ""
        echo "      sudo apt install python3-venv"
        echo ""
        echo "    If that doesn't work, try the version-specific package:"
        echo ""
        echo "      sudo apt install python${python_version%.*}-venv"
        echo ""
        echo "    Other distros (venv is already included, just reinstall python):"
        echo "      Fedora/RHEL:  sudo dnf install python3"
        echo "      Arch Linux:   sudo pacman -S python"
        echo ""
        FAIL=true
    fi
else
    echo "  [ERROR] Python3 is not installed."
    echo ""
    echo "    Install it yourself:"
    echo "      Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "      Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "      Arch Linux:     sudo pacman -S python"
    echo "      Other:          https://www.python.org/downloads/"
    echo ""
    FAIL=true
fi

# --- libpcap (needed by Scapy for packet capture) ---
LIBPCAP_FOUND=false
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    LIBPCAP_FOUND=true
elif [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ] || \
     [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.1 ] || \
     [ -f /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 ] || \
     [ -f /usr/lib/libpcap.so ] || \
     [ -f /usr/lib/libpcap.so.1 ]; then
    LIBPCAP_FOUND=true
fi

if [ "$LIBPCAP_FOUND" = true ]; then
    echo "  [OK] libpcap found"
else
    echo "  [ERROR] libpcap is not installed."
    echo "          Scapy (packet capture library) needs libpcap to work."
    echo ""
    echo "    Copy-paste the install command for your distro:"
    echo ""
    echo "      Ubuntu/Debian:  sudo apt install libpcap-dev"
    echo "      Fedora/RHEL:    sudo dnf install libpcap-devel"
    echo "      Arch Linux:     sudo pacman -S libpcap"
    echo ""
    FAIL=true
fi

if [ "$FAIL" = true ]; then
    echo "================================================================================"
    echo "  SETUP CANNOT CONTINUE"
    echo "  Install the missing software above, then re-run this script."
    echo "================================================================================"
    exit 1
fi

# ==================================================================
# Step 2: Create virtual environment
# ==================================================================
echo ""
echo "Step 2: Creating virtual environment..."
echo ""

if [ -d "venv" ]; then
    echo "  [OK] Already exists — skipping"
else
    if ! python3 -m venv venv 2>&1; then
        echo ""
        echo "  [ERROR] Failed to create virtual environment."
        echo ""
        echo "    Most likely cause: the python3-venv package is not installed."
        echo "    Fix:"
        echo "      Ubuntu/Debian:  sudo apt install python3-venv"
        echo "      Then re-run this script."
        echo ""
        exit 1
    fi
    if [ ! -d "venv" ]; then
        echo "  [ERROR] venv directory was not created"
        exit 1
    fi
    echo "  [OK] Virtual environment created"
fi

# ==================================================================
# Step 3: Activate venv & install pip dependencies
# ==================================================================
echo ""
echo "Step 3: Installing Python dependencies..."
echo ""

. venv/bin/activate

pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [ERROR] pip install failed"
    exit 1
fi
echo "  [OK] Dependencies installed"

# ==================================================================
# Step 4: Verify network interfaces exist
# ==================================================================
echo ""
echo "Step 4: Verifying network interface availability..."
echo ""

# Use 'ip link show' which doesn't require root — just checks if interfaces exist
if command -v ip >/dev/null 2>&1; then
    IFACE_COUNT=$(ip link show | grep -c "^[0-9]:" || true)
    if [ "$IFACE_COUNT" -gt 1 ]; then
        echo "  [OK] Detected $IFACE_COUNT network interface(s)"
    else
        echo "  [WARNING] Only loopback interface detected. This may be a VM or container."
    fi
else
    # Fallback: use ifconfig/iwconfig if ip command not available
    if command -v ifconfig >/dev/null 2>&1; then
        if ifconfig | grep -q "eth\|en\|wlan"; then
            echo "  [OK] Network interfaces detected"
        else
            echo "  [WARNING] Limited interface detection. Check your network setup."
        fi
    else
        echo "  [OK] Interface check skipped (ip/ifconfig not available)"
    fi
fi

# ==================================================================
# Done
# ==================================================================
echo ""
echo "================================================================================"
echo "  Setup Complete!  Everything is working."
echo "================================================================================"
echo ""
echo "  IMPORTANT: You must activate the virtual environment before running."
echo ""

case "$0" in
    *setup.sh*)
        echo "  You ran this script with 'sh' or 'bash', so the venv is NOT active."
        echo "  Activate it now:"
        echo ""
        echo "      source venv/bin/activate    (bash/zsh)"
        echo "      . venv/bin/activate          (any shell)"
        echo ""
        ;;
    *)
        echo "  venv is active. You're ready to go."
        echo ""
        ;;
esac

echo "  Quick test (120 sec capture):"
echo "    Linux:"
echo "      sudo ./venv/bin/python classification.py"
echo ""
echo "    Windows/Mac:"
echo "      python classification.py"
echo ""
echo "  See all options:"
echo "    python classification.py --help"
echo ""
echo "  ML model pipeline:"
echo "    python ml_model.py --help"
echo ""
echo "================================================================================"
echo ""
