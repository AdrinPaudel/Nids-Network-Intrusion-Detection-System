#!/bin/sh
# ==============================================================================
# NIDS Basic Setup - Linux
# ==============================================================================
# Sets up Python environment for classification (live + batch) using
# the pre-trained model. No dataset download or ML training needed.
#
# Usage: Run from project root:
#   chmod +x setup/setup_basic/setup_basic.sh
#   ./setup/setup_basic/setup_basic.sh
# ==============================================================================

set -e

# Navigate to project root (two levels up from setup/setup_basic/)
cd "$(dirname "$0")/../.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "  NIDS Basic Setup - Linux"
echo "================================================================================"
echo "  Sets up Python environment for classification using the pre-trained model."
echo "  No dataset or ML training required."
echo "================================================================================"
echo ""

# ==================================================================
# Step 1: Check Python & libpcap
# ==================================================================
echo "Step 1: Checking prerequisites..."
echo ""

FAIL=false

# --- Python ---
if command -v python3 > /dev/null 2>&1; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python $python_version"

    # Check venv module
    if ! python3 -c "import ensurepip" > /dev/null 2>&1; then
        echo "  [ERROR] Python 'venv' module is not installed."
        echo ""
        echo "    Install it:"
        echo "      Ubuntu/Debian:  sudo apt install python3-venv"
        echo "      Fedora/RHEL:    sudo dnf install python3"
        echo "      Arch Linux:     sudo pacman -S python"
        echo ""
        FAIL=true
    fi
else
    echo "  [ERROR] Python3 is not installed."
    echo ""
    echo "    Install it:"
    echo "      Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "      Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "      Arch Linux:     sudo pacman -S python"
    echo ""
    FAIL=true
fi

# --- libpcap ---
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
    echo "  [!] libpcap not found (needed for live capture only)"
    echo ""
    echo "    Install it:"
    echo "      Ubuntu/Debian:  sudo apt install libpcap-dev"
    echo "      Fedora/RHEL:    sudo dnf install libpcap-devel"
    echo "      Arch Linux:     sudo pacman -S libpcap"
    echo ""
    echo "    If you only need batch classification, you can skip this."
fi

if [ "$FAIL" = true ]; then
    echo ""
    echo "================================================================================"
    echo "  SETUP CANNOT CONTINUE — Missing required software (see above)"
    echo "================================================================================"
    exit 1
fi

echo ""

# ==================================================================
# Step 2: Create virtual environment
# ==================================================================
echo "Step 2: Creating virtual environment..."

if [ -d "venv" ]; then
    echo "  [OK] venv already exists"
else
    if ! python3 -m venv venv 2>&1; then
        echo "  [ERROR] Failed to create virtual environment."
        echo "    Try: sudo apt install python3-venv"
        exit 1
    fi
    if [ ! -d "venv" ]; then
        echo "  [ERROR] venv directory was not created"
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
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [ERROR] pip install failed"
    exit 1
fi
echo "  [OK] Dependencies installed"

echo ""

# ==================================================================
# Step 5: Verify packages
# ==================================================================
echo "Step 5: Verifying packages..."
echo ""

verify_ok=1

for pkg in pandas numpy sklearn imblearn matplotlib seaborn joblib tqdm pyarrow psutil cicflowmeter scapy; do
    if python3 -c "import $pkg" 2>/dev/null; then
        echo "  [OK] $pkg"
    else
        echo "  [!] $pkg MISSING"
        verify_ok=0
    fi
done
echo ""

if [ "$verify_ok" -eq 0 ]; then
    echo "  WARNING: Some packages are missing. Try running again or:"
    echo "    pip install -r requirements.txt"
    echo ""
else
    echo "  [OK] All packages verified!"
    echo ""
fi

# ==================================================================
# Done
# ==================================================================
echo "================================================================================"
echo "  Basic Setup Complete!"
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
echo "  Permissions (for live capture without sudo):"
echo "    sudo setcap cap_net_raw,cap_net_admin=eip \$(readlink -f \$(which python3))"
echo ""
echo "================================================================================"
echo ""
