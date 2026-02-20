#!/bin/bash
# Setup script for NIDS Project on Linux
# Creates virtual environment and installs dependencies

# Navigate to project root (one level up from setup/)
cd "$(dirname "$0")/.." || exit 1

echo ""
echo "================================================================================"
echo "NIDS Project Setup - Linux"
echo "================================================================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Install it with: sudo apt-get install python3 python3-venv python3-dev"
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python: $python_version"

echo ""
echo "Step 1: Installing system dependencies..."
echo ""

# Try to install system packages if apt-get is available
if command -v apt-get &> /dev/null; then
    echo "Installing with apt-get..."
    sudo apt-get update
    sudo apt-get install -y python3-venv python3-dev libpcap-dev
elif command -v yum &> /dev/null; then
    echo "Installing with yum..."
    sudo yum install -y python3-devel libpcap-devel
elif command -v dnf &> /dev/null; then
    echo "Installing with dnf..."
    sudo dnf install -y python3-devel libpcap-devel
else
    echo "WARNING: Could not auto-install system packages"
    echo "Please manually install: libpcap-dev (or libpcap-devel)"
fi

echo "✓ System dependencies handled"

echo ""
echo "Step 2: Creating virtual environment..."
echo ""
python3 -m venv venv

if [ ! -d "venv" ]; then
    echo "ERROR: Failed to create venv"
    exit 1
fi

echo "✓ Virtual environment created"

echo ""
echo "Step 3: Activating virtual environment..."
echo ""
source venv/bin/activate

echo "✓ Virtual environment activated"

echo ""
echo "Step 4: Installing Python dependencies..."
echo ""
pip install --upgrade pip
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

echo "✓ Dependencies installed successfully"

echo ""
echo "================================================================================"
echo "Setup Complete!"
echo "================================================================================"
echo ""
echo "To use the NIDS system:"
echo ""
echo "  1. Activate venv (in new terminal):"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run classification (requires sudo for packet capture):"
echo "     sudo venv/bin/python classification.py --duration 180"
echo ""
echo "     OR set capabilities (one-time, allows non-sudo usage):"
echo "     sudo setcap cap_net_raw,cap_net_admin=eip /usr/lib/jvm/java-11-openjdk-amd64/bin/java"
echo "     then: python classification.py --duration 180"
echo ""
echo "  3. Run ML model pipeline:"
echo "     python ml_model.py --help"
echo ""
echo "================================================================================"
echo ""
