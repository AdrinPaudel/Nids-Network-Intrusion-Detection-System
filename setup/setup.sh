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
echo "Step 5: Building CICFlowMeter (for live network capture)..."
echo ""

# Check if Java is installed
if command -v java &> /dev/null; then
    java_version=$(java -version 2>&1 | head -1)
    echo "Found Java: $java_version"

    if [ -f "CICFlowMeter/gradlew" ]; then
        echo "Building CICFlowMeter with Gradle..."
        pushd CICFlowMeter > /dev/null
        chmod +x gradlew
        ./gradlew build
        if [ $? -eq 0 ]; then
            echo "✓ CICFlowMeter built successfully"
        else
            echo "WARNING: CICFlowMeter build failed - live capture may not work"
            echo "You can retry manually: cd CICFlowMeter && ./gradlew build && cd .."
        fi
        popd > /dev/null
    else
        echo "WARNING: CICFlowMeter/gradlew not found - skipping build"
    fi
else
    echo "WARNING: Java is not installed - skipping CICFlowMeter build"
    echo "Java 8+ is required for live capture. Install from https://adoptium.net/"
    echo "Then build manually: cd CICFlowMeter && chmod +x gradlew && ./gradlew build && cd .."
fi

echo ""
echo "Step 6: Checking libpcap (required for live capture)..."
echo ""

# Check if libpcap is available
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    echo "✓ libpcap found"
elif [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ] || [ -f /usr/lib/libpcap.so ]; then
    echo "✓ libpcap found"
else
    echo "WARNING: libpcap not detected"
    echo "For live capture, install it: sudo apt-get install libpcap-dev"
fi

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
echo "     sudo setcap cap_net_raw,cap_net_admin=eip \$(which java)"
echo "     then: python classification.py --duration 180"
echo ""
echo "  3. Run ML model pipeline:"
echo "     python ml_model.py --help"
echo ""
echo "  For live capture you also need:"
echo "    - Java 8+ (https://adoptium.net/)"
echo "    - libpcap-dev installed"
echo "    - CICFlowMeter built (cd CICFlowMeter && ./gradlew build && cd ..)"
echo ""
echo "================================================================================"
echo ""
