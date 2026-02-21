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
# Note: These require package manager access. If they fail, install manually.
if command -v apt-get &> /dev/null; then
    echo "Installing with apt-get (may prompt for password)..."
    apt-get update 2>/dev/null && apt-get install -y python3-venv python3-dev libpcap-dev 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "NOTE: Could not install system packages automatically."
        echo "If needed, install manually: apt-get install python3-venv python3-dev libpcap-dev"
    fi
elif command -v yum &> /dev/null; then
    echo "Installing with yum (may prompt for password)..."
    yum install -y python3-devel libpcap-devel 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "NOTE: Could not install system packages automatically."
        echo "If needed, install manually: yum install python3-devel libpcap-devel"
    fi
elif command -v dnf &> /dev/null; then
    echo "Installing with dnf (may prompt for password)..."
    dnf install -y python3-devel libpcap-devel 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "NOTE: Could not install system packages automatically."
        echo "If needed, install manually: dnf install python3-devel libpcap-devel"
    fi
else
    echo "WARNING: Could not auto-install system packages"
    echo "Please manually install: libpcap-dev (or libpcap-devel)"
fi

echo "✓ System dependencies handled"

echo ""
echo "Step 2: Creating virtual environment..."
echo ""

if [ -d "venv" ]; then
    echo "✓ Virtual environment already exists - skipping creation"
else
    python3 -m venv venv
    if [ ! -d "venv" ]; then
        echo "ERROR: Failed to create venv"
        exit 1
    fi
    echo "✓ Virtual environment created"
fi

echo ""
echo "Step 3: Activating virtual environment..."
echo ""
source venv/bin/activate

echo "✓ Virtual environment activated"

echo ""
echo "Step 4: Installing Python dependencies..."
echo ""

# Check if all requirements are already satisfied
if pip install -r requirements.txt --quiet --dry-run 2>&1 | grep -q "Would install"; then
    echo "Installing/updating dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
    echo "✓ Dependencies installed successfully"
else
    echo "✓ All dependencies already installed - skipping"
fi

echo ""
echo "Step 5: Building CICFlowMeter (for live network capture)..."
echo ""

# Gradle 8.5 only supports Java 8 through 21.
# Newer Java versions (22+) will fail with "Unsupported class file major version" errors.
JAVA_OK=false
JAVA_MAJOR=0

if command -v java &> /dev/null; then
    java_version_full=$(java -version 2>&1 | head -1)
    echo "Found Java: $java_version_full"

    # Extract major version number
    # Java 8: "1.8.0_xxx" → major=8
    # Java 9+: "9.x.x", "11.x.x", "17.x.x", "21.x.x" etc.
    JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')
    if [ "$JAVA_MAJOR" = "1" ]; then
        # Java 8 reports as 1.8
        JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"1\.([0-9]+).*/\1/')
    fi

    echo "Detected Java major version: $JAVA_MAJOR"

    if [ "$JAVA_MAJOR" -ge 8 ] && [ "$JAVA_MAJOR" -le 21 ] 2>/dev/null; then
        JAVA_OK=true
    else
        echo ""
        echo "WARNING: Java $JAVA_MAJOR is NOT compatible with Gradle 8.5"
        echo "Gradle 8.5 supports Java 8 through 21 only."
        echo ""
        echo "To fix this, install a compatible Java version:"
        echo "  Ubuntu/Debian: apt install openjdk-17-jdk"
        echo "  Then switch:   update-alternatives --config java"
        echo "  Or download:   https://adoptium.net/ (Temurin 17 LTS)"
        echo ""
        echo "Skipping CICFlowMeter build."
    fi
else
    echo "WARNING: Java is not installed - skipping CICFlowMeter build"
    echo "Java 8-21 is required for live capture."
    echo "  Ubuntu/Debian: apt install openjdk-17-jdk"
    echo "  Or download:   https://adoptium.net/ (Temurin 17 LTS recommended)"
    echo "Then re-run this script or build manually:"
    echo "  cd CICFlowMeter && chmod +x gradlew && ./gradlew build && cd .."
fi

if [ "$JAVA_OK" = true ]; then
    if [ -f "CICFlowMeter/gradlew" ]; then
        # Skip if already built
        if [ -d "CICFlowMeter/build/classes/main" ]; then
            echo "✓ CICFlowMeter already built - skipping"
        else
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
        fi
    else
        echo "WARNING: CICFlowMeter/gradlew not found - skipping build"
    fi
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
echo "  2. Run classification:"
echo "     python classification.py --duration 180"
echo ""
echo "  3. Run ML model pipeline:"
echo "     python ml_model.py --help"
echo ""
echo "  For live capture you also need:"
echo "    - Java 8-21 (https://adoptium.net/ - recommend Temurin 17 LTS)"
echo "    - libpcap-dev installed"
echo "    - CICFlowMeter built (cd CICFlowMeter && ./gradlew build && cd ..)"
echo ""
echo "================================================================================"
echo ""
