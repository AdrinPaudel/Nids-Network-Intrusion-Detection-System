#!/bin/bash
# Setup script for NIDS Project on Linux
# Checks prerequisites, creates venv, installs deps, builds CICFlowMeter, tests interface detection

set -e  # Exit on error

# Navigate to project root (one level up from setup/)
cd "$(dirname "$0")/.." || exit 1

echo ""
echo "================================================================================"
echo "NIDS Project Setup - Linux"
echo "================================================================================"
echo ""

# ==================================================================
# Step 1: Check Python & Java (user must install these themselves)
# ==================================================================
echo "Step 1: Checking required software..."
echo ""

FAIL=false

# --- Python ---
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  [OK] Python $python_version"
else
    echo "  [ERROR] Python3 is not installed."
    echo ""
    echo "    Install it yourself:"
    echo "      Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "      Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "      Or download:    https://www.python.org/downloads/"
    echo ""
    FAIL=true
fi

# --- Java ---
JAVA_OK=false
if command -v java &> /dev/null; then
    java_version_full=$(java -version 2>&1 | head -1)
    JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')
    if [ "$JAVA_MAJOR" = "1" ]; then
        JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"1\.([0-9]+).*/\1/')
    fi

    if [ "$JAVA_MAJOR" -ge 8 ] 2>/dev/null && [ "$JAVA_MAJOR" -le 21 ] 2>/dev/null; then
        echo "  [OK] Java $JAVA_MAJOR ($java_version_full)"
        JAVA_OK=true
    else
        echo "  [ERROR] Java $JAVA_MAJOR is NOT compatible. Need Java 8-21."
        echo ""
        echo "    Install a compatible version yourself:"
        echo "      Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
        echo "      Then switch:    sudo update-alternatives --config java"
        echo "      Or download:    https://adoptium.net/ (Temurin 17 LTS)"
        echo ""
        FAIL=true
    fi
else
    echo "  [ERROR] Java is not installed."
    echo ""
    echo "    Install it yourself:"
    echo "      Ubuntu/Debian:  sudo apt install openjdk-17-jdk"
    echo "      Fedora/RHEL:    sudo dnf install java-17-openjdk-devel"
    echo "      Or download:    https://adoptium.net/ (Temurin 17 LTS)"
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
    python3 -m venv venv
    if [ ! -d "venv" ]; then
        echo "  [ERROR] Failed to create venv"
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

source venv/bin/activate

pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [ERROR] pip install failed"
    exit 1
fi
echo "  [OK] Dependencies installed"

# ==================================================================
# Step 4: Build CICFlowMeter
# ==================================================================
echo ""
echo "Step 4: Building CICFlowMeter..."
echo ""

if [ ! -f "CICFlowMeter/gradlew" ]; then
    echo "  [ERROR] CICFlowMeter/gradlew not found"
    exit 1
fi

if [ -d "CICFlowMeter/build/classes/java/main" ]; then
    echo "  [OK] Already built — skipping"
else
    echo "  Building with Gradle (this may take a minute)..."
    pushd CICFlowMeter > /dev/null
    chmod +x gradlew
    ./gradlew --no-daemon classes
    if [ $? -eq 0 ]; then
        echo "  [OK] CICFlowMeter built successfully"
    else
        echo "  [ERROR] Gradle build failed"
        echo "  Try manually: cd CICFlowMeter && ./gradlew classes"
        popd > /dev/null
        exit 1
    fi
    popd > /dev/null
fi

# ==================================================================
# Step 5: Test interface detection
# ==================================================================
echo ""
echo "Step 5: Testing network interface detection..."
echo ""

# Run the Java interface listing through Gradle
INTERFACE_OUTPUT=$(cd CICFlowMeter && chmod +x gradlew && ./gradlew --no-daemon exeLive '--args=--list-interfaces' 2>&1)
INTERFACE_COUNT=$(echo "$INTERFACE_OUTPUT" | grep -cE '^[0-9]+\|')

if [ "$INTERFACE_COUNT" -gt 0 ] 2>/dev/null; then
    echo "  [OK] Detected $INTERFACE_COUNT network interface(s):"
    echo ""
    echo "$INTERFACE_OUTPUT" | grep -E '^[0-9]+\|' | while IFS='|' read -r idx name desc addrs; do
        if [ "$desc" = "N/A" ] || [ -z "$desc" ]; then
            echo "        $idx. $name  ($addrs)"
        else
            echo "        $idx. $desc  ($addrs)"
        fi
    done
    echo ""
else
    echo "  [ERROR] No network interfaces detected!"
    echo ""

    # Check for common Linux problems
    # 1. libpcap
    if ! ldconfig -p 2>/dev/null | grep -q libpcap && \
       [ ! -f /usr/lib/x86_64-linux-gnu/libpcap.so ] && \
       [ ! -f /usr/lib/libpcap.so ]; then
        echo "  PROBLEM: libpcap is not installed."
        echo "    Fix:   sudo apt install libpcap-dev"
        echo ""
    fi

    # 2. Permissions
    echo "  PROBLEM: Java likely lacks permission to access network interfaces."
    echo "    Fix (one-time, then no sudo needed to run):"
    echo "      sudo setcap cap_net_raw,cap_net_admin=eip \$(readlink -f \$(which java))"
    echo ""
    echo "    Or run the program with sudo:"
    echo "      sudo venv/bin/python classification.py"
    echo ""

    # 3. Architecture
    ARCH=$(uname -m)
    if [ "$ARCH" != "x86_64" ]; then
        echo "  PROBLEM: Your architecture is $ARCH. The bundled jnetpcap native"
        echo "    library is compiled for x86_64 only. This won't work on ARM/other."
        echo ""
    fi

    # Show raw Java errors for debugging
    ERR_LINES=$(echo "$INTERFACE_OUTPUT" | grep -iE 'error|exception|denied|libpcap|unsatisfied' | head -5)
    if [ -n "$ERR_LINES" ]; then
        echo "  Java errors:"
        echo "$ERR_LINES" | while read -r line; do
            echo "    $line"
        done
        echo ""
    fi

    echo "  Fix the issues above, then re-run this script."
    exit 1
fi

# ==================================================================
# Done
# ==================================================================
echo "================================================================================"
echo "  Setup Complete!  Everything is working."
echo "================================================================================"
echo ""

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "  To start, activate venv first:"
    echo "      source venv/bin/activate"
    echo ""
    echo "  Or next time run setup with 'source' so venv stays active:"
    echo "      source setup/setup.sh"
else
    echo "  venv is active. You're ready to go."
fi

echo ""
echo "  Run live classification:"
echo "      python classification.py --duration 180"
echo ""
echo "  Run ML model pipeline:"
echo "      python ml_model.py --help"
echo ""
echo "================================================================================"
echo ""
