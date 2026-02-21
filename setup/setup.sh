#!/bin/bash
# Setup script for NIDS Project on Linux
# Checks prerequisites, creates venv, installs pip deps, builds CICFlowMeter

# Navigate to project root (one level up from setup/)
cd "$(dirname "$0")/.." || exit 1

echo ""
echo "================================================================================"
echo "NIDS Project Setup - Linux"
echo "================================================================================"
echo ""

# ------------------------------------------------------------------
# Step 1: Check prerequisites (won't install anything system-level)
# ------------------------------------------------------------------
echo "Step 1: Checking prerequisites..."
echo ""

MISSING=()

# --- Python ---
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "  ✓ Python $python_version found"
else
    echo "  ✗ Python3 not found"
    MISSING+=("  - Python 3.8+  →  https://www.python.org/downloads/")
    MISSING+=("    Ubuntu/Debian: sudo apt install python3 python3-venv python3-dev")
    MISSING+=("    Fedora/RHEL:   sudo dnf install python3 python3-devel")
fi

# --- Java ---
JAVA_OK=false
if command -v java &> /dev/null; then
    java_version_full=$(java -version 2>&1 | head -1)

    # Extract major version (handles "1.8.x" and "17.x.x" formats)
    JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')
    if [ "$JAVA_MAJOR" = "1" ]; then
        JAVA_MAJOR=$(java -version 2>&1 | head -1 | sed -E 's/.*"1\.([0-9]+).*/\1/')
    fi

    if [ "$JAVA_MAJOR" -ge 8 ] 2>/dev/null && [ "$JAVA_MAJOR" -le 21 ] 2>/dev/null; then
        echo "  ✓ Java $JAVA_MAJOR found (${java_version_full})"
        JAVA_OK=true
    else
        echo "  ✗ Java $JAVA_MAJOR found — NOT compatible (need 8-21)"
        MISSING+=("  - Java 8-21 (you have $JAVA_MAJOR)  →  https://adoptium.net/ (recommend 17 LTS)")
        MISSING+=("    Ubuntu/Debian: sudo apt install openjdk-17-jdk")
        MISSING+=("    Then switch:   sudo update-alternatives --config java")
    fi
else
    echo "  ✗ Java not found"
    MISSING+=("  - Java 8-21  →  https://adoptium.net/ (recommend Temurin 17 LTS)")
    MISSING+=("    Ubuntu/Debian: sudo apt install openjdk-17-jdk")
    MISSING+=("    Fedora/RHEL:   sudo dnf install java-17-openjdk-devel")
fi

# --- libpcap ---
if ldconfig -p 2>/dev/null | grep -q libpcap || \
   [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ] || \
   [ -f /usr/lib/libpcap.so ]; then
    echo "  ✓ libpcap found"
else
    echo "  ✗ libpcap not found"
    MISSING+=("  - libpcap-dev (required for live network capture)")
    MISSING+=("    Ubuntu/Debian: sudo apt install libpcap-dev")
    MISSING+=("    Fedora/RHEL:   sudo dnf install libpcap-devel")
fi

# --- Report missing prerequisites ---
echo ""
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "────────────────────────────────────────────────────────────────"
    echo "  MISSING PREREQUISITES — please install the following first:"
    echo "────────────────────────────────────────────────────────────────"
    for line in "${MISSING[@]}"; do
        echo "$line"
    done
    echo "────────────────────────────────────────────────────────────────"
    echo ""

    # Python is hard-required — can't continue without it
    if ! command -v python3 &> /dev/null; then
        echo "ERROR: Cannot continue without Python. Install it and re-run this script."
        exit 1
    fi

    # Java / libpcap are soft — warn but keep going
    echo "NOTE: Continuing setup without the above. Live capture features"
    echo "      will not work until all prerequisites are installed."
    echo ""
fi

# ------------------------------------------------------------------
# Step 2: Create virtual environment
# ------------------------------------------------------------------
echo "Step 2: Creating virtual environment..."
echo ""

if [ -d "venv" ]; then
    echo "  ✓ Virtual environment already exists — skipping"
else
    python3 -m venv venv
    if [ ! -d "venv" ]; then
        echo "  ERROR: Failed to create venv"
        exit 1
    fi
    echo "  ✓ Virtual environment created"
fi

# ------------------------------------------------------------------
# Step 3: Activate venv & install pip dependencies
# ------------------------------------------------------------------
echo ""
echo "Step 3: Installing Python dependencies..."
echo ""

source venv/bin/activate

if pip install -r requirements.txt --quiet --dry-run 2>&1 | grep -q "Would install"; then
    echo "  Installing/updating packages..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "  ERROR: pip install failed"
        exit 1
    fi
    echo "  ✓ Dependencies installed"
else
    echo "  ✓ All dependencies already satisfied — skipping"
fi

# ------------------------------------------------------------------
# Step 4: Build CICFlowMeter
# ------------------------------------------------------------------
echo ""
echo "Step 4: Building CICFlowMeter..."
echo ""

if [ "$JAVA_OK" = true ]; then
    if [ -f "CICFlowMeter/gradlew" ]; then
        if [ -d "CICFlowMeter/build/classes/java/main" ]; then
            echo "  ✓ CICFlowMeter already built — skipping"
        else
            echo "  Building with Gradle..."
            pushd CICFlowMeter > /dev/null
            chmod +x gradlew
            ./gradlew classes
            if [ $? -eq 0 ]; then
                echo "  ✓ CICFlowMeter built successfully"
            else
                echo "  WARNING: Build failed — live capture won't work"
                echo "  Retry manually: cd CICFlowMeter && ./gradlew classes"
            fi
            popd > /dev/null
        fi
    else
        echo "  WARNING: CICFlowMeter/gradlew not found — skipping"
    fi
else
    echo "  ⊘ Skipped — Java 8-21 not available (see Step 1)"
fi

# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
echo ""
echo "================================================================================"
echo "Setup Complete!"
echo "================================================================================"
echo ""
echo "Usage:"
echo ""
echo "  1. Activate the virtual environment:"
echo "       source venv/bin/activate"
echo ""
echo "  2. Run live classification:"
echo "       python classification.py --duration 180"
echo ""
echo "  3. Run ML model pipeline:"
echo "       python ml_model.py --help"
echo ""
echo "    - CICFlowMeter built (cd CICFlowMeter && ./gradlew build && cd ..)"
echo ""
echo "================================================================================"
echo ""
