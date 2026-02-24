#!/bin/sh
# ==============================================================================
# NIDS Full Setup - Linux
# ==============================================================================
# Complete setup: Python env + dataset download + CSV fixes + ML training prep.
# Run this if you want to retrain the ML model from scratch.
#
# Usage: Run from project root:
#   chmod +x setup/setup_full/setup_full.sh
#   ./setup/setup_full/setup_full.sh
# ==============================================================================

set -e

cd "$(dirname "$0")/../.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "  NIDS Full Setup - Linux (Basic + Dataset + ML Training Prep)"
echo "================================================================================"
echo ""

# ==================================================================
# PART 1: Basic Python Setup
# ==================================================================
echo "================================================================================"
echo "  PART 1: Python Environment Setup"
echo "================================================================================"
echo ""

# Check Python
if ! command -v python3 > /dev/null 2>&1; then
    echo "  [ERROR] Python3 is not installed."
    echo "    Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "    Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "    Arch Linux:     sudo pacman -S python"
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "  [OK] Python $python_version"

# Check libpcap
if ldconfig -p 2>/dev/null | grep -q libpcap || [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ]; then
    echo "  [OK] libpcap found"
else
    echo "  [!] libpcap not found (needed for live capture only)"
    echo "    Ubuntu/Debian:  sudo apt install libpcap-dev"
    echo "    Fedora/RHEL:    sudo dnf install libpcap-devel"
fi
echo ""

# Create venv
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

# Install dependencies
echo "  Installing dependencies..."
. venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "  [ERROR] pip install failed"
    exit 1
fi
echo "  [OK] Dependencies installed"

echo ""
echo "  Verifying packages..."
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

if [ "$verify_ok" -eq 0 ]; then
    echo ""
    echo "  WARNING: Some packages are missing"
    echo "  Continue anyway? (You can fix with: pip install -r requirements.txt)"
    echo ""
fi
echo ""

# ==================================================================
# PART 2: Dataset Download
# ==================================================================
echo ""
echo "================================================================================"
echo "  PART 2: CICIDS2018 Dataset Download"
echo "================================================================================"
echo ""

skip_download=""

if [ -d "data/raw" ]; then
    csv_count=$(ls -1 data/raw/*.csv 2>/dev/null | wc -l)
    if [ "$csv_count" -ge 10 ]; then
        echo "  [OK] Found $csv_count CSV files already in data/raw/"
        read -p "  Skip download? [y/n]: " skip_dl
        if [ "$skip_dl" = "y" ] || [ "$skip_dl" = "Y" ]; then
            skip_download=1
        fi
    fi
else
    mkdir -p data/raw
    echo "  [OK] Created data/raw directory"
fi

if [ -z "$skip_download" ]; then
    echo ""
    echo "  Download options:"
    echo "    [1] Official UNB (https://www.unb.ca/cic/datasets/ids-2018.html)"
    echo "    [2] Kaggle (https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv)"
    echo "    [3] Manual download"
    echo ""
    read -p "  Enter choice (1-3): " dl_choice

    if [ "$dl_choice" = "1" ]; then
        echo "  Opening UNB download page..."
        if command -v xdg-open > /dev/null 2>&1; then
            xdg-open "https://www.unb.ca/cic/datasets/ids-2018.html" &
        else
            echo "  Visit: https://www.unb.ca/cic/datasets/ids-2018.html"
        fi
    elif [ "$dl_choice" = "2" ]; then
        echo "  Opening Kaggle download page..."
        if command -v xdg-open > /dev/null 2>&1; then
            xdg-open "https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv" &
        else
            echo "  Visit: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv"
        fi
    fi

    echo ""
    echo "  Place all 10 CSV files in: data/raw/"
    echo ""
    echo "  Files needed (10 total, ~6 GB):"
    echo "    - Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  (3.5 GB)"
    echo "    - Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "    - Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"
    echo ""
    read -p "  Press Enter when files are in data/raw/ (or 'skip'): " cont
    if [ "$cont" = "skip" ] || [ "$cont" = "SKIP" ]; then
        skip_download=1
    fi
fi
echo ""

# ==================================================================
# PART 3: Fix Tuesday CSV
# ==================================================================
echo "================================================================================"
echo "  PART 3: Fix Tuesday CSV (Extra Columns)"
echo "================================================================================"
echo ""

if [ -f "data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" ]; then
    echo "  Fixing Tuesday file..."
    python3 setup/setup_full/fix_tuesday_csv.py
    if [ $? -eq 0 ]; then
        echo "  [OK] Tuesday file fixed"
    else
        echo "  [!] Error fixing Tuesday file"
    fi
else
    echo "  [!] Tuesday file not found - skipping"
fi
echo ""

# ==================================================================
# PART 4: Verify CSV Files
# ==================================================================
echo "================================================================================"
echo "  PART 4: Verify CSV Files"
echo "================================================================================"
echo ""

if [ -f "data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" ]; then
    python3 setup/setup_full/verify_csv_files.py
else
    echo "  [!] CSV files not found - skipping"
fi
echo ""

# ==================================================================
# Done
# ==================================================================
echo "================================================================================"
echo "  Full Setup Complete!"
echo "================================================================================"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Activate venv (every new terminal):"
echo "       source venv/bin/activate"
echo ""
echo "  2. For ML training and all features:"
echo "       See: PROJECT_RUN.md (in project root)"
echo ""
echo "  3. To set up other components:"
echo "       See: setup/SETUPS.md"
echo ""
echo "  4. For project overview:"
echo "       See: README.md (in project root)"
echo ""
echo "  5. Low RAM? Adjust config.py settings."
echo "     See: setup/setup_full/TRAINING_CONFIG.md"
echo ""
echo "================================================================================"
echo ""
