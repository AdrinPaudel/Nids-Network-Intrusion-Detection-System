#!/bin/sh
# ==============================================================================
# Complete NIDS Setup - Linux
# ==============================================================================
# This script does EVERYTHING:
#   1. Basic Python environment setup (venv, dependencies)
#   2. Download CICIDS2018 dataset
#   3. Fix Tuesday CSV (extra columns bug)
#   4. Verify all CSV files
#   5. Prepare for ML training
# ==============================================================================

set -e

cd "$(dirname "$0")/.." || exit 1
PROJECT_ROOT=$(pwd)

echo ""
echo "================================================================================"
echo "   NIDS Complete Setup - Linux (Basic + Dataset + ML Prep)"
echo "================================================================================"
echo ""

# ==================================================================
# PART 1: Basic Setup (Python environment)
# ==================================================================
echo ""
echo "================================================================================"
echo "PART 1: Basic Python Environment Setup"
echo "================================================================================"
echo ""

# Check Python
if ! command -v python3 > /dev/null 2>&1; then
    echo "   [ERROR] Python3 is not installed."
    echo "     Ubuntu/Debian:  sudo apt install python3 python3-venv python3-dev"
    echo "     Fedora/RHEL:    sudo dnf install python3 python3-devel"
    echo "     Arch Linux:     sudo pacman -S python"
    exit 1
fi

python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   [OK] Python $python_version"

# Check libpcap
if ldconfig -p 2>/dev/null | grep -q libpcap || [ -f /usr/lib/x86_64-linux-gnu/libpcap.so ]; then
    echo "   [OK] libpcap found"
else
    echo "   [!] libpcap not found (optional, only needed for live capture)"
    echo "     Ubuntu/Debian:  sudo apt install libpcap-dev"
    echo "     Fedora/RHEL:    sudo dnf install libpcap-devel"
fi
echo ""

# Create venv
if [ -d "venv" ]; then
    echo "   [OK] Virtual environment exists"
else (
    echo "   Creating virtual environment..."
    python3 -m venv venv
    if [ ! -d "venv" ]; then
        echo "   [ERROR] Failed to create venv"
        exit 1
    fi
    echo "   [OK] venv created"
fi
echo ""

# Install dependencies
echo "   Installing Python dependencies..."
. venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "   [ERROR] pip install failed"
    exit 1
fi
echo "   [OK] Dependencies installed"
echo ""

# ==================================================================
# PART 2: Dataset Download
# ==================================================================
echo ""
echo "================================================================================"
echo "PART 2: CICIDS2018 Dataset Download"
echo "================================================================================"
echo ""

if [ -d "data/raw" ]; then
    echo "   [OK] data/raw directory exists"
    
    # Count CSV files
    csv_count=$(ls -1 data/raw/*.csv 2>/dev/null | wc -l)
    
    if [ "$csv_count" -ge 10 ]; then
        echo "   [OK] Found $csv_count CSV files already in data/raw"
        read -p "   Skip download? [y/n]: " skip_download
        if [ "$skip_download" = "y" ] || [ "$skip_download" = "Y" ]; then
            goto_skip_download=1
        fi
    fi
else
    mkdir -p data/raw
    echo "   [OK] Created data/raw directory"
fi

if [ -z "$goto_skip_download" ]; then
    echo ""
    echo "   Dataset download options:"
    echo ""
    echo "   1. OFFICIAL LINK (direct download):"
    echo "      https://www.unb.ca/cic/datasets/ids-2018.html"
    echo ""
    echo "   2. Download via wget (replace URL with actual link):"
    echo "      cd data/raw/"
    echo "      wget https://[mirror-url]/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    echo "      wget https://[mirror-url]/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "      ... (all 10 files) ..."
    echo ""
    echo "   Files needed (all 10):"
    echo "     - Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  (3.5 GB - LARGEST)"
    echo "     - Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv"
    echo "     - Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv"
    echo ""
    read -p "   Press Enter when files are in data/raw/ (or type 'skip' to skip): " continue_val
    
    if [ "$continue_val" = "skip" ] || [ "$continue_val" = "SKIP" ]; then
        goto_skip_download=1
    fi
    
    if [ -z "$goto_skip_download" ]; then
        echo "   Verifying downloads..."
        csv_count=$(ls -1 data/raw/*.csv 2>/dev/null | wc -l)
        echo "   Found $csv_count CSV files"
        if [ "$csv_count" -lt 10 ]; then
            echo "   [!] Only $csv_count files found, need 10"
            echo "   Please download remaining files and re-run"
            goto_skip_download=1
        else
            echo "   [OK] All 10 files found"
        fi
    fi
fi
echo ""

# ==================================================================
# PART 3: Fix Tuesday CSV
# ==================================================================
echo ""
echo "================================================================================"
echo "PART 3: Fix Tuesday CSV File (Remove Extra Columns)"
echo "================================================================================"
echo ""

if [ -f "data/raw/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" ]; then
    echo "   Found Tuesday file - fixing extra columns..."
    python3 setup/fix_tuesday_csv.py
    if [ $? -eq 0 ]; then
        echo "   [OK] Tuesday file fixed"
    else
        echo "   [!] Error running fix_tuesday_csv.py"
    fi
else
    echo "   [!] Tuesday file not found in data/raw/ - skipping fix"
fi
echo ""
read -p "   Press Enter to continue..." dummy

# ==================================================================
# PART 4: Verify CSV Files
# ==================================================================
echo ""
echo "================================================================================"
echo "PART 4: Verify CSV Files"
echo "================================================================================"
echo ""

if [ -f "data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" ]; then
    echo "   Verifying all CSV files..."
    python3 setup/verify_csv_files.py
    if [ $? -eq 0 ]; then
        echo "   [OK] All files verified"
    else
        echo "   [!] Error during verification"
    fi
else
    echo "   [!] CSVs not found - skipping verification"
fi
echo ""
read -p "   Press Enter to continue..." dummy

# ==================================================================
# PART 5: Success
# ==================================================================
echo ""
echo "================================================================================"
echo "   Complete Setup Done!"
echo "================================================================================"
echo ""
echo "   Next steps:"
echo ""
echo "   1. Activate venv (each new terminal):"
echo "      source venv/bin/activate"
echo ""
echo "   2. Train ML model (uses dataset from data/raw/):"
echo "      python3 ml_model.py --full"
echo ""
echo "   3. Run live classification:"
echo "      sudo ./venv/bin/python3 classification.py"
echo ""
echo "   4. Run batch classification:"
echo "      python3 classification.py --batch flows.csv"
echo ""
echo "================================================================================"
echo ""
