#!/usr/bin/env bash
# ============================================================
#  NIDS Project - Basic Setup Script (Linux / macOS)
#  Creates venv, installs dependencies, verifies environment
# ============================================================
set -e

# -- Colors --
GREEN='\033[92m'
RED='\033[91m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
RESET='\033[0m'

PASS="${GREEN}[PASS]${RESET}"
FAIL="${RED}[FAIL]${RESET}"
WARN="${YELLOW}[WARN]${RESET}"
INFO="${CYAN}[INFO]${RESET}"

# -- Resolve project root (parent of setup/) --
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"
REQUIREMENTS="$PROJECT_ROOT/requirements.txt"
ERRORS=0

echo ""
echo -e "${BOLD}============================================================${RESET}"
echo -e "${BOLD}  NIDS Project - Basic Setup${RESET}"
echo -e "${BOLD}============================================================${RESET}"
echo "  Project root: $PROJECT_ROOT"
echo ""

# ============================================================
#  STEP 1: Check Python
# ============================================================
echo -e "${BOLD}--- Step 1: Python Check ---${RESET}"

PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON_CMD="$cmd"
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "  $FAIL Python is not installed or not on PATH."
    echo "         Install Python 3.12+ from https://www.python.org/downloads/"
    ((ERRORS++)) || true
else
    PY_VERSION=$($PYTHON_CMD --version 2>&1)
    echo -e "  $PASS $PY_VERSION found"

    PY_VER_NUM=$(echo "$PY_VERSION" | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VER_NUM" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER_NUM" | cut -d. -f2)

    if [ "$PY_MAJOR" -lt 3 ]; then
        echo -e "  $FAIL Python 3.12+ required, found $PY_VER_NUM"
        ((ERRORS++)) || true
    elif [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 12 ]; then
        echo -e "  $WARN Python 3.12+ recommended, found $PY_VER_NUM. May still work."
    fi

    # Check pip
    if $PYTHON_CMD -m pip --version &>/dev/null; then
        echo -e "  $PASS pip available"
    else
        echo -e "  $FAIL pip is not available."
        echo "         Install: $PYTHON_CMD -m ensurepip --upgrade"
        ((ERRORS++)) || true
    fi

    # Check venv module
    if $PYTHON_CMD -c "import venv" &>/dev/null; then
        echo -e "  $PASS venv module available"
    else
        echo -e "  $FAIL venv module not available."
        echo "         Install: sudo apt install python3-venv (Debian/Ubuntu)"
        ((ERRORS++)) || true
    fi
fi

echo ""

# ============================================================
#  STEP 2: Virtual Environment
# ============================================================
echo -e "${BOLD}--- Step 2: Virtual Environment ---${RESET}"

if [ -f "$VENV_DIR/bin/python" ]; then
    echo -e "  $PASS Virtual environment already exists at venv/"
    echo -e "  $INFO Skipping venv creation."
else
    echo -e "  $INFO Creating virtual environment..."
    $PYTHON_CMD -m venv "$VENV_DIR"
    if [ $? -ne 0 ]; then
        echo -e "  $FAIL Failed to create virtual environment."
        ((ERRORS++)) || true
    else
        echo -e "  $PASS Virtual environment created at venv/"
    fi
fi

# Activate venv
source "$VENV_DIR/bin/activate"
echo -e "  $PASS Virtual environment activated"
echo ""

# ============================================================
#  STEP 3: Install Dependencies
# ============================================================
echo -e "${BOLD}--- Step 3: Install Dependencies ---${RESET}"

if [ ! -f "$REQUIREMENTS" ]; then
    echo -e "  $FAIL requirements.txt not found at project root."
    ((ERRORS++)) || true
else
    echo -e "  $INFO Upgrading pip..."
    python -m pip install --upgrade pip >/dev/null 2>&1
    echo -e "  $PASS pip upgraded"

    echo -e "  $INFO Installing packages from requirements.txt..."
    echo "         (this may take a few minutes on first run)"
    echo ""
    if python -m pip install -r "$REQUIREMENTS"; then
        echo ""
        echo -e "  $PASS All packages installed successfully."
    else
        echo ""
        echo -e "  $FAIL Some packages failed to install. Check output above."
        ((ERRORS++)) || true
    fi
fi

echo ""

# ============================================================
#  STEP 4: Verify Key Packages
# ============================================================
echo -e "${BOLD}--- Step 4: Verify Key Packages ---${RESET}"

PKG_ERRORS=0

for pkg in sklearn pandas numpy joblib tqdm psutil pyarrow seaborn matplotlib; do
    if python -c "import $pkg" &>/dev/null; then
        echo -e "  $PASS $pkg"
    else
        echo -e "  $FAIL $pkg - NOT importable"
        ((PKG_ERRORS++)) || true
    fi
done

# imbalanced-learn imports as imblearn
if python -c "import imblearn" &>/dev/null; then
    echo -e "  $PASS imbalanced-learn (imblearn)"
else
    echo -e "  $FAIL imbalanced-learn (imblearn) - NOT importable"
    ((PKG_ERRORS++)) || true
fi

# cicflowmeter (optional)
if python -c "import cicflowmeter" &>/dev/null; then
    echo -e "  $PASS cicflowmeter"
else
    echo -e "  $WARN cicflowmeter - not installed (only needed for live capture mode)"
fi

ERRORS=$((ERRORS + PKG_ERRORS))
echo ""

# ============================================================
#  STEP 5: Directory Structure
# ============================================================
echo -e "${BOLD}--- Step 5: Directory Structure ---${RESET}"

DIRS_CREATED=0
DIRS_EXISTED=0

DIRS=(
    "data/data_model_training/raw"
    "data/data_model_training/combined"
    "data/data_model_training/preprocessed"
    "data/data_model_training/preprocessed_all"
    "data/data_model_use/default/batch"
    "data/data_model_use/default/batch_labeled"
    "data/data_model_use/all/batch"
    "data/data_model_use/all/batch_labeled"
    "data/simul"
    "trained_models/trained_model_default"
    "trained_models/trained_model_all"
    "results/exploration"
    "results/preprocessing"
    "results/preprocessing_all"
    "results/training"
    "results/training_all"
    "results/testing"
    "results/testing_all"
    "reports"
    "temp/simul"
)

for dir in "${DIRS[@]}"; do
    if [ ! -d "$PROJECT_ROOT/$dir" ]; then
        mkdir -p "$PROJECT_ROOT/$dir"
        ((DIRS_CREATED++)) || true
    else
        ((DIRS_EXISTED++)) || true
    fi
done

echo -e "  $PASS Directories verified  (created: $DIRS_CREATED, already existed: $DIRS_EXISTED)"
echo ""

# ============================================================
#  STEP 6: Trained Models Check
# ============================================================
echo -e "${BOLD}--- Step 6: Trained Models ---${RESET}"

MODEL_FILES=("random_forest_model.joblib" "scaler.joblib" "label_encoder.joblib" "selected_features.joblib")

# Default model
DEFAULT_OK=1
for f in "${MODEL_FILES[@]}"; do
    [ ! -f "$PROJECT_ROOT/trained_models/trained_model_default/$f" ] && DEFAULT_OK=0
done
if [ $DEFAULT_OK -eq 1 ]; then
    echo -e "  $PASS Default model (5-class) - all files present"
else
    echo -e "  $WARN Default model (5-class) - some files missing"
    echo "         Run the ML pipeline (python ml_model.py) to train the model."
fi

# All model
ALL_OK=1
for f in "${MODEL_FILES[@]}"; do
    [ ! -f "$PROJECT_ROOT/trained_models/trained_model_all/$f" ] && ALL_OK=0
done
if [ $ALL_OK -eq 1 ]; then
    echo -e "  $PASS All model (6-class) - all files present"
else
    echo -e "  $WARN All model (6-class) - some files missing"
    echo "         Run the ML pipeline with --all flag to train."
fi

echo ""

# ============================================================
#  STEP 7: Simulation Data Check
# ============================================================
echo -e "${BOLD}--- Step 7: Simulation Data ---${RESET}"

SIMUL_DIR="$PROJECT_ROOT/data/simul"
SIMUL_OK=1
for f in simul.csv simul_lable.csv simul_infiltration.csv simul_infiltration_lable.csv; do
    if [ ! -f "$SIMUL_DIR/$f" ]; then
        echo -e "  $WARN Missing: data/simul/$f"
        SIMUL_OK=0
    fi
done
if [ $SIMUL_OK -eq 1 ]; then
    echo -e "  $PASS All simulation data files present"
fi

echo ""

# ============================================================
#  STEP 8: Project Modules Check
# ============================================================
echo -e "${BOLD}--- Step 8: Project Modules ---${RESET}"

# ml_model module
if [ -f "$PROJECT_ROOT/ml_model/__init__.py" ]; then
    echo -e "  $PASS ml_model/ module found"
    for f in data_loader.py explorer.py preprocessor.py trainer.py tester.py utils.py; do
        [ ! -f "$PROJECT_ROOT/ml_model/$f" ] && echo -e "  $WARN Missing: ml_model/$f"
    done
else
    echo -e "  $FAIL ml_model/ module not found or missing __init__.py"
    ((ERRORS++)) || true
fi

# classification module
if [ -f "$PROJECT_ROOT/classification/__init__.py" ]; then
    echo -e "  $PASS classification/ module found"
else
    echo -e "  $FAIL classification/ module not found or missing __init__.py"
    ((ERRORS++)) || true
fi

# classification sub-modules
for sub in classification_batch classification_live classification_simulated; do
    if [ -f "$PROJECT_ROOT/classification/$sub/__init__.py" ]; then
        echo -e "  $PASS classification/$sub/ found"
    else
        echo -e "  $WARN classification/$sub/ missing or no __init__.py"
    fi
done

# Key entry scripts
for f in main.py ml_model.py classification.py config.py; do
    if [ -f "$PROJECT_ROOT/$f" ]; then
        echo -e "  $PASS $f"
    else
        echo -e "  $FAIL $f missing!"
        ((ERRORS++)) || true
    fi
done

echo ""

# ============================================================
#  STEP 9: Packet Capture (libpcap) Check
# ============================================================
echo -e "${BOLD}--- Step 9: Packet Capture (libpcap) ---${RESET}"

if ldconfig -p 2>/dev/null | grep -q libpcap; then
    echo -e "  $PASS libpcap detected"
elif [ -f /usr/lib/libpcap.so ] || [ -f /usr/lib64/libpcap.so ] || [ -f /usr/local/lib/libpcap.so ]; then
    echo -e "  $PASS libpcap detected"
elif command -v brew &>/dev/null && brew list libpcap &>/dev/null 2>&1; then
    echo -e "  $PASS libpcap detected (Homebrew)"
else
    echo -e "  $WARN libpcap not detected. Required ONLY for live capture mode."
    echo "         Debian/Ubuntu: sudo apt install libpcap-dev"
    echo "         Fedora/RHEL:   sudo dnf install libpcap-devel"
    echo "         macOS:         brew install libpcap"
    echo "         (Not needed for batch/simulation/ML training modes)"
fi

echo ""

# ============================================================
#  SUMMARY
# ============================================================
echo -e "${BOLD}============================================================${RESET}"
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  SETUP COMPLETE - No errors!${RESET}"
else
    echo -e "${RED}${BOLD}  SETUP COMPLETE - $ERRORS error(s) detected.${RESET}"
    echo -e "  Review the ${FAIL} items above and fix them."
fi
echo -e "${BOLD}============================================================${RESET}"
echo ""
echo "  Next steps:"
echo "    1. Activate the venv:   source venv/bin/activate"
echo "    2. Run ML pipeline:     python ml_model.py --help"
echo "    3. Run classification:  python classification.py --help"
echo ""
