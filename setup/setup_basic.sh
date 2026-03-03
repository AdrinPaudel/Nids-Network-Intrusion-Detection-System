#!/bin/sh
# ============================================================
#  NIDS Project - Basic Setup Script (Linux / macOS)
#  Creates venv, installs dependencies, verifies environment
#  POSIX sh compatible - works with sh, dash, bash, etc.
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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_ROOT/venv"
REQUIREMENTS="$PROJECT_ROOT/requirements.txt"
ERRORS=0

printf "\n"
printf "${BOLD}============================================================${RESET}\n"
printf "${BOLD}  NIDS Project - Basic Setup${RESET}\n"
printf "${BOLD}============================================================${RESET}\n"
printf "  Project root: %s\n" "$PROJECT_ROOT"
printf "\n"

# ============================================================
#  STEP 1: Check Python
# ============================================================
printf "${BOLD}--- Step 1: Python Check ---${RESET}\n"

PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_CMD="$cmd"
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    printf "  $FAIL Python is not installed or not on PATH.\n"
    printf "         Install Python 3.12+ from https://www.python.org/downloads/\n"
    ERRORS=$((ERRORS + 1))
else
    PY_VERSION=$($PYTHON_CMD --version 2>&1)
    printf "  $PASS %s found\n" "$PY_VERSION"

    PY_VER_NUM=$(echo "$PY_VERSION" | awk '{print $2}')
    PY_MAJOR=$(echo "$PY_VER_NUM" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER_NUM" | cut -d. -f2)

    if [ "$PY_MAJOR" -lt 3 ]; then
        printf "  $FAIL Python 3.12+ required, found %s\n" "$PY_VER_NUM"
        ERRORS=$((ERRORS + 1))
    elif [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 12 ]; then
        printf "  $WARN Python 3.12+ recommended, found %s. May still work.\n" "$PY_VER_NUM"
    fi

    # Check pip
    if $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        printf "  $PASS pip available\n"
    else
        printf "  $FAIL pip is not available.\n"
        printf "         Install: %s -m ensurepip --upgrade\n" "$PYTHON_CMD"
        ERRORS=$((ERRORS + 1))
    fi

    # Check venv module
    if $PYTHON_CMD -c "import venv" >/dev/null 2>&1; then
        printf "  $PASS venv module available\n"
    else
        printf "  $FAIL venv module not available.\n"
        printf "         Install: sudo apt install python3-venv (Debian/Ubuntu)\n"
        ERRORS=$((ERRORS + 1))
    fi
fi

printf "\n"

# ============================================================
#  STEP 2: Virtual Environment
# ============================================================
printf "${BOLD}--- Step 2: Virtual Environment ---${RESET}\n"

if [ -f "$VENV_DIR/bin/python" ]; then
    printf "  $PASS Virtual environment already exists at venv/\n"
    printf "  $INFO Skipping venv creation.\n"
else
    printf "  $INFO Creating virtual environment...\n"
    # Try normal venv first; fall back to --without-pip if ensurepip is missing
    if $PYTHON_CMD -m venv "$VENV_DIR" 2>/dev/null; then
        printf "  $PASS Virtual environment created at venv/\n"
    elif $PYTHON_CMD -m venv --without-pip "$VENV_DIR" 2>/dev/null; then
        printf "  $PASS Virtual environment created at venv/ (without pip)\n"
        printf "  $INFO pip will be bootstrapped after activation.\n"
    else
        printf "  $FAIL Failed to create virtual environment.\n"
        printf "         Try: sudo apt install python3-venv python3-pip\n"
        ERRORS=$((ERRORS + 1))
    fi
fi

# Activate venv
. "$VENV_DIR/bin/activate"
printf "  $PASS Virtual environment activated\n"

# Bootstrap pip inside venv if it's missing
if ! python -m pip --version >/dev/null 2>&1; then
    printf "  $INFO pip not found in venv, bootstrapping...\n"
    if python -m ensurepip --upgrade >/dev/null 2>&1; then
        printf "  $PASS pip bootstrapped via ensurepip\n"
    else
        printf "  $INFO Downloading get-pip.py...\n"
        curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
        python /tmp/get-pip.py >/dev/null 2>&1
        rm -f /tmp/get-pip.py
        if python -m pip --version >/dev/null 2>&1; then
            printf "  $PASS pip installed via get-pip.py\n"
        else
            printf "  $FAIL Could not install pip. Install manually:\n"
            printf "           sudo apt install python3-pip\n"
            ERRORS=$((ERRORS + 1))
        fi
    fi
fi
printf "\n"

# ============================================================
#  STEP 3: Install Dependencies
# ============================================================
printf "${BOLD}--- Step 3: Install Dependencies ---${RESET}\n"

if [ ! -f "$REQUIREMENTS" ]; then
    printf "  $FAIL requirements.txt not found at project root.\n"
    ERRORS=$((ERRORS + 1))
else
    printf "  $INFO Upgrading pip...\n"
    python -m pip install --upgrade pip >/dev/null 2>&1
    printf "  $PASS pip upgraded\n"

    printf "  $INFO Installing packages from requirements.txt...\n"
    printf "         (this may take a few minutes on first run)\n"
    printf "\n"
    if python -m pip install -r "$REQUIREMENTS"; then
        printf "\n"
        printf "  $PASS All packages installed successfully.\n"
    else
        printf "\n"
        printf "  $FAIL Some packages failed to install. Check output above.\n"
        ERRORS=$((ERRORS + 1))
    fi
fi

printf "\n"

# ============================================================
#  STEP 4: Verify Key Packages
# ============================================================
printf "${BOLD}--- Step 4: Verify Key Packages ---${RESET}\n"

PKG_ERRORS=0

for pkg in sklearn pandas numpy joblib tqdm psutil pyarrow seaborn matplotlib; do
    if python -c "import $pkg" >/dev/null 2>&1; then
        printf "  $PASS %s\n" "$pkg"
    else
        printf "  $FAIL %s - NOT importable\n" "$pkg"
        PKG_ERRORS=$((PKG_ERRORS + 1))
    fi
done

# imbalanced-learn imports as imblearn
if python -c "import imblearn" >/dev/null 2>&1; then
    printf "  $PASS imbalanced-learn (imblearn)\n"
else
    printf "  $FAIL imbalanced-learn (imblearn) - NOT importable\n"
    PKG_ERRORS=$((PKG_ERRORS + 1))
fi

# cicflowmeter (optional)
if python -c "import cicflowmeter" >/dev/null 2>&1; then
    printf "  $PASS cicflowmeter\n"
else
    printf "  $WARN cicflowmeter - not installed (only needed for live capture mode)\n"
fi

ERRORS=$((ERRORS + PKG_ERRORS))
printf "\n"

# ============================================================
#  STEP 5: Directory Structure
# ============================================================
printf "${BOLD}--- Step 5: Directory Structure ---${RESET}\n"

DIRS_CREATED=0
DIRS_EXISTED=0

for dir in \
    "data/data_model_training/raw" \
    "data/data_model_training/combined" \
    "data/data_model_training/preprocessed" \
    "data/data_model_training/preprocessed_all" \
    "data/data_model_use/default/batch" \
    "data/data_model_use/default/batch_labeled" \
    "data/data_model_use/all/batch" \
    "data/data_model_use/all/batch_labeled" \
    "data/simul" \
    "trained_models/trained_model_default" \
    "trained_models/trained_model_all" \
    "results/exploration" \
    "results/preprocessing" \
    "results/preprocessing_all" \
    "results/training" \
    "results/training_all" \
    "results/testing" \
    "results/testing_all" \
    "reports" \
    "temp/simul"
do
    if [ ! -d "$PROJECT_ROOT/$dir" ]; then
        mkdir -p "$PROJECT_ROOT/$dir"
        DIRS_CREATED=$((DIRS_CREATED + 1))
    else
        DIRS_EXISTED=$((DIRS_EXISTED + 1))
    fi
done

printf "  $PASS Directories verified  (created: %s, already existed: %s)\n" "$DIRS_CREATED" "$DIRS_EXISTED"
printf "\n"

# ============================================================
#  STEP 6: Trained Models Check
# ============================================================
printf "${BOLD}--- Step 6: Trained Models ---${RESET}\n"

# Default model
DEFAULT_OK=1
for f in random_forest_model.joblib scaler.joblib label_encoder.joblib selected_features.joblib; do
    [ ! -f "$PROJECT_ROOT/trained_models/trained_model_default/$f" ] && DEFAULT_OK=0
done
if [ $DEFAULT_OK -eq 1 ]; then
    printf "  $PASS Default model (5-class) - all files present\n"
else
    printf "  $WARN Default model (5-class) - some files missing\n"
    printf "         Run the ML pipeline (python ml_model.py) to train the model.\n"
fi

# All model
ALL_OK=1
for f in random_forest_model.joblib scaler.joblib label_encoder.joblib selected_features.joblib; do
    [ ! -f "$PROJECT_ROOT/trained_models/trained_model_all/$f" ] && ALL_OK=0
done
if [ $ALL_OK -eq 1 ]; then
    printf "  $PASS All model (6-class) - all files present\n"
else
    printf "  $WARN All model (6-class) - some files missing\n"
    printf "         Run the ML pipeline with --all flag to train.\n"
fi

printf "\n"

# ============================================================
#  STEP 7: Simulation Data Check
# ============================================================
printf "${BOLD}--- Step 7: Simulation Data ---${RESET}\n"

SIMUL_DIR="$PROJECT_ROOT/data/simul"
SIMUL_OK=1
for f in simul.csv simul_lable.csv simul_infiltration.csv simul_infiltration_lable.csv; do
    if [ ! -f "$SIMUL_DIR/$f" ]; then
        printf "  $WARN Missing: data/simul/%s\n" "$f"
        SIMUL_OK=0
    fi
done
if [ $SIMUL_OK -eq 1 ]; then
    printf "  $PASS All simulation data files present\n"
fi

printf "\n"

# ============================================================
#  STEP 8: Project Modules Check
# ============================================================
printf "${BOLD}--- Step 8: Project Modules ---${RESET}\n"

# ml_model module
if [ -f "$PROJECT_ROOT/ml_model/__init__.py" ]; then
    printf "  $PASS ml_model/ module found\n"
    for f in data_loader.py explorer.py preprocessor.py trainer.py tester.py utils.py; do
        [ ! -f "$PROJECT_ROOT/ml_model/$f" ] && printf "  $WARN Missing: ml_model/%s\n" "$f"
    done
else
    printf "  $FAIL ml_model/ module not found or missing __init__.py\n"
    ERRORS=$((ERRORS + 1))
fi

# classification module
if [ -f "$PROJECT_ROOT/classification/__init__.py" ]; then
    printf "  $PASS classification/ module found\n"
else
    printf "  $FAIL classification/ module not found or missing __init__.py\n"
    ERRORS=$((ERRORS + 1))
fi

# classification sub-modules
for sub in classification_batch classification_live classification_simulated; do
    if [ -f "$PROJECT_ROOT/classification/$sub/__init__.py" ]; then
        printf "  $PASS classification/%s/ found\n" "$sub"
    else
        printf "  $WARN classification/%s/ missing or no __init__.py\n" "$sub"
    fi
done

# Key entry scripts
for f in main.py ml_model.py classification.py config.py; do
    if [ -f "$PROJECT_ROOT/$f" ]; then
        printf "  $PASS %s\n" "$f"
    else
        printf "  $FAIL %s missing!\n" "$f"
        ERRORS=$((ERRORS + 1))
    fi
done

printf "\n"

# ============================================================
#  STEP 9: Packet Capture (libpcap) Check
# ============================================================
printf "${BOLD}--- Step 9: Packet Capture (libpcap) ---${RESET}\n"

if ldconfig -p 2>/dev/null | grep -q libpcap; then
    printf "  $PASS libpcap detected\n"
elif [ -f /usr/lib/libpcap.so ] || [ -f /usr/lib64/libpcap.so ] || [ -f /usr/local/lib/libpcap.so ]; then
    printf "  $PASS libpcap detected\n"
elif command -v brew >/dev/null 2>&1 && brew list libpcap >/dev/null 2>&1; then
    printf "  $PASS libpcap detected (Homebrew)\n"
else
    printf "  $WARN libpcap not detected. Required ONLY for live capture mode.\n"
    printf "         Debian/Ubuntu: sudo apt install libpcap-dev\n"
    printf "         Fedora/RHEL:   sudo dnf install libpcap-devel\n"
    printf "         macOS:         brew install libpcap\n"
    printf "         (Not needed for batch/simulation/ML training modes)\n"
fi

printf "\n"

# ============================================================
#  SUMMARY
# ============================================================
printf "${BOLD}============================================================${RESET}\n"
if [ $ERRORS -eq 0 ]; then
    printf "${GREEN}${BOLD}  SETUP COMPLETE - No errors!${RESET}\n"
else
    printf "${RED}${BOLD}  SETUP COMPLETE - %s error(s) detected.${RESET}\n" "$ERRORS"
    printf "  Review the $FAIL items above and fix them.\n"
fi
printf "${BOLD}============================================================${RESET}\n"
printf "\n"
printf "  Next steps:\n"
printf "    1. Activate the venv:   . venv/bin/activate\n"
printf "    2. Run ML pipeline:     python ml_model.py --help\n"
printf "    3. Run classification:  python classification.py --help\n"
printf "\n"
