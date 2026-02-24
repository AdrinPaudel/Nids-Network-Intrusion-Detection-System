@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM NIDS Full Setup - Windows
REM ==============================================================================
REM Complete setup: Python env + dataset download + CSV fixes + ML training prep.
REM Run this if you want to retrain the ML model from scratch.
REM
REM Usage: Run from project root:
REM   setup\setup_full\setup_full.bat
REM ==============================================================================

REM Navigate to project root
cd /d "%~dp0..\.."

echo.
echo ================================================================================
echo   NIDS Full Setup - Windows (Basic + Dataset + ML Training Prep)
echo ================================================================================
echo.

REM ==================================================================
REM PART 1: Basic Setup
REM ==================================================================
echo ================================================================================
echo   PART 1: Python Environment Setup
echo ================================================================================
echo.

REM Step 1: Check Python
echo Step 1: Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [ERROR] Python is not installed.
    echo.
    echo   Install Python 3.12+:
    echo     Download: https://www.python.org/downloads/
    echo     Or:       winget install Python.Python.3.12
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python %PYVER%
echo.

REM Step 2: Create venv
echo Step 2: Creating virtual environment...
if exist venv (
    echo   [OK] venv already exists
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] venv created
)
echo.

REM Step 3: Install dependencies
echo Step 3: Installing dependencies...
call venv\Scripts\activate.bat
echo.
echo   Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo   Installing packages from requirements.txt...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo   [ERROR] pip install failed
    pause
    exit /b 1
)
echo   [OK] All packages installed
echo.

REM Step 3b: Verify packages
echo Step 3b: Verifying packages...
echo.

set VERIFY_OK=1
for %%p in (pandas,numpy,sklearn,imblearn,matplotlib,seaborn,joblib,tqdm,pyarrow,psutil,cicflowmeter,scapy) do (
    python -c "import %%p" >nul 2>&1
    if !errorlevel! equ 0 (
        echo   [OK] %%p
    ) else (
        echo   [!] %%p MISSING
        set VERIFY_OK=0
    )
)
if %VERIFY_OK% equ 0 (
    echo.
    echo   WARNING: Some packages are missing
    echo   Continue anyway? (You can manually fix with: pip install -r requirements.txt)
    echo.
)
echo.

REM ==================================================================
REM PART 2: Dataset Download
REM ==================================================================
echo ================================================================================
echo   PART 2: CICIDS2018 Dataset Download
echo ================================================================================
echo.
echo   The dataset is ~6 GB total (10 CSV files). NOT included in the repo.
echo.

REM Check if already downloaded
set CSV_COUNT=0
if exist "data\raw" (
    for %%f in (data\raw\*.csv) do set /a CSV_COUNT+=1
)

if %CSV_COUNT% geq 10 (
    echo   [OK] Found %CSV_COUNT% CSV files already in data\raw\
    echo.
    set /p SKIP_DL="  Skip download? [y/n]: "
    if /i "!SKIP_DL!"=="y" goto :skip_download
)

echo   Download options:
echo     [1] Official UNB (https://www.unb.ca/cic/datasets/ids-2018.html)
echo     [2] Kaggle (https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv)
echo     [3] Manual (download yourself)
echo.
set /p DL_CHOICE="  Enter choice (1-3): "
echo.

if "%DL_CHOICE%"=="1" (
    echo   Opening UNB download page...
    start https://www.unb.ca/cic/datasets/ids-2018.html
) else if "%DL_CHOICE%"=="2" (
    echo   Opening Kaggle download page...
    start https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
) else (
    echo   Manual download selected.
)

echo.
echo   Place all 10 CSV files in: data\raw\
echo.
echo   Files needed:
echo     - Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
echo     - Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv (3.5 GB)
echo     - Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
echo     - Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
echo.
set /p DUMMY=Press Enter when files are downloaded...
echo.

:skip_download

REM ==================================================================
REM PART 3: Fix Tuesday CSV
REM ==================================================================
echo ================================================================================
echo   PART 3: Fix Tuesday CSV (Extra Columns)
echo ================================================================================
echo.

if exist "data\raw\Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" (
    python setup\setup_full\fix_tuesday_csv.py
    if %errorlevel% neq 0 (
        echo   [!] Error fixing Tuesday CSV (continuing anyway)
    ) else (
        echo   [OK] Tuesday CSV fixed
    )
) else (
    echo   [!] Tuesday CSV not found - skipping
)
echo.

REM ==================================================================
REM PART 4: Verify CSV Files
REM ==================================================================
echo ================================================================================
echo   PART 4: Verify CSV Files
echo ================================================================================
echo.

if exist "data\raw\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" (
    python setup\setup_full\verify_csv_files.py
    if %errorlevel% neq 0 (
        echo   [!] Error during verification
    ) else (
        echo   [OK] Files verified
    )
) else (
    echo   [!] CSV files not found - skipping
)
echo.

REM ==================================================================
REM Done
REM ==================================================================
echo ================================================================================
echo   Full Setup Complete!
echo ================================================================================
echo.
echo   Next steps:
echo.
echo   1. Activate venv:
echo        venv\Scripts\activate.bat
echo.
echo   2. For ML training and all features:
echo        See: PROJECT_RUN.md (in project root)
echo.
echo   3. To set up other components:
echo        See: setup/SETUPS.md
echo.
echo   4. For project overview:
echo        See: README.md (in project root)
echo.
echo   5. Low RAM? Adjust config.py settings.
echo      See: setup/setup_full/TRAINING_CONFIG.md
echo.
pause
