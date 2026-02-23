@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Complete Setup - Windows
echo ================================================================================
echo.
echo This script will:
echo   1. Setup Python environment
echo   2. Guide you to download dataset
echo   3. Fix Tuesday CSV
echo   4. Verify all CSV files
echo.

REM Step 1: Check Python
echo Step 1: Checking Python...
python --version
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Python not installed
    echo.
    echo DOWNLOAD OPTIONS:
    echo   Link: https://www.python.org/downloads/
    echo   Command: winget install Python.Python.3.12
    echo.
    pause
    exit /b 1
)
echo OK - Python installed
echo.

REM Step 2: Create venv
echo Step 2: Creating virtual environment...
if exist venv (
    echo OK - venv already exists
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create venv
        pause
        exit /b 1
    )
    echo OK - venv created
)
echo.

REM Step 3: Install dependencies
echo Step 3: Installing dependencies...
call venv\Scripts\activate.bat
echo.
echo Upgrading pip (optional)...
python -m pip install --upgrade pip >nul 2>&1
echo.
echo Installing packages from requirements.txt...
pip install -r ..\requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo ERROR: pip install failed
    echo.
    echo Try manually:
    echo   venv\Scripts\activate
    echo   pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo OK - All packages installed
echo.

REM Step 4: Dataset Download
echo Step 4: Download CICIDS2018 Dataset
echo.
echo Download from: https://www.unb.ca/cic/datasets/ids-2018.html
echo.
echo Files needed (10 total, ~6 GB):
echo   - Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
echo   - Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv (3.5 GB)
echo   - Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
echo   - Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
echo   - Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
echo.
echo Place all files in: data\raw\
echo.
set /p DUMMY=Press Enter when ready...
echo.

REM Step 5: Fix Tuesday CSV
echo Step 5: Fixing Tuesday CSV...
if exist "data\raw\Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" (
    python setup\fix_tuesday_csv.py
    if %errorlevel% neq 0 (
        echo WARNING - Error fixing Tuesday CSV (continuing anyway)
    ) else (
        echo OK - Tuesday CSV fixed
    )
) else (
    echo WARNING - Tuesday CSV not found (skipping)
)
echo.

REM Step 6: Verify CSV files
echo Step 6: Verifying CSV files...
if exist "data\raw\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" (
    python setup\verify_csv_files.py
    if %errorlevel% neq 0 (
        echo WARNING - Error verifying files
    ) else (
        echo OK - Files verified
    )
) else (
    echo WARNING - CSV files not found (skipping)
)
echo.

REM Success
echo ================================================================================
echo SUCCESS - Complete Setup Done!
echo ================================================================================
echo.
echo You can now:
echo   1. Activate venv: venv\Scripts\activate
echo   2. Train ML model: python ml_model.py --full
echo   3. Run classification: python classification.py
echo.
pause
