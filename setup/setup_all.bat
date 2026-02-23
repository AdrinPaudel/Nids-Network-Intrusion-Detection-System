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
echo Script started
echo.
pause

REM Step 1: Check Python
echo.
echo ================================================================================
echo Step 1: Checking Python
echo ================================================================================
echo.

python --version
if errorlevel 1 (
    echo ERROR: Python not found
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo OK - Python is installed
echo.
pause

REM Step 2: Create venv
echo.
echo ================================================================================
echo Step 2: Creating virtual environment
echo ================================================================================
echo.

if exist venv (
    echo OK - venv already exists
) else (
    echo Creating venv...
    python -m venv venv
    if not exist venv (
        echo ERROR: Failed to create venv
        pause
        exit /b 1
    )
    echo OK - venv created
)

echo.
pause

REM Step 3: Install dependencies
echo.
echo ================================================================================
echo Step 3: Installing dependencies
echo ================================================================================
echo.

call venv\Scripts\activate.bat

echo Upgrading pip...
pip install --upgrade pip

echo Installing packages...
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: pip install failed
    pause
    exit /b 1
)

echo OK - All packages installed
echo.
pause

REM Step 4: Dataset Download
echo.
echo ================================================================================
echo Step 4: Download CICIDS2018 Dataset
echo ================================================================================
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
pause

REM Step 5: Fix Tuesday CSV
echo.
echo ================================================================================
echo Step 5: Fix Tuesday CSV
echo ================================================================================
echo.

if exist "data\raw\Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" (
    echo Running fix...
    python setup\fix_tuesday_csv.py
    echo OK - Tuesday CSV fixed
) else (
    echo WARNING - Tuesday CSV not found (skipping)
)

echo.
pause

REM Step 6: Verify CSV files
echo.
echo ================================================================================
echo Step 6: Verify CSV Files
echo ================================================================================
echo.

if exist "data\raw\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" (
    echo Verifying files...
    python setup\verify_csv_files.py
    echo OK - Files verified
) else (
    echo WARNING - CSV files not found (skipping)
)

echo.
pause

REM Success
echo.
echo ================================================================================
echo SUCCESS - Complete Setup Done!
echo ================================================================================
echo.
echo You can now:
echo   1. Activate venv: venv\Scripts\activate
echo   2. Train ML model: python ml_model.py --full
echo   3. Run classification: python classification.py
echo.
echo ================================================================================
echo.
pause
