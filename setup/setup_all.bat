REM ==============================================================================
REM Complete NIDS Setup - Windows
REM ==============================================================================
REM This script does EVERYTHING:
REM   1. Basic Python environment setup (venv, dependencies)
REM   2. Download CICIDS2018 dataset
REM   3. Fix Tuesday CSV (extra columns bug)
REM   4. Verify all CSV files
REM   5. Prepare for ML training
REM ==============================================================================

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo   NIDS Complete Setup - Windows (Basic + Dataset + ML Prep)
echo ================================================================================
echo.

REM Navigate to project root
cd /d "%~dp0.." || (
    echo [ERROR] Failed to navigate to project root
    pause
    exit /b 1
)

REM ==================================================================
REM PART 1: Basic Setup (Python environment)
REM ==================================================================
echo.
echo ================================================================================
echo PART 1: Basic Python Environment Setup
echo ================================================================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Python is not installed.
    echo     Download: https://www.python.org/downloads/
    echo     OR: winget install Python.Python.3.12
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo   [OK] Python %PYTHON_VER%

REM Check Npcap
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo   [OK] Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo   [OK] WinPcap/Npcap found
) else (
    echo   [!] Npcap not found (optional, only needed for live capture)
    echo     Download: https://npcap.com
)
echo.

REM Create venv
if exist venv (
    echo   [OK] Virtual environment exists
) else (
    echo   Creating virtual environment...
    python -m venv venv
    if not exist venv (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] venv created
)
echo.

REM Install dependencies
echo   Installing Python dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo   [ERROR] pip install failed
    pause
    exit /b 1
)
echo   [OK] Dependencies installed
echo.

REM ==================================================================
REM PART 2: Dataset Download
REM ==================================================================
echo.
echo ================================================================================
echo PART 2: CICIDS2018 Dataset Download
echo ================================================================================
echo.

if exist "data\raw" (
    echo   [OK] data\raw directory exists
    
    REM Count CSV files
    for /f %%A in ('dir /b "data\raw\*.csv" 2^>nul ^| find /c /v ""') do set CSV_COUNT=%%A
    
    if !CSV_COUNT! geq 10 (
        echo   [OK] Found !CSV_COUNT! CSV files already in data\raw
        set /p SKIP_DOWNLOAD="   Skip download? [y/n]: "
        if /i "!SKIP_DOWNLOAD!"=="y" (
            goto :skip_download
        )
    )
) else (
    mkdir data\raw
    echo   [OK] Created data\raw directory
)

echo.
echo   Dataset download options:
echo.
echo   1. OFFICIAL LINK (direct download):
echo      https://www.unb.ca/cic/datasets/ids-2018.html
echo.
echo   2. AWS MIRROR (if available on official page):
echo      Check the official link for current AWS mirror
echo.
echo   Files needed (all 10):
echo     - Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
echo     - Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  (3.5 GB - LARGEST)
echo     - Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
echo     - Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
echo     - Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
echo.
echo   After download, place all CSVs in: data\raw\
echo.
set /p CONTINUE="   Press Enter when files are in data\raw\ (or type 'skip' to skip): "
if /i "!CONTINUE!"=="skip" (
    goto :skip_download
)

echo   Verifying downloads...
for /f %%A in ('dir /b "data\raw\*.csv" 2^>nul ^| find /c /v ""') do set CSV_COUNT=%%A
echo   Found !CSV_COUNT! CSV files
if !CSV_COUNT! lss 10 (
    echo   [!] Only !CSV_COUNT! files found, need 10
    echo   Please download remaining files and re-run
    pause
    goto :skip_download
)
echo   [OK] All 10 files found
echo.

:skip_download

REM ==================================================================
REM PART 3: Fix Tuesday CSV
REM ==================================================================
echo.
echo ================================================================================
echo PART 3: Fix Tuesday CSV File (Remove Extra Columns)
echo ================================================================================
echo.

if exist "data\raw\Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" (
    echo   Found Tuesday file - fixing extra columns...
    python setup\fix_tuesday_csv.py
    if errorlevel 1 (
        echo   [!] Error running fix_tuesday_csv.py
    ) else (
        echo   [OK] Tuesday file fixed
    )
) else (
    echo   [!] Tuesday file not found in data\raw\ - skipping fix
)
echo.
pause

REM ==================================================================
REM PART 4: Verify CSV Files
REM ==================================================================
echo.
echo ================================================================================
echo PART 4: Verify CSV Files
echo ================================================================================
echo.

if exist "data\raw\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" (
    echo   Verifying all CSV files...
    python setup\verify_csv_files.py
    if errorlevel 1 (
        echo   [!] Error during verification
    ) else (
        echo   [OK] All files verified
    )
) else (
    echo   [!] CSVs not found - skipping verification
)
echo.
pause

REM ==================================================================
REM PART 5: Success
REM ==================================================================
echo.
echo ================================================================================
echo   Complete Setup Done!
echo ================================================================================
echo.
echo   Next steps:
echo.
echo   1. Activate venv (each new terminal):
echo      venv\Scripts\activate
echo.
echo   2. Train ML model (uses dataset from data\raw\):
echo      python ml_model.py --full
echo.
echo   3. Run live classification:
echo      python classification.py
echo.
echo   4. Run batch classification:
echo      python classification.py --batch flows.csv
echo.
echo ================================================================================
echo.
pause
