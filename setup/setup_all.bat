REM Complete NIDS Setup - Windows (Basic + Dataset + ML Prep)

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Complete Setup - Windows
echo ================================================================================
echo This will:
echo   1. Setup Python environment
echo   2. Guide you to download CICIDS2018 dataset (6 GB)
echo   3. Fix Tuesday CSV file
echo   4. Verify all CSV files
echo   5. Prepare for ML training
echo ================================================================================
echo.
pause

echo [STATUS] Setting up NIDS...
echo.
echo Current directory: %cd%
echo.

REM ==================================================================
REM PART 1: Basic Setup
REM ==================================================================
echo.
echo ================================================================================
echo PART 1: Basic Python Environment Setup
echo ================================================================================
echo.

REM Check Python
python --version
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    echo Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
echo [OK] Python found
echo ========== PYTHON CHECK COMPLETE ==========
pause

REM Create venv
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if not exist venv (
        echo [ERROR] Failed to create venv
        pause
        exit /b 1
    )
)
echo [OK] Virtual environment ready
echo ========== VENV CREATION COMPLETE ==========
pause

REM Install dependencies
echo Installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed
    pause
    exit /b 1
)
echo ========== DEPENDENCIES INSTALLED COMPLETE ==========
echo [OK] Dependencies installed
pause

REM ==================================================================
REM PART 2: Dataset Download
REM ==================================================================
echo.
echo ================================================================================
echo PART 2: CICIDS2018 Dataset Download
echo ================================================================================
echo.
echo This dataset is ~6 GB total (10 CSV files)
echo.
echo Download from: https://www.unb.ca/cic/datasets/ids-2018.html
echo.
echo Files to download:
echo   1. Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
echo   2. Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
echo   3. Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
echo   4. Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  (3.5 GB - LARGEST)
echo   5. Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
echo   6. Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
echo   7. Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
echo   8. Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
echo   9. Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
echo   10. Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
echo.
echo Place all files in: data\raw\
echo.
pause

REM Check if files exist
for /f %%A in ('dir /b "data\raw\*.csv" 2^>nul ^| find /c /v ""') do set CSV_COUNT=%%A
if %CSV_COUNT% gtr 0 (
    echo [OK] Found %CSV_COUNT% CSV files in data\raw\
)
if %CSV_COUNT% lss 10 (
    echo [!] Only %CSV_COUNT% files found, need 10
    set /p "WAIT=Press Enter after you download all files to data\raw\ ..."
)
pause

REM ==================================================================
REM PART 3: Fix Tuesday CSV
REM ==================================================================
echo.
echo ================================================================================
echo PART 3: Fix Tuesday CSV (Remove Extra Columns)
echo ================================================================================
echo.

if exist "data\raw\Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv" (
    echo Running fix_tuesday_csv.py...
    python setup\fix_tuesday_csv.py
    echo [OK] Tuesday file processed
) else (
    echo [!] Tuesday file not found - skipping
echo.
echo ========== TUESDAY CSV FIX COMPLETE ==========
)
pause

REM ==================================================================
REM PART 4: Verify CSV Files
REM ==================================================================
echo.
echo ================================================================================
echo PART 4: Verify CSV Files (Check 80 columns)
echo ================================================================================
echo.

if exist "data\raw\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv" (
    echo Running verify_csv_files.py...
    python setup\verify_csv_files.py
    echo [OK] Files verified
echo.
echo ========== CSV VERIFICATION COMPLETE ==========
) else (
    echo [!] CSV files not found - skipping
)
pause

REM ==================================================================
REM SUCCESS
REM ==================================================================
echo.
echo ================================================================================
echo   SUCCESS! Complete Setup Done!
echo ================================================================================
echo.
echo   You can now:
echo.
echo     1. Activate venv:
echo        venv\Scripts\activate
echo.
echo     2. Train ML model (uses data\raw\ CSVs):
echo        python ml_model.py --full
echo.
echo     3. Run classifications:
echo        python classification.py
echo.
echo ================================================================================
echo.
pause
