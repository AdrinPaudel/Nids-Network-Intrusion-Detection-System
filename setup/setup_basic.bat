@echo off
REM ============================================================
REM  NIDS Project - Basic Setup Script (Windows)
REM  Creates venv, installs dependencies, verifies environment
REM ============================================================
setlocal enabledelayedexpansion

REM -- Colors via ANSI (Windows 10+) --
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "CYAN=[96m"
set "BOLD=[1m"
set "RESET=[0m"

set "PASS=%GREEN%[PASS]%RESET%"
set "FAIL=%RED%[FAIL]%RESET%"
set "WARN=%YELLOW%[WARN]%RESET%"
set "INFO=%CYAN%[INFO]%RESET%"

REM -- Resolve project root (parent of setup/) --
set "PROJECT_ROOT=%~dp0.."
pushd "%PROJECT_ROOT%"
set "PROJECT_ROOT=%CD%"
popd

set "VENV_DIR=%PROJECT_ROOT%\venv"
set "REQUIREMENTS=%PROJECT_ROOT%\requirements.txt"
set "ERRORS=0"

echo.
echo %BOLD%============================================================%RESET%
echo %BOLD%  NIDS Project - Basic Setup%RESET%
echo %BOLD%============================================================%RESET%
echo   Project root: %PROJECT_ROOT%
echo.

REM ============================================================
REM  STEP 1: Check Python
REM ============================================================
echo %BOLD%--- Step 1: Python Check ---%RESET%

where python >nul 2>&1
if errorlevel 1 (
    echo   %FAIL% Python is not installed or not on PATH.
    echo          Install Python 3.12+ from https://www.python.org/downloads/
    set /a ERRORS+=1
    goto :skip_python
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set "PY_VERSION=%%i"
echo   %PASS% %PY_VERSION% found

REM Extract major.minor for version check
for /f "tokens=2 delims= " %%a in ("%PY_VERSION%") do set "PY_VER_NUM=%%a"
for /f "tokens=1,2 delims=." %%a in ("%PY_VER_NUM%") do (
    set "PY_MAJOR=%%a"
    set "PY_MINOR=%%b"
)

if %PY_MAJOR% LSS 3 (
    echo   %FAIL% Python 3.12+ required, found %PY_VER_NUM%
    set /a ERRORS+=1
) else if %PY_MAJOR% EQU 3 if %PY_MINOR% LSS 12 (
    echo   %WARN% Python 3.12+ recommended, found %PY_VER_NUM%. May still work.
)

REM Check pip
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo   %FAIL% pip is not available. Reinstall Python with pip enabled.
    set /a ERRORS+=1
) else (
    for /f "tokens=*" %%i in ('python -m pip --version 2^>^&1') do set "PIP_VER=%%i"
    echo   %PASS% pip available
)

REM Check venv module
python -c "import venv" >nul 2>&1
if errorlevel 1 (
    echo   %FAIL% venv module not available. Reinstall Python with standard library.
    set /a ERRORS+=1
) else (
    echo   %PASS% venv module available
)

:skip_python
echo.

REM ============================================================
REM  STEP 2: Virtual Environment
REM ============================================================
echo %BOLD%--- Step 2: Virtual Environment ---%RESET%

if exist "%VENV_DIR%\Scripts\python.exe" (
    echo   %PASS% Virtual environment already exists at venv\
    echo   %INFO% Skipping venv creation.
) else (
    echo   %INFO% Creating virtual environment...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo   %FAIL% Failed to create virtual environment.
        set /a ERRORS+=1
        goto :skip_venv
    )
    echo   %PASS% Virtual environment created at venv\
)

REM Activate venv for the rest of the script
call "%VENV_DIR%\Scripts\activate.bat"
echo   %PASS% Virtual environment activated

:skip_venv
echo.

REM ============================================================
REM  STEP 3: Install Dependencies
REM ============================================================
echo %BOLD%--- Step 3: Install Dependencies ---%RESET%

if not exist "%REQUIREMENTS%" (
    echo   %FAIL% requirements.txt not found at project root.
    set /a ERRORS+=1
    goto :skip_deps
)

echo   %INFO% Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1
echo   %PASS% pip upgraded

echo   %INFO% Installing packages from requirements.txt...
echo          (this may take a few minutes on first run)
echo.
python -m pip install -r "%REQUIREMENTS%"
if errorlevel 1 (
    echo.
    echo   %FAIL% Some packages failed to install. Check output above.
    set /a ERRORS+=1
) else (
    echo.
    echo   %PASS% All packages installed successfully.
)

:skip_deps
echo.

REM ============================================================
REM  STEP 4: Verify Key Packages
REM ============================================================
echo %BOLD%--- Step 4: Verify Key Packages ---%RESET%

set "PKG_ERRORS=0"

for %%p in (sklearn pandas numpy joblib tqdm psutil pyarrow seaborn matplotlib) do (
    python -c "import %%p" >nul 2>&1
    if errorlevel 1 (
        echo   %FAIL% %%p - NOT importable
        set /a PKG_ERRORS+=1
    ) else (
        echo   %PASS% %%p
    )
)

REM imbalanced-learn imports as imblearn
python -c "import imblearn" >nul 2>&1
if errorlevel 1 (
    echo   %FAIL% imbalanced-learn (imblearn) - NOT importable
    set /a PKG_ERRORS+=1
) else (
    echo   %PASS% imbalanced-learn (imblearn)
)

REM cicflowmeter (optional - only needed for live capture)
python -c "import cicflowmeter" >nul 2>&1
if errorlevel 1 (
    echo   %WARN% cicflowmeter - not installed (only needed for live capture mode)
) else (
    echo   %PASS% cicflowmeter
)

if %PKG_ERRORS% GTR 0 (
    set /a ERRORS+=%PKG_ERRORS%
)

echo.

REM ============================================================
REM  STEP 5: Directory Structure
REM ============================================================
echo %BOLD%--- Step 5: Directory Structure ---%RESET%

set "DIRS_CREATED=0"
set "DIRS_EXISTED=0"

for %%d in (
    "data\data_model_training\raw"
    "data\data_model_training\combined"
    "data\data_model_training\preprocessed"
    "data\data_model_training\preprocessed_all"
    "data\data_model_use\default\batch"
    "data\data_model_use\default\batch_labeled"
    "data\data_model_use\all\batch"
    "data\data_model_use\all\batch_labeled"
    "data\simul"
    "trained_models\trained_model_default"
    "trained_models\trained_model_all"
    "results\exploration"
    "results\preprocessing"
    "results\preprocessing_all"
    "results\training"
    "results\training_all"
    "results\testing"
    "results\testing_all"
    "reports"
    "temp\simul"
) do (
    if not exist "%PROJECT_ROOT%\%%~d" (
        mkdir "%PROJECT_ROOT%\%%~d" 2>nul
        set /a DIRS_CREATED+=1
    ) else (
        set /a DIRS_EXISTED+=1
    )
)

echo   %PASS% Directories verified  (created: %DIRS_CREATED%, already existed: %DIRS_EXISTED%)
echo.

REM ============================================================
REM  STEP 6: Trained Models Check
REM ============================================================
echo %BOLD%--- Step 6: Trained Models ---%RESET%

set "MODEL_FILES=random_forest_model.joblib scaler.joblib label_encoder.joblib selected_features.joblib"

REM Check default model
set "DEFAULT_OK=1"
for %%f in (%MODEL_FILES%) do (
    if not exist "%PROJECT_ROOT%\trained_models\trained_model_default\%%f" (
        set "DEFAULT_OK=0"
    )
)
if %DEFAULT_OK% EQU 1 (
    echo   %PASS% Default model (5-class) - all files present
) else (
    echo   %WARN% Default model (5-class) - some files missing
    echo          Run the ML pipeline (python ml_model.py) to train the model.
)

REM Check all model
set "ALL_OK=1"
for %%f in (%MODEL_FILES%) do (
    if not exist "%PROJECT_ROOT%\trained_models\trained_model_all\%%f" (
        set "ALL_OK=0"
    )
)
if %ALL_OK% EQU 1 (
    echo   %PASS% All model (6-class) - all files present
) else (
    echo   %WARN% All model (6-class) - some files missing
    echo          Run the ML pipeline with --all flag to train.
)

echo.

REM ============================================================
REM  STEP 7: Simulation Data Check
REM ============================================================
echo %BOLD%--- Step 7: Simulation Data ---%RESET%

set "SIMUL_DIR=%PROJECT_ROOT%\data\simul"
set "SIMUL_OK=1"
for %%f in (simul.csv simul_lable.csv simul_infiltration.csv simul_infiltration_lable.csv) do (
    if not exist "%SIMUL_DIR%\%%f" (
        echo   %WARN% Missing: data\simul\%%f
        set "SIMUL_OK=0"
    )
)
if %SIMUL_OK% EQU 1 (
    echo   %PASS% All simulation data files present
) else (
    echo   %WARN% Some simulation CSV files are missing. Simulation mode may not work.
)

echo.

REM ============================================================
REM  STEP 8: Project Modules Check
REM ============================================================
echo %BOLD%--- Step 8: Project Modules ---%RESET%

REM ml_model module
if exist "%PROJECT_ROOT%\ml_model\__init__.py" (
    echo   %PASS% ml_model/ module found
    set "ML_FILES=data_loader.py explorer.py preprocessor.py trainer.py tester.py utils.py"
    for %%f in (!ML_FILES!) do (
        if not exist "%PROJECT_ROOT%\ml_model\%%f" (
            echo   %WARN% Missing: ml_model\%%f
        )
    )
) else (
    echo   %FAIL% ml_model/ module not found or missing __init__.py
    set /a ERRORS+=1
)

REM classification module
if exist "%PROJECT_ROOT%\classification\__init__.py" (
    echo   %PASS% classification/ module found
) else (
    echo   %FAIL% classification/ module not found or missing __init__.py
    set /a ERRORS+=1
)

REM classification sub-modules
for %%s in (classification_batch classification_live classification_simulated) do (
    if exist "%PROJECT_ROOT%\classification\%%s\__init__.py" (
        echo   %PASS% classification/%%s/ found
    ) else (
        echo   %WARN% classification/%%s/ missing or no __init__.py
    )
)

REM Key entry scripts
for %%f in (main.py ml_model.py classification.py config.py) do (
    if exist "%PROJECT_ROOT%\%%f" (
        echo   %PASS% %%f
    ) else (
        echo   %FAIL% %%f missing!
        set /a ERRORS+=1
    )
)

echo.

REM ============================================================
REM  STEP 9: Npcap / Packet Capture Check (for live mode)
REM ============================================================
echo %BOLD%--- Step 9: Packet Capture (Npcap) ---%RESET%

set "NPCAP_OK=0"
if exist "C:\Windows\System32\Npcap\wpcap.dll" set "NPCAP_OK=1"
if exist "C:\Windows\SysWOW64\Npcap\wpcap.dll" set "NPCAP_OK=1"
REM Also check the older WinPcap-compatible location
if exist "C:\Windows\System32\wpcap.dll" set "NPCAP_OK=1"

if %NPCAP_OK% EQU 1 (
    echo   %PASS% Npcap / WinPcap detected
) else (
    echo   %WARN% Npcap not detected. Required ONLY for live capture mode.
    echo          Download from: https://npcap.com
    echo          Install with "WinPcap API-compatible Mode" enabled.
    echo          (Not needed for batch/simulation/ML training modes)
)

echo.

REM ============================================================
REM  SUMMARY
REM ============================================================
echo %BOLD%============================================================%RESET%
if %ERRORS% EQU 0 (
    echo %GREEN%%BOLD%  SETUP COMPLETE - No errors!%RESET%
) else (
    echo %RED%%BOLD%  SETUP COMPLETE - %ERRORS% error(s) detected.%RESET%
    echo   Review the %FAIL% items above and fix them.
)
echo %BOLD%============================================================%RESET%
echo.
echo   Next steps:
echo     1. Activate the venv:   venv\Scripts\activate
echo     2. Run ML pipeline:     python ml_model.py --help
echo     3. Run classification:  python classification.py --help
echo.

endlocal
pause
