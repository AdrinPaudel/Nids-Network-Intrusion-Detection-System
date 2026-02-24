@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM NIDS Basic Setup - Windows
REM ==============================================================================
REM Sets up Python environment for classification (live + batch) using
REM the pre-trained model. No dataset download or ML training needed.
REM
REM Usage: Run from project root:
REM   setup\setup_basic\setup_basic.bat
REM ==============================================================================

REM Navigate to project root (two levels up from setup/setup_basic/)
cd /d "%~dp0..\.."
if !errorlevel! neq 0 (
    echo [ERROR] Failed to change to project root
    pause
    exit /b 1
)

REM Get absolute path to project root
for /f "delims=" %%i in ('cd') do set PROJECT_ROOT=%%i
set VENV_PYTHON=!PROJECT_ROOT!\venv\Scripts\python.exe

echo.
echo ================================================================================
echo   NIDS Basic Setup - Windows
echo ================================================================================
echo   Sets up Python environment for classification using the pre-trained model.
echo   No dataset or ML training required.
echo ================================================================================
echo.

REM ==================================================================
REM Step 1: Check Python
REM ==================================================================
echo Step 1: Checking Python...
python --version >nul 2>&1
if !errorlevel! neq 0 (
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
echo   [OK] Python !PYVER!
echo.

REM ==================================================================
REM Step 2: Check Npcap (needed for live capture)
REM ==================================================================
echo Step 2: Checking Npcap (for live packet capture)...

if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo   [OK] Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo   [OK] WinPcap/Npcap found
) else (
    echo   [!] Npcap not found (needed for live capture only)
    echo.
    echo   Install Npcap:
    echo     Download: https://npcap.com
    echo     IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode"
    echo.
    echo   If you only need batch classification, you can skip this.
)
echo.

REM ==================================================================
REM Step 3: Create virtual environment
REM ==================================================================
echo Step 3: Creating virtual environment...

if exist "!VENV_PYTHON!" (
    echo   [OK] venv already exists
) else (
    python -m venv venv
    if !errorlevel! neq 0 (
        echo   [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo   [OK] venv created
)
echo.

REM ==================================================================
REM Step 4: Install dependencies
REM ==================================================================
echo Step 4: Installing dependencies...
call "!PROJECT_ROOT!\venv\Scripts\activate.bat"
echo.

echo   Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

echo   Installing packages from requirements.txt...
pip install -r requirements.txt
if !errorlevel! neq 0 (
    echo.
    echo   [ERROR] pip install failed
    echo.
    echo   Try manually:
    echo     venv\Scripts\activate.bat
    echo     pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo   [OK] All packages installed
echo.

REM ==================================================================
REM Step 5: Verify packages
REM ==================================================================
echo Step 5: Verifying packages...
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
echo.

if %VERIFY_OK% equ 0 (
    echo   WARNING: Some packages are missing. Try running again or:
    echo     pip install -r requirements.txt
    echo.
) else (
    echo   [OK] All packages verified!
    echo.
)

REM ==================================================================
REM Done
REM ==================================================================
echo ================================================================================
echo   Basic Setup Complete!
echo ================================================================================
echo.
echo   Next steps:
echo.
echo   1. Activate venv (every new terminal):
echo        venv\Scripts\activate.bat
echo.
echo   2. For details on running features:
echo        See: PROJECT_RUN.md (in project root)
echo.
echo   3. To set up other components:
echo        See: setup/SETUPS.md
echo.
echo   4. For project overview:
echo        See: README.md (in project root)
echo.
pause
