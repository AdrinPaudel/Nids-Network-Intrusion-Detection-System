@echo off
REM Setup script for NIDS Project on Windows
REM Checks prerequisites, creates venv, installs deps, tests interface detection

REM Navigate to project root (one level up from setup/)
cd /d "%~dp0.."

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.

REM ==================================================================
REM Step 1: Check Python ^& Npcap (user must install these themselves)
REM ==================================================================
echo Step 1: Checking required software...
echo.

set "FAIL=0"

REM --- Python ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Python is not installed.
    echo.
    echo     Download and install Python:
    echo       https://www.python.org/downloads/
    echo.
    echo     IMPORTANT during install:
    echo       1. Check "Add Python to PATH" at the bottom of the installer
    echo       2. Click "Install Now" (or Customize ^> check all boxes)
    echo       3. Close and reopen your terminal after installing
    echo.
    set "FAIL=1"
    goto :check_npcap
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo   [OK] Python %PYTHON_VER%

:check_npcap
REM --- Npcap (needed by Scapy for packet capture) ---
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo   [OK] Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo   [OK] WinPcap/Npcap found
) else (
    echo   [ERROR] Npcap is not installed.
    echo           Scapy ^(packet capture library^) needs Npcap to work.
    echo.
    echo     Download and install Npcap:
    echo       https://npcap.com
    echo.
    echo     IMPORTANT during install:
    echo       Check "Install Npcap in WinPcap API-compatible Mode"
    echo.
    set "FAIL=1"
)

if "%FAIL%"=="1" (
    echo.
    echo ================================================================================
    echo   SETUP CANNOT CONTINUE
    echo   Install the missing software above, then re-run this script.
    echo ================================================================================
    pause
    exit /b 1
)

REM ==================================================================
REM Step 2: Create virtual environment
REM ==================================================================
echo.
echo Step 2: Creating virtual environment...
echo.

if exist venv (
    echo   [OK] Already exists — skipping
) else (
    python -m venv venv
    if not exist venv (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] Virtual environment created
)

REM ==================================================================
REM Step 3: Activate venv ^& install pip dependencies
REM ==================================================================
echo.
echo Step 3: Installing Python dependencies...
echo.
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo   [ERROR] Failed to activate venv
    pause
    exit /b 1
)

pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo   [ERROR] pip install failed
    pause
    exit /b 1
)
echo   [OK] Dependencies installed

REM ==================================================================
REM Step 4: Test interface detection
REM ==================================================================
echo.
echo Step 4: Testing network interface detection...
echo.

python -c "from classification.flowmeter_source import list_interfaces; ifaces = list_interfaces(); print(f'  [OK] Detected {len(ifaces)} network interface(s)') if ifaces else print('  [WARNING] No interfaces detected')" 2>nul
if errorlevel 1 (
    echo   [WARNING] Interface detection test failed. This may be a permissions issue.
    echo            Try running the terminal as Administrator.
)

REM ==================================================================
REM Done
REM ==================================================================
echo.
echo ================================================================================
echo   Setup Complete!  Everything is working.  (venv is active)
echo ================================================================================
echo.
echo   Run live classification:
echo       python classification.py --duration 180
echo.
echo   List network interfaces:
echo       python classification.py --list-interfaces
echo.
echo   Run ML model pipeline:
echo       python ml_model.py --help
echo.
echo   NOTE: If you open a NEW terminal, activate the venv again first:
echo       venv\Scripts\activate
echo.
echo ================================================================================
echo.

pause
