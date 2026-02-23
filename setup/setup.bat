REM Setup script for NIDS Project on Windows
REM Checks prerequisites, creates venv, installs deps, tests interface detection

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.

REM Navigate to project root (one level up from setup/)
cd /d "%~dp0.." || (
    echo [ERROR] Failed to navigate to project root
    echo Current location: %cd%
    echo Script location: %~dp0
    pause
    exit /b 1
)

echo [DEBUG] Now in directory: %cd%
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
    echo     DOWNLOAD and install Python from:
    echo       https://www.python.org/downloads/
    echo.
    echo     OR use Windows Package Manager (winget):
    echo       winget install Python.Python.3.12
    echo.
    echo     OR use Chocolatey:
    echo       choco install python
    echo.
    echo     IMPORTANT during install:
    echo       - Check "Add Python to PATH" at the bottom
    echo       - Click "Install Now" or Customize to install all
    echo       - CLOSE and REOPEN this terminal after install
    echo       - Run: python --version
    echo       - Then run this script again
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
    echo   [ERROR] Npcap is not installed (needed for packet capture).
    echo.
    echo     OPTION 1: Download and run installer:
    echo       Link: https://npcap.com/
    echo       - Download npcap-X.XX.exe
    echo       - Run the installer
    echo       - CHECK "Install Npcap in WinPcap API-compatible Mode"
    echo.
    echo     OPTION 2: Download via PowerShell (auto-run):
    echo       powershell -Command "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.81.exe' -OutFile 'npcap-installer.exe'; Start-Process 'npcap-installer.exe' -Wait"
    echo.
    echo     OPTION 3: Use Chocolatey:
    echo       choco install npcap
    echo.
    echo     After install, CLOSE and REOPEN this terminal, then run script again.
    echo. — Missing required software
    echo ================================================================================
    echo.
    echo   STEPS TO FIX:
    echo     1. Install the software shown above
    echo     2. CLOSE this terminal completely
    echo     3. OPEN a NEW terminal (critical for PATH updates)
    echo     4. Navigate to this folder: cd Z:\Nids
    echo     5. Run this script again: setup\setup.bat
    echo
)

if "%FAIL%"=="1" (
    echo.
    echo ================================================================================
    echo   SETUP CANNOT CONTINUE - Missing required software
    echo ================================================================================
    echo.
    echo   STEPS TO FIX:
    echo     1. Install the software shown above
    echo     2. CLOSE this terminal completely
    echo     3. OPEN a NEW terminal (critical for PATH updates)
    echo     4. Navigate to this folder: cd Z:\Nids
    echo     5. Run this script again: setup\setup.bat
    echo.
    echo ================================================================================
    echo.
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
        echo.
        echo   Troubleshooting:
        echo     - Check Python is installed: python --version
        echo     - Check Python location: where python
        echo     - Check disk space available
        echo.
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
    echo.
    echo   Try manually:
    echo     venv\Scripts\activate.bat
    echo.
    pause
    exit /b 1
)

pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo   [ERROR] pip install failed
    echo.
    echo   Troubleshooting:
    echo     1. Check internet connection
    echo     2. Try manually: pip install --upgrade pip
    echo     3. Then: pip install -r requirements.txt
    echo     4. If errors about packages, try: pip install --upgrade pip
    echo.
    pause
    exit /b 1
)
echo   [OK] Dependencies installed

REM ==================================================================
REM Done
REM ==================================================================
echo.
echo ================================================================================
echo   Setup Complete!  Everything is working.
echo ================================================================================
echo.
echo   NEXT STEPS:
echo.
echo   1. ACTIVATE the virtual environment:
echo      venv\Scripts\activate
echo.
echo   2. TEST live classification (detects interfaces):
echo      python classification.py
echo.
echo   3. RUN live classification (captures packets):
echo      python classification.py
echo.
echo   OPTIONS:
echo.
echo      See all commands:
echo        python classification.py --help
echo.
echo      Capture for 5 minutes:
echo        python classification.py --duration 300
echo.
echo      Use 6-class model (if trained):
echo        python classification.py --model all
echo.
echo      Batch classify a CSV file:
echo        python classification.py --batch flows.csv
echo.
echo      Train ML model (requires CICIDS2018 dataset):
echo        python ml_model.py --full
echo.
echo   NOTE: If you open a NEW terminal, activate the venv first:
echo      venv\Scripts\activate
echo.
echo ================================================================================
echo   Press any key to close this window...
echo ================================================================================
echo.

pause
