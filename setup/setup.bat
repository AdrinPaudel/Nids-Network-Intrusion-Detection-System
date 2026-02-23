@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
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

REM Step 2: Check Npcap
echo Step 2: Checking Npcap...
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo OK - Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo OK - WinPcap found
) else (
    echo WARNING - Npcap not found (optional for live capture)
    echo.
    echo DOWNLOAD OPTIONS:
    echo   Link: https://npcap.com/
    echo   Command: choco install npcap
    echo   Command: winget install Nmap.Npcap
    echo.
    echo IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode" during install
echo.

REM Step 3: Create venv
echo Step 3: Creating virtual environment...
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

REM Step 4: Activate and install
echo Step 4: Installing dependencies...
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

REM Success
echo ================================================================================
echo SUCCESS - Setup Complete!
echo ================================================================================
echo.
echo Next steps:
echo   1. Activate venv: venv\Scripts\activate
echo   2. Run: python classification.py
echo.
pause
