@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.
echo Script started - you should see this message
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

REM Step 2: Check Npcap
echo.
echo ================================================================================
echo Step 2: Checking Npcap (optional)
echo ================================================================================
echo.

if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo OK - Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo OK - WinPcap found
) else (
    echo WARNING - Npcap not found (optional for live capture)
    echo Download: https://npcap.com
)

echo.
pause

REM Step 3: Create venv
echo.
echo ================================================================================
echo Step 3: Creating virtual environment
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

REM Step 4: Activate and install
echo.
echo ================================================================================
echo Step 4: Installing dependencies
echo ================================================================================
echo.

call venv\Scripts\activate.bat

echo Upgrading pip...
pip install --upgrade pip

echo.
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

REM Success
echo.
echo ================================================================================
echo SUCCESS - Setup Complete!
echo ================================================================================
echo.
echo Next steps:
echo   1. Activate venv: venv\Scripts\activate
echo   2. Run: python classification.py
echo.
echo ================================================================================
echo.
pause
