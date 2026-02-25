@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM NIDS Attacker Setup - Windows
REM ==============================================================================
REM Sets up the attacker machine with dependencies to launch attacks
REM against the target device.
REM
REM Usage: Run from project root:
REM   setup\setup_attacker\setup_attacker.bat
REM ==============================================================================

cd /d "%~dp0..\.."
if !errorlevel! neq 0 (
    echo [ERROR] Failed to change to project root directory
    pause
    exit /b 1
)

REM Get absolute path to project root
for /f "delims=" %%i in ('cd') do set PROJECT_ROOT=%%i
set VENV_PYTHON=!PROJECT_ROOT!\venv\Scripts\python.exe

echo.
echo ================================================================================
echo   NIDS Attacker Setup - Windows
echo ================================================================================
echo   Sets up your machine to launch attacks against a target device.
echo ================================================================================
echo.

REM ==================================================================
REM Step 1: Enable TCP Timestamps (CRITICAL for classification)
REM ==================================================================
echo Step 1: Enabling TCP Timestamps...
echo.
echo   TCP timestamps add 12 bytes to the TCP header (20 -^> 32 bytes).
echo   This is CRITICAL because the CICIDS2018 training data was generated
echo   from Linux (Kali) attackers that always include TCP timestamps.
echo   The model's #1 feature (Fwd Seg Size Min) depends on this.
echo   Without timestamps: Fwd Seg Size Min = 20 -^> classified as Benign
echo   With timestamps:    Fwd Seg Size Min = 32 -^> classified correctly
echo.

REM Check current setting
for /f "tokens=*" %%i in ('netsh int tcp show global ^| findstr /i "Timestamps"') do set TSLINE=%%i
echo   Current: !TSLINE!

REM Try to enable (requires admin)
netsh int tcp set global timestamps=enabled >nul 2>&1
if !errorlevel! equ 0 (
    echo   [OK] TCP timestamps enabled
) else (
    echo   [WARNING] Could not enable TCP timestamps (need admin privileges)
    echo.
    echo   To fix manually, run as Administrator:
    echo     netsh int tcp set global timestamps=enabled
    echo.
    echo   This is THE MOST IMPORTANT fix for classification accuracy.
)
echo.

REM ==================================================================
REM Step 2: Check Python
REM ==================================================================
echo Step 2: Checking Python...
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
echo   [OK] Python %PYVER%
echo.

REM ==================================================================
REM Step 3: Create/Check venv
REM ==================================================================
echo Step 3: Checking virtual environment...

if exist venv (
    echo   [OK] venv already exists
) else (
    echo   Creating virtual environment...
    python -m venv venv
    if !errorlevel! neq 0 (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] venv created
)
echo.

REM ==================================================================
REM Step 4: Install base + attack dependencies
REM ==================================================================
echo Step 4: Installing dependencies...
call venv\Scripts\activate.bat
echo.

echo   Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

echo   Installing base packages (from project root)...
pip install -r requirements.txt
if !errorlevel! neq 0 (
    echo   [!] Base requirements install failed
)
echo.

echo   Installing attack dependencies (paramiko + psutil)...
if exist "setup\setup_attacker\requirements.txt" (
    pip install -r setup\setup_attacker\requirements.txt
    if !errorlevel! neq 0 (
        echo   [ERROR] Attack requirements install failed
        echo.
        echo   Try manually:
        echo     pip install -r setup\setup_attacker\requirements.txt
        echo.
    ) else (
        echo   [OK] Attack dependencies installed
    )
) else (
    echo   [ERROR] setup\setup_attacker\requirements.txt not found!
    echo.
    echo   Trying individual packages...
    pip install paramiko psutil
)
echo.

REM ==================================================================
REM Step 5: Verify packages and scripts
REM ==================================================================
echo Step 5: Verifying installation...
echo.

set VERIFY_OK=1

echo   Checking attack packages:
echo.

REM Check paramiko
echo   Checking paramiko...
python -c "import paramiko" >nul 2>&1
if !errorlevel! equ 0 (
    echo     [OK] paramiko ^(SSH attacks^)
) else (
    echo     [!] paramiko MISSING
    set VERIFY_OK=0
)

REM Check requests
echo   Checking requests...
python -c "import requests" >nul 2>&1
if !errorlevel! equ 0 (
    echo     [OK] requests
) else (
    echo     [!] requests MISSING
    set VERIFY_OK=0
)

REM Check psutil
echo   Checking psutil...
python -c "import psutil" >nul 2>&1
if !errorlevel! equ 0 (
    echo     [OK] psutil
) else (
    echo     [!] psutil MISSING
    set VERIFY_OK=0
)

echo.
echo   Checking attack scripts:
if exist setup\setup_attacker\device_attack.py (
    echo     [OK] device_attack.py
) else (
    echo     [!] device_attack.py not found
    set VERIFY_OK=0
)

if exist setup\setup_attacker\discover_and_save.py (
    echo     [OK] discover_and_save.py
) else (
    echo     [!] discover_and_save.py not found
    set VERIFY_OK=0
)

if exist setup\setup_attacker\config.py (
    echo     [OK] config.py
) else (
    echo     [!] config.py not found
    set VERIFY_OK=0
)

echo.
if %VERIFY_OK% equ 0 (
    echo   WARNING: Some packages or scripts are missing
    echo   Try: pip install paramiko
    echo.
) else (
    echo   [OK] All packages and scripts verified!
    echo.
)

REM ==================================================================
REM Done
REM ==================================================================
echo ================================================================================
echo   Attacker Setup Complete!
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
