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

echo.
echo ================================================================================
echo   NIDS Attacker Setup - Windows
echo ================================================================================
echo   Sets up your machine to launch attacks against a target device.
echo ================================================================================
echo.

REM ==================================================================
REM Step 1: Check Python
REM ==================================================================
echo Step 1: Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
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
REM Step 2: Create/Check venv
REM ==================================================================
echo Step 2: Checking virtual environment...

if exist venv (
    echo   [OK] venv already exists
) else (
    echo   Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] venv created
)
echo.

REM ==================================================================
REM Step 3: Install base + attack dependencies
REM ==================================================================
echo Step 3: Installing dependencies...
call venv\Scripts\activate.bat
echo.

echo   Upgrading pip...
python -m pip install --upgrade pip >nul 2>&1

echo   Installing base packages (requirements.txt)...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo   [!] Base requirements install failed
)

echo   Installing attack dependencies...
if exist setup\setup_attacker\requirements.txt (
    pip install -r setup\setup_attacker\requirements.txt
    if %errorlevel% neq 0 (
        echo   [!] Attack requirements install failed
    ) else (
        echo   [OK] Attack dependencies installed
    )
) else (
    echo   [!] setup\setup_attacker\requirements.txt not found
)
echo.

REM ==================================================================
REM Step 4: Verify packages and scripts
REM ==================================================================
echo Step 4: Verifying installation...
echo.

set VERIFY_OK=1

echo   Checking attack packages:
python -c "import paramiko" >nul 2>&1
if !errorlevel! equ 0 (
    echo     [OK] paramiko (SSH attacks)
) else (
    echo     [!] paramiko MISSING
    set VERIFY_OK=0
)

for %%p in (requests,psutil) do (
    python -c "import %%p" >nul 2>&1
    if !errorlevel! equ 0 (
        echo     [OK] %%p
    ) else (
        echo     [!] %%p MISSING
        set VERIFY_OK=0
    )
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
echo   1. Activate venv:
echo        venv\Scripts\activate.bat
echo.
echo   2. For attack simulation steps:
echo        See: PROJECT_RUN.md (in project root) - Section 4: Attack Simulation
echo.
echo   3. To set up other components:
echo        See: setup/SETUPS.md
echo.
echo   4. For project overview:
echo        See: README.md (in project root)
echo.
echo   IMPORTANT: Set up the victim device first!
echo   Run setup\setup_victim\setup_victim.bat on the target device.
echo.
pause
