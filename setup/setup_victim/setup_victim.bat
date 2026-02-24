@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM Victim Device Setup - Windows
REM ==============================================================================
REM Run this ON THE TARGET DEVICE (VM or server) to check readiness for attacks.
REM Right-click -> Run as Administrator
REM ==============================================================================

REM Navigate to project root - CRITICAL
cd /d "%~dp0..\.."
if !errorlevel! neq 0 (
    echo [ERROR] Failed to change directory to project root
    pause
    exit /b 1
)

REM Get absolute path to project root
for /f "delims=" %%i in ('cd') do set PROJECT_ROOT=%%i

REM Define venv path
set VENV_PYTHON=!PROJECT_ROOT!\venv\Scripts\python.exe

echo.
echo ================================================================================
echo   Victim Device Setup - Windows
echo ================================================================================
echo   Checks if this device is ready to receive attacks.
echo   Will NOT change anything without asking first.
echo ================================================================================
echo.

REM Check admin
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Run as Administrator.
    echo   Right-click setup_victim.bat -^> Run as Administrator
    pause
    exit /b 1
)

echo   [OK] Running as Administrator
echo.

REM Check if Python is available
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo   [ERROR] Python not found in PATH
    echo   Install Python 3.12+ from https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python found: !PYVER!
echo.
REM Check current directory
echo [DEBUG] Current directory: !PROJECT_ROOT!
echo [DEBUG] Checking for venv at: !VENV_PYTHON!

REM Check if venv exists - REQUIRED, no fallback
if not exist "!VENV_PYTHON!" (
    echo   [ERROR] venv not found at !VENV_PYTHON!
    echo   venv must be set up first.
    echo.
    echo   Run setup_basic first:
    echo     setup\setup_basic\setup_basic.bat
    echo.
    pause
    exit /b 1
)
echo   [OK] Found venv: !VENV_PYTHON!
echo   Using venv Python...
call "!PROJECT_ROOT!\venv\Scripts\activate.bat"
if !errorlevel! neq 0 (
    echo   [ERROR] Failed to activate venv
    pause
    exit /b 1
)
"!VENV_PYTHON!" setup\setup_victim\setup_victim.py
set exit_code=!errorlevel!
echo.
echo ================================================================================
if !exit_code! equ 0 (
    echo   [OK] Victim setup check complete
) else (
    echo   [!] Some issues were found (see above)
)
echo ================================================================================
echo.
echo   Log file location (if needed): setup\setup_victim\setup_victim_debug.log
echo.
echo   Next steps:
echo.
echo   1. Start NIDS on this device to detect attacks:
echo        See: PROJECT_RUN.md (in project root)
echo.
echo   2. To understand all setup options:
echo        See: setup/SETUPS.md
echo.
echo   3. For project overview:
echo        See: README.md (in project root)
echo.

echo.
echo ================================================================================
echo   Press any key to close this window...
echo ================================================================================
pause
