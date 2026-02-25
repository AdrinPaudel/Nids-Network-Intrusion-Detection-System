@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM NIDS Victim Device Setup - Windows
REM ==============================================================================
REM Sets up the victim device for attack simulation testing.
REM Configures SSH server and web services for network traffic generation.
REM
REM REQUIRES: Administrator privileges
REM Usage: Right-click -> Run as Administrator
REM   OR: setup\setup_victim\setup_victim.bat
REM ==============================================================================

echo.
echo ================================================================================
echo   NIDS Victim Device Setup - Windows
echo ================================================================================
echo   Configures SSH server and web services for attack simulations.
echo ================================================================================
echo.

REM ==================================================================
REM Check: Administrator Privileges
REM ==================================================================
echo Checking: Administrator privileges...
net session >nul 2>&1
if !errorlevel! neq 0 (
    echo.
    echo   [ERROR] This script requires Administrator privileges!
    echo.
    echo   Please run as Administrator:
    echo     1. Right-click on this .bat file
    echo     2. Select "Run as Administrator"
    echo     3. Click "Yes" when prompted
    echo.
    pause
    exit /b 1
)
echo   [OK] Running as Administrator
echo.

REM ==================================================================
REM Check: Python Installation
REM ==================================================================
echo Checking: Python installation...
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo.
    echo   [ERROR] Python is not installed or not in PATH.
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
REM Navigate to project root
REM ==================================================================
cd /d "%~dp0..\.."
if !errorlevel! neq 0 (
    echo [ERROR] Failed to navigate to project root
    pause
    exit /b 1
)

for /f "delims=" %%i in ('cd') do set PROJECT_ROOT=%%i
echo Project Root: !PROJECT_ROOT!
echo.

REM ==================================================================
REM Run Victim Setup Script
REM ==================================================================
echo Running victim device configuration...
echo.

python "%~dp0setup_victim.py" %*
if !errorlevel! neq 0 (
    echo.
    echo   [ERROR] Victim setup script failed
    echo.
    pause
    exit /b 1
)
echo.

REM ==================================================================
REM Done
REM ==================================================================
echo ================================================================================
echo   Victim Device Setup Complete!
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
