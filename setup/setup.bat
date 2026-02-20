@echo off
REM Setup script for NIDS Project on Windows
REM Creates virtual environment and installs dependencies

REM Navigate to project root (one level up from setup/)
cd /d "%~dp0.."

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    exit /b 1
)

echo.
echo Step 1: Creating virtual environment...
echo.
python -m venv venv

if not exist venv (
    echo ERROR: Failed to create venv
    exit /b 1
)

echo ✓ Virtual environment created

echo.
echo Step 2: Activating virtual environment...
echo.
call venv\Scripts\activate.bat

if errorlevel 1 (
    echo ERROR: Failed to activate venv
    exit /b 1
)

echo ✓ Virtual environment activated

echo.
echo Step 3: Installing dependencies from requirements.txt...
echo.
pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)

echo ✓ Dependencies installed successfully

echo.
echo ================================================================================
echo Setup Complete!
echo ================================================================================
echo.
echo To use the NIDS system:
echo.
echo   1. Activate venv (in new terminal):
echo      venv\Scripts\activate
echo.
echo   2. Run classification:
echo      python classification.py --duration 180
echo.
echo   3. Run ML model pipeline:
echo      python ml_model.py --help
echo.
echo ================================================================================
echo.

pause
