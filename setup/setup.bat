REM Setup script for NIDS Project on Windows
REM Checks prerequisites, creates venv, installs deps, tests interface detection

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.
echo [STATUS] Script started - you should see this message!
echo.
pause

REM ==================================================================
REM Step 1: Check Python
REM ==================================================================
echo.
echo ================================================================================
echo Step 1: Checking Python installation...
echo ================================================================================
echo.
echo [STATUS] Checking if Python is installed...if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Python is not installed OR not in PATH
    echo.
    echo   How to fix:
    echo     1. Download Python: https://www.python.org/downloads/
    echo     2. During install - CHECK "Add Python to PATH"
    echo     3. Restart your terminal completely (close and reopen)
    echo     4. Run: python --version
    echo     5. Then run this script again
    echo.
    pause
    exit /b 1
)
echo [OK] Python is installed
echo.
echo ========== PYTHON CHECK COMPLETE ==========
pause

REM ==================================================================
REM Step 2: Check Npcap
REM ==================================================================
echo.
echo ================================================================================
echo Step 2: Checking Npcap (packet capture - optional)...
echo ================================================================================
echo.

if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo [OK] Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo [OK] WinPcap/Npcap found
) else (
    echo [WARNING] Npcap not found (optional - only for live packet capture)
echo.
echo ========== NPCAP CHECK COMPLETE ==========
    echo   Download: https://npcap.com
)
pause

REM ==================================================================
REM Step 3: Create virtual environment
REM ==================================================================
echo.
echo ================================================================================
echo Step 3: Creating/checking virtual environment...
echo ================================================================================
echo.

if exist venv (
    echo [OK] Virtual environment already exists - skipping creation
) else (
    echo Creating virtual environment...
    python -m venv venv
    if not exist venv (
        echo [ERROR] Failed to create venv
        echo.
        pause
        exit /b 1
    )
echo.
echo ========== VENV CREATION COMPLETE ==========
    echo [OK] Virtual environment created
)
pause

REM ==================================================================
REM Step 4: Activate virtual environment
REM ==================================================================
echo.
echo ================================================================================
echo Step 4: Activating virtual environment...
echo ================================================================================
echo.

call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    echo.
echo.
echo ========== VENV ACTIVATION COMPLETE ==========
    pause
    exit /b 1
)
echo [OK] Virtual environment activated
pause

REM ==================================================================
REM Step 5: Install Python packages
REM ==================================================================
echo.
echo ================================================================================
echo Step 5: Installing Python dependencies...
echo        (this may take a few minutes)
echo ================================================================================
echo.

echo Upgrading pip...
pip install --upgrade pip
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip
    echo.
    pause
    exit /b 1
)
echo [OK] pip upgraded
echo.
echo ========== PIP UPGRADE COMPLETE - Press any key to continue to package install ==========
pause
echo.

echo Installing packages from requirements.txt...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed
    echo.
    echo Troubleshooting:
    echo   - Check internet connection
    echo   - Try manually: pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo [OK] All packages installed
echo.
echo ========== PACKAGE INSTALL COMPLETE ==========
pause

REM ==================================================================
REM SUCCESS
REM ==================================================================
echo.
echo ================================================================================
echo   SUCCESS! Setup Complete!
echo ================================================================================
echo.
echo   Next time you open a terminal, run:
echo      venv\Scripts\activate
echo.
echo   Then you can:
echo      python classification.py
echo      python ml_model.py --help
echo.
echo ================================================================================
echo.
pause
