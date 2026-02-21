@echo off
REM Setup script for NIDS Project on Windows
REM Checks prerequisites, creates venv, installs pip deps, builds CICFlowMeter

REM Navigate to project root (one level up from setup/)
cd /d "%~dp0.."

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.

REM ------------------------------------------------------------------
REM Step 1: Check prerequisites (won't install anything for you)
REM ------------------------------------------------------------------
echo Step 1: Checking prerequisites...
echo.

set "HAS_ISSUES=0"
set "JAVA_OK=0"

REM --- Python ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   X Python not found
    echo     Install Python 3.8+ from https://www.python.org/downloads/
    echo     IMPORTANT: Check "Add Python to PATH" during install
    echo.
    echo ERROR: Cannot continue without Python. Install it and re-run.
    echo.
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo   OK  Python %PYTHON_VER% found

REM --- Java ---
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo   X Java not found
    echo     Install Java 8-21 from https://adoptium.net/ ^(recommend Temurin 17 LTS^)
    echo     Make sure java is added to PATH
    set "HAS_ISSUES=1"
    goto :done_java
)

for /f "tokens=3" %%v in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VER_RAW=%%~v
)
for /f "delims=." %%m in ("%JAVA_VER_RAW%") do set JAVA_MAJOR=%%m
if "%JAVA_MAJOR%"=="1" (
    for /f "tokens=2 delims=." %%m in ("%JAVA_VER_RAW%") do set JAVA_MAJOR=%%m
)

if %JAVA_MAJOR% GEQ 8 if %JAVA_MAJOR% LEQ 21 (
    set JAVA_OK=1
    echo   OK  Java %JAVA_MAJOR% found
    goto :done_java
)

echo   X Java %JAVA_MAJOR% found — NOT compatible ^(need 8-21^)
echo     Gradle 8.5 supports Java 8 through 21 only.
echo     Install Java 17 LTS from https://adoptium.net/
set "HAS_ISSUES=1"

:done_java

REM --- Npcap ---
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo   OK  Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo   OK  WinPcap/Npcap found
) else (
    echo   X Npcap not found
    echo     Install from https://npcap.com
    echo     IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode"
    set "HAS_ISSUES=1"
)

echo.
if "%HAS_ISSUES%"=="1" (
    echo ----------------------------------------------------------------
    echo   Some prerequisites are missing ^(see above^).
    echo   Live capture features won't work until they're installed.
    echo   Continuing with what we can do...
    echo ----------------------------------------------------------------
    echo.
)

REM ------------------------------------------------------------------
REM Step 2: Create virtual environment
REM ------------------------------------------------------------------
echo Step 2: Creating virtual environment...
echo.

if exist venv (
    echo   OK  Virtual environment already exists — skipping
) else (
    python -m venv venv
    if not exist venv (
        echo   ERROR: Failed to create venv
        pause
        exit /b 1
    )
    echo   OK  Virtual environment created
)

REM ------------------------------------------------------------------
REM Step 3: Activate venv & install pip dependencies
REM ------------------------------------------------------------------
echo.
echo Step 3: Installing Python dependencies...
echo.
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo   ERROR: Failed to activate venv
    pause
    exit /b 1
)

pip install -r requirements.txt --quiet --dry-run >nul 2>&1
if %errorlevel% equ 0 (
    pip install -r requirements.txt --quiet --dry-run 2>&1 | findstr /i "Would install" >nul 2>&1
    if errorlevel 1 (
        echo   OK  All dependencies already satisfied — skipping
        goto :skip_pip
    )
)

echo   Installing/updating packages...
pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo   ERROR: pip install failed
    pause
    exit /b 1
)
echo   OK  Dependencies installed

:skip_pip

REM ------------------------------------------------------------------
REM Step 4: Build CICFlowMeter
REM ------------------------------------------------------------------
echo.
echo Step 4: Building CICFlowMeter...
echo.

if %JAVA_OK%==0 (
    echo   Skipped — Java 8-21 not available ^(see Step 1^)
    goto :skip_gradle
)

if not exist CICFlowMeter\gradlew.bat (
    echo   WARNING: CICFlowMeter\gradlew.bat not found — skipping
    goto :skip_gradle
)

if exist CICFlowMeter\build\classes\java\main (
    echo   OK  CICFlowMeter already built — skipping
    goto :skip_gradle
)

echo   Building with Gradle...
pushd CICFlowMeter
call gradlew.bat classes
if errorlevel 1 (
    echo   WARNING: Build failed — live capture won't work
    echo   Retry manually: cd CICFlowMeter ^& gradlew.bat classes ^& cd ..
) else (
    echo   OK  CICFlowMeter built successfully
)
popd

:skip_gradle

REM ------------------------------------------------------------------
REM Done
REM ------------------------------------------------------------------
echo.
echo ================================================================================
echo Setup Complete!
echo ================================================================================
echo.
echo Usage:
echo.
echo   1. Activate the virtual environment:
echo        venv\Scripts\activate
echo.
echo   2. Run live classification:
echo        python classification.py --duration 180
echo.
echo   3. Run ML model pipeline:
echo        python ml_model.py --help
echo.
echo ================================================================================
echo.

pause
