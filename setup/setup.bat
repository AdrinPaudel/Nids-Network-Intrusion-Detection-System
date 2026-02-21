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

if exist venv (
    echo ✓ Virtual environment already exists - skipping creation
) else (
    python -m venv venv
    if not exist venv (
        echo ERROR: Failed to create venv
        exit /b 1
    )
    echo ✓ Virtual environment created
)

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

REM Check if all requirements are already satisfied
pip install -r requirements.txt --quiet --dry-run >nul 2>&1
if %errorlevel% equ 0 (
    pip install -r requirements.txt --quiet --dry-run 2>&1 | findstr /i "Would install" >nul 2>&1
    if errorlevel 1 (
        echo ✓ All dependencies already installed - skipping
        goto :skip_pip
    )
)

echo Installing/updating dependencies...
pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)

echo ✓ Dependencies installed successfully

:skip_pip

echo.
echo Step 4: Building CICFlowMeter (for live network capture)...
echo.

REM Check if Java is installed
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Java is not installed or not in PATH
    echo Skipping CICFlowMeter build - Java 8-21 is required for live capture
    echo Recommend installing Java 17 LTS from https://adoptium.net/
    echo Then build manually: cd CICFlowMeter ^& gradlew.bat build ^& cd ..
    goto :skip_gradle
)

REM Check Java version - Gradle 8.5 only supports Java 8 through 21
REM Extract major version from java -version output
for /f "tokens=3" %%v in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VER_RAW=%%~v
)
REM Parse major version (handles both "1.8.x" and "17.x.x" formats)
for /f "delims=." %%m in ("%JAVA_VER_RAW%") do set JAVA_MAJOR=%%m
if "%JAVA_MAJOR%"=="1" (
    for /f "tokens=2 delims=." %%m in ("%JAVA_VER_RAW%") do set JAVA_MAJOR=%%m
)

echo Detected Java major version: %JAVA_MAJOR%

REM Check if version is between 8 and 21
set JAVA_OK=0
if %JAVA_MAJOR% GEQ 8 if %JAVA_MAJOR% LEQ 21 set JAVA_OK=1

if %JAVA_OK%==0 (
    echo WARNING: Java %JAVA_MAJOR% is NOT compatible with Gradle 8.5
    echo Gradle 8.5 supports Java 8 through 21 only.
    echo Install Java 17 LTS from https://adoptium.net/
    echo Then build manually: cd CICFlowMeter ^& gradlew.bat build ^& cd ..
    goto :skip_gradle
)

if not exist CICFlowMeter\gradlew.bat (
    echo WARNING: CICFlowMeter\gradlew.bat not found - skipping build
    goto :skip_gradle
)

echo Building CICFlowMeter with Gradle...

REM Skip if already built
if exist CICFlowMeter\build\classes\main (
    echo ✓ CICFlowMeter already built - skipping
    goto :skip_gradle
)

pushd CICFlowMeter
call gradlew.bat build
if errorlevel 1 (
    echo WARNING: CICFlowMeter build failed - live capture may not work
    echo You can retry manually: cd CICFlowMeter ^& gradlew.bat build ^& cd ..
) else (
    echo ✓ CICFlowMeter built successfully
)
popd

:skip_gradle

echo.
echo Step 5: Checking Npcap (required for live capture on Windows)...
echo.

REM Check if Npcap/WinPcap is installed by looking for the DLL
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo ✓ Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo ✓ WinPcap/Npcap found
) else (
    echo WARNING: Npcap not detected
    echo For live network capture, install Npcap from https://npcap.com
    echo IMPORTANT: Check "Install Npcap in WinPcap API-compatible Mode" during install
)

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
echo   For live capture you also need:
echo     - Java 8-21 (https://adoptium.net/ - recommend Java 17 LTS)
echo     - Npcap installed with WinPcap API-compatible mode (https://npcap.com)
echo     - CICFlowMeter built (cd CICFlowMeter ^& gradlew.bat build ^& cd ..)
echo.
echo ================================================================================
echo.

pause
