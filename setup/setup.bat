@echo off
REM Setup script for NIDS Project on Windows
REM Checks prerequisites, creates venv, installs deps, builds CICFlowMeter, tests interface detection

REM Navigate to project root (one level up from setup/)
cd /d "%~dp0.."

echo.
echo ================================================================================
echo NIDS Project Setup - Windows
echo ================================================================================
echo.

REM ==================================================================
REM Step 1: Check Python ^& Java (user must install these themselves)
REM ==================================================================
echo Step 1: Checking required software...
echo.

set "FAIL=0"
set "JAVA_OK=0"

REM --- Python ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Python is not installed.
    echo.
    echo     Download and install Python:
    echo       https://www.python.org/downloads/
    echo.
    echo     IMPORTANT during install:
    echo       1. Check "Add Python to PATH" at the bottom of the installer
    echo       2. Click "Install Now" (or Customize ^> check all boxes)
    echo       3. Close and reopen your terminal after installing
    echo.
    set "FAIL=1"
    goto :check_java
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo   [OK] Python %PYTHON_VER%

:check_java
REM --- Java ---
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Java is not installed.
    echo.
    echo     Download and install the Java Development Kit (JDK):
    echo       https://adoptium.net/  (select Temurin 17 LTS, JDK, Windows x64)
    echo.
    echo     IMPORTANT during install:
    echo       1. Make sure you download the JDK (not JRE)
    echo       2. Check "Add to PATH" and "Set JAVA_HOME" options
    echo       3. Close and reopen your terminal after installing
    echo.
    set "FAIL=1"
    goto :done_prereq
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
    echo   [OK] Java %JAVA_MAJOR%
    goto :check_javac
)

echo   [ERROR] Java %JAVA_MAJOR% is NOT compatible. Need Java 8-21.
echo.
echo     Gradle 8.5 supports Java 8 through 21 only.
echo     Download a compatible JDK:
echo       https://adoptium.net/  (select Temurin 17 LTS, JDK, Windows x64)
echo.
echo     IMPORTANT: Check "Add to PATH" and "Set JAVA_HOME" during install.
echo     Close and reopen your terminal after installing.
echo.
set "FAIL=1"
goto :done_prereq

:check_javac
REM --- Check for javac (JDK vs JRE) ---
javac -version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] 'javac' (Java compiler) not found.
    echo           You have Java installed, but only the runtime ^(JRE^).
    echo           Gradle needs the full JDK which includes javac.
    echo.
    echo     NOTE: javac is included in the JDK — do NOT search for it separately.
    echo     Download the JDK from: https://adoptium.net/
    echo       Select: Temurin 17 LTS, JDK (not JRE), Windows x64
    echo.
    echo     IMPORTANT: Check "Add to PATH" and "Set JAVA_HOME" during install.
    echo     Close and reopen your terminal after installing.
    echo.
    set "FAIL=1"
    set "JAVA_OK=0"
) else (
    echo   [OK] javac found ^(JDK^)
)

:done_prereq

if "%FAIL%"=="1" (
    echo.
    echo ================================================================================
    echo   SETUP CANNOT CONTINUE
    echo   Install the missing software above, then re-run this script.
    echo ================================================================================
    pause
    exit /b 1
)

REM ==================================================================
REM Step 2: Create virtual environment
REM ==================================================================
echo.
echo Step 2: Creating virtual environment...
echo.

if exist venv (
    echo   [OK] Already exists — skipping
) else (
    python -m venv venv
    if not exist venv (
        echo   [ERROR] Failed to create venv
        pause
        exit /b 1
    )
    echo   [OK] Virtual environment created
)

REM ==================================================================
REM Step 3: Activate venv ^& install pip dependencies
REM ==================================================================
echo.
echo Step 3: Installing Python dependencies...
echo.
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo   [ERROR] Failed to activate venv
    pause
    exit /b 1
)

pip install --upgrade pip --quiet
pip install -r requirements.txt
if errorlevel 1 (
    echo   [ERROR] pip install failed
    pause
    exit /b 1
)
echo   [OK] Dependencies installed

REM ==================================================================
REM Step 4: Build CICFlowMeter
REM ==================================================================
echo.
echo Step 4: Building CICFlowMeter...
echo.

if not exist CICFlowMeter\gradlew.bat (
    echo   [ERROR] CICFlowMeter\gradlew.bat not found
    pause
    exit /b 1
)

if exist CICFlowMeter\build\classes\java\main (
    echo   [OK] Already built — skipping
    goto :do_interface_test
)

echo   Building with Gradle (this may take a minute)...
pushd CICFlowMeter
call gradlew.bat --no-daemon classes
if errorlevel 1 (
    echo   [ERROR] Gradle build failed
    echo   Try manually: cd CICFlowMeter ^& gradlew.bat classes ^& cd ..
    popd
    pause
    exit /b 1
)
echo   [OK] CICFlowMeter built successfully
popd

:do_interface_test

REM ==================================================================
REM Step 5: Test interface detection
REM ==================================================================
echo.
echo Step 5: Testing network interface detection...
echo.

REM Run the Java interface listing and capture output
set "IFACE_COUNT=0"
set "IFACE_TMPFILE=%TEMP%\nids_iface_test.txt"

pushd CICFlowMeter
call gradlew.bat --no-daemon exeLive "--args=--list-interfaces" > "%IFACE_TMPFILE%" 2>&1
popd

REM Count interface lines (lines starting with digit followed by |)
for /f %%c in ('findstr /r /c:"^[0-9]" "%IFACE_TMPFILE%" ^| find /c "|"') do set IFACE_COUNT=%%c

if %IFACE_COUNT% GTR 0 (
    echo   [OK] Detected %IFACE_COUNT% network interface^(s^):
    echo.
    for /f "tokens=1-4 delims=|" %%a in ('findstr /r /c:"^[0-9]" "%IFACE_TMPFILE%"') do (
        echo         %%a. %%c  ^(%%d^)
    )
    echo.
    del "%IFACE_TMPFILE%" 2>nul
) else (
    echo   [ERROR] No network interfaces detected!
    echo.

    REM Check Npcap
    if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
        echo   Npcap is installed.
    ) else if exist "%SystemRoot%\System32\wpcap.dll" (
        echo   WinPcap/Npcap is installed.
    ) else (
        echo   PROBLEM: Npcap is not installed.
        echo     Fix: Download and install from https://npcap.com
        echo          Check "Install Npcap in WinPcap API-compatible Mode" during install
        echo.
    )

    echo   PROBLEM: You may need to run as Administrator.
    echo     Fix: Right-click the terminal and select "Run as Administrator"
    echo          then re-run this script.
    echo.

    REM Show Java errors if any
    echo   Java output (for debugging):
    findstr /i "error exception denied" "%IFACE_TMPFILE%" 2>nul
    echo.
    del "%IFACE_TMPFILE%" 2>nul

    echo   Fix the issues above, then re-run this script.
    pause
    exit /b 1
)

REM ==================================================================
REM Done
REM ==================================================================
echo ================================================================================
echo   Setup Complete!  Everything is working.  (venv is active)
echo ================================================================================
echo.
echo   Run live classification:
echo       python classification.py --duration 180
echo.
echo   Run ML model pipeline:
echo       python ml_model.py --help
echo.
echo   NOTE: If you open a NEW terminal, activate the venv again first:
echo       venv\Scripts\activate
echo.
echo ================================================================================
echo.

pause
