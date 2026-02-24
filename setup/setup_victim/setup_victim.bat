@echo off
REM ==============================================================================
REM Victim Device Setup - Windows
REM ==============================================================================
REM Run this ON THE TARGET DEVICE (VM or server) to check readiness for attacks.
REM Right-click -> Run as Administrator
REM ==============================================================================

cd /d "%~dp0..\.."

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
if %errorlevel% neq 0 (
    echo   [ERROR] Run as Administrator.
    echo   Right-click setup_victim.bat -^> Run as Administrator
    pause
    exit /b 1
)

echo   [OK] Running as Administrator
echo.

REM Check if venv exists and use it, otherwise use system python
if exist "venv\Scripts\python.exe" (
    echo   Using venv Python...
    call venv\Scripts\activate.bat
    python setup\setup_victim\setup_victim.py
    set exit_code=%errorlevel%
) else (
    echo   Using system Python (venv not found)...
    python setup\setup_victim\setup_victim.py
    set exit_code=%errorlevel%
)

echo.
echo ================================================================================
if %exit_code% equ 0 (
    echo   [OK] Victim setup check complete
) else (
    echo   [!] Some issues were found (see above)
)
echo ================================================================================
echo.

pause
