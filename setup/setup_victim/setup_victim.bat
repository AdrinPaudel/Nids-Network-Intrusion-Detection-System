@echo off
REM ==============================================================================
REM Victim Device Setup - Windows (Launcher)
REM ==============================================================================
REM Run this ON THE TARGET DEVICE to check readiness for attacks.
REM Right-click -> Run as Administrator
REM
REM This is a thin launcher. All logic is in setup_victim.py.
REM If this .bat gives trouble, use setup_victim.ps1 instead:
REM   Right-click -> Run with PowerShell (as Admin)
REM ==============================================================================

REM --- Navigate to project root (two levels up from this script) ---
cd /d "%~dp0..\.."
if %errorlevel% neq 0 (
    echo [ERROR] Could not navigate to project root.
    pause
    exit /b 1
)
set "PROJECT_ROOT=%cd%"

REM --- Admin check (works on Win10 + Win11) ---
fsutil dirty query %SystemDrive% >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [ERROR] This script must be run as Administrator.
    echo   Right-click setup_victim.bat and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM --- Find a working Python (venv first, then system) ---
set "PYTHON="

REM Try venv python
if exist "%PROJECT_ROOT%\venv\Scripts\python.exe" (
    set "PYTHON=%PROJECT_ROOT%\venv\Scripts\python.exe"
    goto :found_python
)

REM Try system python
where python >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON=python"
    goto :found_python
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON=python3"
    goto :found_python
)

REM Try common install locations
if exist "C:\Python312\python.exe" (
    set "PYTHON=C:\Python312\python.exe"
    goto :found_python
)
if exist "C:\Python311\python.exe" (
    set "PYTHON=C:\Python311\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    goto :found_python
)
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :found_python
)

echo.
echo   [ERROR] Python not found.
echo   Install Python 3.10+ from https://www.python.org/downloads/
echo   Make sure to check "Add Python to PATH" during install.
echo.
pause
exit /b 1

:found_python
echo   Using Python: %PYTHON%

REM --- Run the setup script ---
"%PYTHON%" "%PROJECT_ROOT%\setup\setup_victim\setup_victim.py"
set "EXIT_CODE=%errorlevel%"

echo.
if %EXIT_CODE% equ 0 (
    echo   [OK] Victim setup check complete.
) else (
    echo   [!] Some issues were found - see above.
)
echo.
pause
