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

REM --- Check and setup SSH (Windows built-in or standalone) ---
echo.
echo   Checking SSH server...

REM Try to query OpenSSH service
sc query sshd >nul 2>&1
if %errorlevel% equ 0 (
    echo   [OK] OpenSSH service found.
) else (
    echo   [!] OpenSSH not installed. Attempting to enable Windows built-in OpenSSH...
    
    REM Try to add Windows built-in OpenSSH (Win10 1809+ and Win11)
    powershell -NoProfile -Command "Get-WindowsCapability -Online | Where-Object {$_.Name -like 'OpenSSH.Server*'} | Add-WindowsCapability -Online" >nul 2>&1
    
    timeout /t 2 /nobreak >nul 2>&1
    
    sc query sshd >nul 2>&1
    if %errorlevel% neq 0 (
        echo   [!] Windows built-in OpenSSH unavailable. Will download standalone version...
    ) else (
        echo   [OK] Windows built-in OpenSSH enabled successfully.
    )
)

REM --- Find and activate Python venv, or use system Python ---
set "VENV_ACTIVATE=%PROJECT_ROOT%\venv\Scripts\activate.bat"

if exist "%VENV_ACTIVATE%" (
    echo   Using venv Python
    call "%VENV_ACTIVATE%"
) else (
    echo   Venv not found, using system Python
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo.
        echo   [ERROR] Python not found.
        echo   Install Python 3.10+ from https://www.python.org/downloads/
        echo.
        pause
        exit /b 1
    )
)

REM --- Run the setup script ---
python "%PROJECT_ROOT%\setup\setup_victim\setup_victim.py"
