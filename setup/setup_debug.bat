REM Debug version of setup - shows what's happening
REM No cd command - runs from wherever you are

setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Project Setup - DEBUG MODE
echo ================================================================================
echo.
echo [DEBUG] Started at: %time%
echo [DEBUG] Current directory: %cd%
echo [DEBUG] Script directory: %~dp0
echo [DEBUG] Project root should be: %~dp0..
echo.
pause

REM ==================================================================
REM Step 1: Check Python
REM ==================================================================
echo Step 1: Checking Python...
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Python not found at all
    echo.
    echo   Try: python --version
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo   [OK] Found Python %PYTHON_VER%
echo.
pause

REM ==================================================================
REM Step 2: Check if we can navigate to project root
REM ==================================================================
echo Step 2: Checking project directory...
echo.

echo   Trying to navigate to: %~dp0..
cd /d "%~dp0.."
if %errorlevel% neq 0 (
    echo   [ERROR] CD failed!
    echo   Current dir: %cd%
    pause
    exit /b 1
)

echo   [OK] Now in: %cd%
echo   Checking for requirements.txt...

if exist requirements.txt (
    echo   [OK] Found requirements.txt
) else (
    echo   [ERROR] requirements.txt not found in %cd%
    dir
    pause
    exit /b 1
)

echo.
pause

echo.
echo ================================================================================
echo [OK] All checks passed! Debug complete.
echo ================================================================================
echo.
pause
