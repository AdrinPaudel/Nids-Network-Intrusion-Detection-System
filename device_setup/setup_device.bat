@echo off
REM ==============================================================================
REM Device Attack Setup Check - Windows
REM ==============================================================================
REM Run this ON THE TARGET DEVICE (VM or server) to check readiness for NIDS
REM attack testing. Works on both virtual machines and physical servers.
REM Checks everything, asks before installing/changing anything.
REM
REM Usage:
REM   Right-click setup_device.bat -> Run as Administrator
REM ==============================================================================

echo.
echo ================================================================================
echo   Device Attack Setup Check - Windows
echo ================================================================================
echo   Checks if your device (VM or server) is ready to receive attacks.
echo   Will NOT install or change anything without asking first.
echo ================================================================================
echo.

set "ISSUES=0"

REM ==================================================================
REM Check admin privileges
REM ==================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] This script must be run as Administrator.
    echo.
    echo   Right-click setup_device.bat and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)
echo   [OK] Running as Administrator
echo.

REM ==================================================================
REM Step 1: Show Network Info
REM ==================================================================
echo Step 1: Checking network interfaces...
echo.
echo   [INFO] Recommended network interface setup:
echo     For VMs:     At least 1 Host-Only adapter (attacker-to-target communication)
echo                  + 1 Bridged or NAT adapter (internet access)
echo     For servers: At least 1 NIC with a reachable IP from your attacker machine
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    echo   IP: %%a
)
echo.

REM ==================================================================
REM Step 2: Check SSH Server
REM ==================================================================
echo Step 2: Checking SSH Server (needed for Brute Force attack)...
echo.

sc query sshd >nul 2>&1
if %errorlevel% equ 0 (
    REM SSH is installed, check if running
    sc query sshd | find "RUNNING" >nul 2>&1
    if %errorlevel% equ 0 (
        echo   [OK] OpenSSH Server is installed and running
    ) else (
        echo   [!] OpenSSH Server is installed but NOT running
        echo.
        set /p "STARTSSH=  Do you want to start SSH? [y/n]: "
        if /i "%STARTSSH%"=="y" (
            sc config sshd start= auto >nul 2>&1
            net start sshd >nul 2>&1
            sc query sshd | find "RUNNING" >nul 2>&1
            if %errorlevel% equ 0 (
                echo   [OK] SSH started
            ) else (
                echo   [!] Failed to start SSH
            )
        ) else (
            echo   [SKIP] SSH not started
            echo   To start manually:
            echo     sc config sshd start= auto
            echo     net start sshd
        )
    )
) else (
    echo   [!] OpenSSH Server is NOT installed
    echo       This is needed for the Brute Force attack.
    echo.
    set /p "INSTALLSSH=  Do you want to install OpenSSH Server? [y/n]: "
    if /i "%INSTALLSSH%"=="y" (
        echo   Installing OpenSSH Server...
        powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0" >nul 2>&1
        if %errorlevel% equ 0 (
            echo   [OK] Installed
            echo.
            set /p "STARTSSH2=  Start SSH now? [y/n]: "
            if /i "%STARTSSH2%"=="y" (
                sc config sshd start= auto >nul 2>&1
                net start sshd >nul 2>&1
                echo   [OK] SSH started
            )
        ) else (
            echo   [!] Failed to install
            echo   Install manually:
            echo     Settings ^> Apps ^> Optional Features ^> Add a feature ^> OpenSSH Server
        )
    ) else (
        echo   [SKIP] Not installing SSH
        echo   To install manually:
        echo     Settings ^> Apps ^> Optional Features ^> Add a feature ^> OpenSSH Server
        echo   Then run:
        echo     sc config sshd start= auto
        echo     net start sshd
        set /a ISSUES+=1
    )
)
echo.

REM ==================================================================
REM Step 3: Check Web Server (needed for DoS/DDoS attacks)
REM ==================================================================
echo Step 3: Checking Web Server (needed for DoS and DDoS HTTP attacks)...
echo.

REM Check if IIS is running
sc query W3SVC >nul 2>&1
if %errorlevel% equ 0 (
    sc query W3SVC | find "RUNNING" >nul 2>&1
    if %errorlevel% equ 0 (
        echo   [OK] IIS Web Server is running
    ) else (
        echo   [!] IIS is installed but not running
        echo       Start it: net start W3SVC
    )
) else (
    REM Check if anything is on port 80
    netstat -an | findstr ":80 " | findstr "LISTEN" >nul 2>&1
    if %errorlevel% equ 0 (
        echo   [OK] A web server is listening on port 80
    ) else (
        echo   [!] No web server running on port 80
        echo       DoS/DDoS attacks (Hulk, Slowloris, LOIC, HOIC) need a web server.
        echo.
        echo       Options:
        echo         1. Install IIS: Settings ^> Apps ^> Optional Features ^> IIS
        echo         2. Or run: python -m http.server 80  (simple test server)
        set /a ISSUES+=1
    )
)
echo.

REM ==================================================================
REM Step 4: Check Firewall Rules
REM ==================================================================
echo Step 4: Checking Firewall rules...
echo.

set "FW_MISSING=0"

REM Check SSH rule
netsh advfirewall firewall show rule name="NIDS-SSH" >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] No firewall rule for SSH (port 22)
    set /a FW_MISSING+=1
) else (
    echo   [OK] SSH (port 22) rule exists
)

REM Check FTP rule
netsh advfirewall firewall show rule name="NIDS-FTP" >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] No firewall rule for FTP (port 21)
    set /a FW_MISSING+=1
) else (
    echo   [OK] FTP (port 21) rule exists
)

REM Check ICMP rule
netsh advfirewall firewall show rule name="NIDS-Ping" >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] No firewall rule for Ping (ICMP)
    set /a FW_MISSING+=1
) else (
    echo   [OK] Ping (ICMP) rule exists
)

REM Check common ports
for %%p in (80,443,8080,8443) do (
    netsh advfirewall firewall show rule name="NIDS-Port-%%p" >nul 2>&1
    if errorlevel 1 (
        echo   [!] No firewall rule for port %%p
        set /a FW_MISSING+=1
    ) else (
        echo   [OK] Port %%p rule exists
    )
)

if %FW_MISSING% gtr 0 (
    echo.
    echo   %FW_MISSING% firewall rule(s) missing.
    set /p "ADDFW=  Add missing firewall rules? [y/n]: "
    if /i "%ADDFW%"=="y" (
        netsh advfirewall firewall show rule name="NIDS-SSH" >nul 2>&1
        if errorlevel 1 (
            netsh advfirewall firewall add rule name="NIDS-SSH" dir=in action=allow protocol=tcp localport=22 >nul 2>&1
            echo   [OK] Added: SSH (port 22)
        )
        netsh advfirewall firewall show rule name="NIDS-FTP" >nul 2>&1
        if errorlevel 1 (
            netsh advfirewall firewall add rule name="NIDS-FTP" dir=in action=allow protocol=tcp localport=21 >nul 2>&1
            echo   [OK] Added: FTP (port 21)
        )
        netsh advfirewall firewall show rule name="NIDS-Ping" >nul 2>&1
        if errorlevel 1 (
            netsh advfirewall firewall add rule name="NIDS-Ping" dir=in action=allow protocol=icmpv4 >nul 2>&1
            echo   [OK] Added: Ping (ICMP)
        )
        for %%p in (80,443,8080,8443) do (
            netsh advfirewall firewall show rule name="NIDS-Port-%%p" >nul 2>&1
            if errorlevel 1 (
                netsh advfirewall firewall add rule name="NIDS-Port-%%p" dir=in action=allow protocol=tcp localport=%%p >nul 2>&1
                echo   [OK] Added: port %%p
            )
        )
    ) else (
        echo   [SKIP] Not adding firewall rules
        set /a ISSUES+=1
    )
) else (
    echo   [OK] All firewall rules present
)
echo.

REM ==================================================================
REM Step 5: Check Npcap
REM ==================================================================
echo Step 5: Checking Npcap (needed by NIDS for packet capture)...
echo.

if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo   [OK] Npcap found
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo   [OK] WinPcap/Npcap found
) else (
    echo   [!] Npcap NOT found — NIDS packet capture won't work
    echo       Download from: https://npcap.com
    echo       Check "Install Npcap in WinPcap API-compatible Mode" during install
    set /a ISSUES+=1
)
echo.

REM ==================================================================
REM Step 6: Check NIDS Project
REM ==================================================================
echo Step 6: Checking NIDS project...
echo.

set "NIDS_DIR="
if exist "%USERPROFILE%\Nids\classification.py" (
    set "NIDS_DIR=%USERPROFILE%\Nids"
) else if exist "%USERPROFILE%\Desktop\Nids\classification.py" (
    set "NIDS_DIR=%USERPROFILE%\Desktop\Nids"
)

if defined NIDS_DIR (
    echo   [OK] NIDS project found at: %NIDS_DIR%
    if exist "%NIDS_DIR%\venv" (
        echo   [OK] Virtual environment exists
    ) else (
        echo   [!] No venv — run setup\setup.bat first
        set /a ISSUES+=1
    )
    if exist "%NIDS_DIR%\trained_model\random_forest_model.joblib" (
        echo   [OK] Default model (5-class)
    ) else (
        echo   [!] No default model
        set /a ISSUES+=1
    )
    if exist "%NIDS_DIR%\trained_model_all\random_forest_model.joblib" (
        echo   [OK] All model (6-class)
    ) else (
        echo   [-] No 6-class model (optional)
    )
) else (
    echo   [!] NIDS project not found
    echo       Make sure you cloned it and ran setup\setup.bat
    set /a ISSUES+=1
)
echo.

REM ==================================================================
REM Summary
REM ==================================================================
echo ================================================================================
if %ISSUES% equ 0 (
    echo   ALL CHECKS PASSED - Device is ready for attacks!
) else (
    echo   CHECKS DONE - %ISSUES% issue(s) found (see above)
)
echo ================================================================================
echo.
echo   Your device IP:
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4" ^| findstr /v "127.0.0"') do (
    echo     =^> %%a
)
echo.
echo   Required services for attacks:
echo     Web server (IIS/Apache) - port 80  -^> DoS (Hulk, Slowloris, GoldenEye) + DDoS (LOIC, HOIC)
echo     SSH server              - port 22  -^> Brute Force SSH
echo     FTP server              - port 21  -^> Brute Force FTP (optional)
echo.
echo   To start NIDS:
if defined NIDS_DIR (
    echo     cd %NIDS_DIR%
) else (
    echo     cd Nids
)
echo     venv\Scripts\activate
echo     python classification.py --duration 600
echo.
echo   Then from your attacker machine:
echo     python run_all_attacks.py ^<DEVICE_IP^>
echo.
echo ================================================================================
echo.
pause
