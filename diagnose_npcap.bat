@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================================================
echo NIDS Network Diagnostics - Windows
echo ================================================================================
echo.

REM Check 1: Npcap/WinPcap DLLs
echo [1] Checking Npcap/WinPcap installation...
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo     OK - Npcap found at: %SystemRoot%\System32\Npcap\wpcap.dll
) else if exist "%SystemRoot%\System32\wpcap.dll" (
    echo     OK - WinPcap found at: %SystemRoot%\System32\wpcap.dll
) else (
    echo     ERROR - Npcap/WinPcap NOT installed
    echo     Download from: https://npcap.com/
    pause
    exit /b 1
)
echo.

REM Check 2: NPF Service
echo [2] Checking NPF (Npcap) service...
net start | findstr /i "NPF" >nul
if %errorlevel% equ 0 (
    echo     OK - NPF service is running
) else (
    echo     WARNING - NPF service not running
    echo     Attempting to start...
    net start NPF
    if %errorlevel% neq 0 (
        echo     ERROR - Failed to start NPF service
        echo     Try: net start NPF
        echo     Or restart your computer
        pause
        exit /b 1
    )
    echo     OK - NPF service started
)
echo.

REM Check 3: Available adapters
echo [3] Listing network adapters...
python -c "
import scapy.all as scapy
from scapy.arch import get_windows_if_list

adapters = get_windows_if_list()
if not adapters:
    print('    ERROR - No adapters found')
    exit(1)

print(f'    Found {len(adapters)} adapter(s):')
for i, adapter in enumerate(adapters, 1):
    try:
        name = adapter.get('name', 'Unknown')
        description = adapter.get('description', 'No description')
        ipaddr = adapter.get('ipaddr', 'No IP')
        print(f'      {i}. {name}')
        print(f'         Description: {description}')
        print(f'         IP: {ipaddr}')
    except Exception as e:
        print(f'      {i}. {adapter}')
" 2>nul
if %errorlevel% neq 0 (
    echo     ERROR - Could not list adapters (Scapy issue)
)
echo.

REM Check 4: Try to capture packets
echo [4] Testing packet capture (5 second timeout)...
python -c "
import scapy.all as scapy
from scapy.arch import get_windows_if_list
import time

adapters = get_windows_if_list()
if not adapters:
    print('    ERROR - No adapters available')
    exit(1)

best_adapter = None
for adapter in adapters:
    try:
        name = adapter.get('name')
        if name and adapter.get('ipaddr'):
            best_adapter = name
            break
    except:
        pass

if not best_adapter:
    best_adapter = adapters[0].get('name') if adapters else None

if not best_adapter:
    print('    ERROR - Could not select adapter')
    exit(1)

print(f'    Attempting capture on: {best_adapter}')
try:
    packets = scapy.sniff(iface=best_adapter, timeout=5, prn=lambda x: None)
    count = len(packets)
    if count > 0:
        print(f'    OK - Captured {count} packet(s)')
    else:
        print(f'    WARNING - Captured 0 packets (no active traffic on this adapter?)')
        print(f'    Try selecting a different adapter or check network activity')
except PermissionError:
    print('    ERROR - Permission denied (need admin privileges)')
except Exception as e:
    print(f'    ERROR - {type(e).__name__}: {str(e)}')
" 2>nul
echo.

echo ================================================================================
echo Diagnostics Complete
echo ================================================================================
echo.
echo If you see warnings/errors:
echo   - NPF not running: Run 'net start NPF' in admin command prompt
echo   - No adapters found: Reinstall Npcap from https://npcap.com/
echo   - 0 packets captured: Different adapter may have traffic, try another one
echo.
pause
