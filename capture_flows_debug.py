"""
Temporary Debug Flow Capture
Captures live network flows and saves them to CSV for inspection.
This helps diagnose classification issues by examining actual feature values.

Usage:
  python capture_flows_debug.py --duration 120
  python capture_flows_debug.py --vm --duration 300
"""

import os
import sys
import argparse
import time
import csv
import queue
import threading

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_IDENTIFIER_COLUMNS, CLASSIFICATION_VM_KEYWORDS,
    CLASSIFICATION_WIFI_KEYWORDS, CLASSIFICATION_ETHERNET_KEYWORDS,
    CLASSIFICATION_EXCLUDE_KEYWORDS, COLOR_CYAN, COLOR_GREEN, COLOR_RED,
    COLOR_YELLOW, COLOR_RESET
)
from classification.flowmeter_source import FlowMeterSource

# Create temp folder
TEMP_DIR = os.path.join(PROJECT_ROOT, "temp_flows")
os.makedirs(TEMP_DIR, exist_ok=True)

def select_interface(vm_mode=False, explicit_interface=None):
    """Select network interface for capture."""
    try:
        from scapy.all import get_if_list
        import platform
        
        if platform.system() == "Windows":
            try:
                import winreg
                interfaces = []
                try:
                    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
                    key = winreg.OpenKey(reg, 
                        r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}")
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name + r"\Connection")
                        name = winreg.QueryValueEx(subkey, "Name")[0]
                        interfaces.append((name, subkey_name))
                except Exception:
                    pass
                
                if not interfaces:
                    adapters = get_if_list()
                    interfaces = [(a, a) for a in adapters]
            except Exception:
                adapters = get_if_list()
                interfaces = [(a, a) for a in adapters]
        else:
            adapters = get_if_list()
            interfaces = [(a, a) for a in adapters]
        
        if explicit_interface:
            for name, guid in interfaces:
                if explicit_interface.lower() in name.lower():
                    return name
            print(f"{COLOR_RED}[ERROR] Interface '{explicit_interface}' not found{COLOR_RESET}")
            return None
        
        if vm_mode:
            vm_keywords = [kw.lower() for kw in CLASSIFICATION_VM_KEYWORDS]
            for name, _ in interfaces:
                if any(kw in name.lower() for kw in vm_keywords):
                    return name
        
        print(f"\n{COLOR_CYAN}Available Interfaces:{COLOR_RESET}")
        for i, (name, _) in enumerate(interfaces, 1):
            print(f"  {i}. {name}")
        
        choice = input(f"\n{COLOR_CYAN}Select interface (number): {COLOR_RESET}").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(interfaces):
                return interfaces[idx][0]
        except ValueError:
            pass
        
        return interfaces[0][0] if interfaces else None
    except Exception as e:
        print(f"{COLOR_RED}[ERROR] Interface selection failed: {e}{COLOR_RESET}")
        return None

def save_flows_to_csv(flow_queue, nflows=None, max_time=None):
    """Read flows from queue and save to CSV."""
    csv_path = os.path.join(TEMP_DIR, f"flows_{int(time.time())}.csv")
    
    flows_saved = 0
    start_time = time.time()
    fieldnames = None
    
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = None
            
            while True:
                try:
                    # Check timeouts
                    if max_time and (time.time() - start_time) > max_time:
                        break
                    if nflows and flows_saved >= nflows:
                        break
                    
                    # Get flow with timeout
                    try:
                        flow = flow_queue.get(timeout=1.0)
                    except queue.Empty:
                        continue
                    
                    # Write header on first flow
                    if writer is None:
                        fieldnames = list(flow.keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        print(f"{COLOR_GREEN}[CAPTURE] CSV created: {csv_path}{COLOR_RESET}")
                        print(f"{COLOR_GREEN}[CAPTURE] Columns: {len(fieldnames)}{COLOR_RESET}")
                    
                    # Write flow
                    writer.writerow(flow)
                    flows_saved += 1
                    
                    # Status update every 10 flows
                    if flows_saved % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = flows_saved / elapsed if elapsed > 0 else 0
                        print(f"{COLOR_CYAN}[CAPTURE] {flows_saved} flows ({rate:.1f}/sec){COLOR_RESET}")
                
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"{COLOR_YELLOW}[CAPTURE] Flow write error: {e}{COLOR_RESET}")
        
        print(f"\n{COLOR_GREEN}[CAPTURE] Saved {flows_saved} flows to {csv_path}{COLOR_RESET}")
        return csv_path
    
    except Exception as e:
        print(f"{COLOR_RED}[ERROR] CSV save failed: {e}{COLOR_RESET}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Capture live network flows and save to CSV for inspection"
    )
    parser.add_argument("--interface", help="Explicit interface name (no menu)")
    parser.add_argument("--vm", action="store_true", help="Auto-detect VirtualBox/VMware")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration (seconds)")
    args = parser.parse_args()
    
    print(f"\n{COLOR_CYAN}{'='*70}{COLOR_RESET}")
    print(f"{COLOR_CYAN}Network Flow Capture Debug Tool{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*70}{COLOR_RESET}\n")
    
    # Select interface
    interface = select_interface(vm_mode=args.vm, explicit_interface=args.interface)
    if not interface:
        print(f"{COLOR_RED}[ERROR] Could not select interface{COLOR_RESET}")
        return
    
    print(f"{COLOR_GREEN}[OK] Using interface: {interface}{COLOR_RESET}\n")
    
    # Create flow queue
    flow_queue = queue.Queue(maxsize=10000)
    
    # Start flowmeter capture
    print(f"{COLOR_CYAN}[CAPTURE] Starting live capture for {args.duration}s...{COLOR_RESET}")
    print(f"{COLOR_CYAN}[CAPTURE] Temp folder: {TEMP_DIR}{COLOR_RESET}\n")
    
    # Create and start FlowMeterSource
    flowmeter = FlowMeterSource(flow_queue=flow_queue, interface_name=interface)
    flowmeter.start()
    
    # Save flows (this will run until max_time expires or KeyboardInterrupt)
    csv_path = save_flows_to_csv(flow_queue, max_time=args.duration + 10)
    
    # Stop capture
    flowmeter.stop()
    time.sleep(1)
    
    if csv_path:
        print(f"\n{COLOR_GREEN}[SUCCESS] Flows saved! Analyze with:{COLOR_RESET}")
        print(f"  cd {TEMP_DIR}")
        print(f"  head flows_*.csv")
        print(f"  # Or inspect in Excel/pandas")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}[CAPTURE] Interrupted by user{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}[ERROR] {e}{COLOR_RESET}")
        import traceback
        traceback.print_exc()
