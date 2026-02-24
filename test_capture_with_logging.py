#!/usr/bin/env python3
"""
Test flow capture with logging to verify Fwd Seg Size Min correction.
Run attacks while this is capturing, and check if correction messages appear.
"""

import os
import sys
import time
import queue

# Add project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN, COLOR_GREEN, COLOR_RED, COLOR_CYAN
from classification.flowmeter_source import FlowMeterSource

def test_correction():
    print(f"\n{COLOR_CYAN}{'='*70}{COLOR_RESET}")
    print(f"{COLOR_CYAN}Testing Fwd Seg Size Min Correction During Capture{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'='*70}{COLOR_RESET}\n")
    
    # Check config flag
    print(f"Config flag FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN = {FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN}")
    if not FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN:
        print(f"{COLOR_RED}[ERROR] Config flag is False! Correction won't run.{COLOR_RESET}\n")
        return
    
    print(f"{COLOR_GREEN}✅ Config flag is True{COLOR_RESET}\n")
    
    # Create flow queue
    flow_queue = queue.Queue(maxsize=10000)
    
    # Test: Run live capture and watch for [FWD_SEG_FIX] messages
    print(f"Starting capture for 30 seconds...")
    print(f"Generate traffic/attacks now - watch for [FWD_SEG_FIX] correction messages below:\n")
    print("-" * 70)
    
    flowmeter = FlowMeterSource(flow_queue=flow_queue, interface_name="Ethernet")
    flowmeter.start()
    
    start_time = time.time()
    flow_count = 0
    correction_count = 0
    fwd_20_count = 0
    fwd_32_count = 0
    
    try:
        while time.time() - start_time < 30:
            try:
                flow = flow_queue.get(timeout=1)
                flow_count += 1
                
                fwd_seg_min = flow.get("Fwd Seg Size Min")
                if fwd_seg_min == 20:
                    fwd_20_count += 1
                elif fwd_seg_min == 32:
                    fwd_32_count += 1
                
                # Print TCP flows to see Fwd Seg Size Min values
                if flow.get("Protocol") in [6, "6"]:  # TCP
                    print(f"Flow {flow_count}: TCP {flow.get('Src Port')}→{flow.get('Dst Port')} "
                          f"Fwd Seg Size Min={fwd_seg_min}")
                    
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        flowmeter.stop()
    
    print("-" * 70)
    print(f"\n{COLOR_CYAN}RESULTS:{COLOR_RESET}")
    print(f"  Total flows: {flow_count}")
    print(f"  Flows with Fwd Seg Size Min=20: {fwd_20_count}")
    print(f"  Flows with Fwd Seg Size Min=32: {fwd_32_count}")
    
    if fwd_20_count > 0 and fwd_32_count == 0:
        print(f"\n{COLOR_RED}❌ PROBLEM: Flows have Fwd Seg Size Min=20 (not corrected to 32){COLOR_RESET}")
        print(f"  This means the correction code is NOT being applied!")
    elif fwd_32_count > 0:
        print(f"\n{COLOR_GREEN}✅ SUCCESS: Some flows were corrected to Fwd Seg Size Min=32{COLOR_RESET}")
    else:
        print(f"\n{COLOR_RED}❌ No TCP flows captured{COLOR_RESET}")

if __name__ == "__main__":
    test_correction()
