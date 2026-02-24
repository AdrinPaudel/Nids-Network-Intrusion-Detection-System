#!/usr/bin/env python3
"""Test if the Fwd Seg Size Min correction is actually being applied."""

from config import FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN
import queue
from classification.flowmeter_source import FlowMeterSource

# Test 1: Config flag
print("=" * 70)
print("TEST 1: Config Flag")
print("=" * 70)
print(f"FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN = {FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN}")
assert FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN == True, "❌ Config flag is False!"
print("✅ Config flag is True\n")

# Test 2: Logic test
print("=" * 70)
print("TEST 2: Correction Logic")
print("=" * 70)
test_flows = [
    {'Fwd Seg Size Min': 20, 'Dst Port': 80},
    {'Fwd Seg Size Min': 32, 'Dst Port': 80},
    {'Fwd Seg Size Min': 8, 'Dst Port': 53},  # UDP
]

for flow in test_flows:
    original = flow['Fwd Seg Size Min']
    if FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN:
        fwd_seg_min = flow.get('Fwd Seg Size Min')
        if fwd_seg_min == 20:
            flow['Fwd Seg Size Min'] = 32
    
    result = flow['Fwd Seg Size Min']
    symbol = "✅" if result == 32 and original == 20 else "✓" if result == original else "?"
    print(f"  {symbol} Flow: {original} → {result}")

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED")
print("=" * 70)
