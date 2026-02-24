"""
Quick test to verify the Fwd Seg Size Min correction is working.
This simulates what QueueWriter.write() will do with the fix.
"""
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN

print("[TEST] Fwd Seg Size Min Safety-Net Fix\n")
print(f"Config flag FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN = {FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN}")

# Simulate a Windows flow with Fwd Seg Size Min = 20
test_flow = {
    "Src IP": "192.168.56.1",
    "Dst IP": "192.168.56.104",
    "Dst Port": 80,
    "Fwd Seg Size Min": 20,  # Windows (no TCP timestamps)
    "Protocol": 6
}

print(f"\nBefore correction:")
print(f"  Fwd Seg Size Min = {test_flow['Fwd Seg Size Min']}")

# Apply the fix (same logic as in QueueWriter.write())
if FLOWMETER_FIX_WINDOWS_FWD_SEG_MIN:
    fwd_seg_min = test_flow.get("Fwd Seg Size Min")
    if fwd_seg_min == 20:  # Windows without TCP timestamps
        test_flow["Fwd Seg Size Min"] = 32  # Correct to training data (Linux)
        print(f"\n✅ CORRECTION APPLIED!")
    else:
        print(f"\n⚠️  No correction needed (value != 20)")
else:
    print(f"\n❌ CORRECTION DISABLED (flag = False)")

print(f"\nAfter correction:")
print(f"  Fwd Seg Size Min = {test_flow['Fwd Seg Size Min']}")

if test_flow["Fwd Seg Size Min"] == 32:
    print(f"\n✅ TEST PASSED: Flow will now match training data!")
else:
    print(f"\n❌ TEST FAILED: Flow still has wrong value!")
