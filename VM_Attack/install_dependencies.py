#!/usr/bin/env python
"""
Install Attack Dependencies
Only installs what's NOT already in the main NIDS requirements.txt

Already installed (via NIDS setup):
  - scapy (comes with cicflowmeter)

Only new package needed:
  - paramiko (for SSH brute force attack)
"""

import subprocess
import sys
import importlib

def check_and_install():
    print(f"\n{'='*60}")
    print(f"  Attack Dependencies Check")
    print(f"{'='*60}\n")

    # Check scapy (should already exist from cicflowmeter)
    try:
        importlib.import_module("scapy")
        print(f"  scapy      ✓ Already installed (from cicflowmeter)")
    except ImportError:
        print(f"  scapy      ✗ Missing — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "scapy"])
        print(f"  scapy      ✓ Installed")

    # Check paramiko (NEW - needed for SSH brute force)
    try:
        importlib.import_module("paramiko")
        print(f"  paramiko   ✓ Already installed")
    except ImportError:
        print(f"  paramiko   ✗ Missing — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "paramiko"])
        print(f"  paramiko   ✓ Installed")

    print(f"\n{'='*60}")
    print(f"  ✓ Ready! You can now run attacks.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    check_and_install()
