"""
Verify Python Environment
==========================

Checks that all required packages are installed and importable.

Run from project root with venv activated:
    python setup/verify_environment.py
"""

import sys


def main():
    print("=" * 60)
    print("Python Environment Verification")
    print("=" * 60)
    print(f"\nPython: {sys.version}")
    print(f"Executable: {sys.executable}")

    # Check venv
    in_venv = (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )
    if in_venv:
        print("Virtual env: YES (active)")
    else:
        print("Virtual env: NO — activate it first!")
        print("  Windows: venv\\Scripts\\activate")
        print("  Linux:   source venv/bin/activate")

    print()

    # Check packages
    packages = {
        "pandas": "pandas",
        "numpy": "numpy",
        "scikit-learn": "sklearn",
        "imbalanced-learn": "imblearn",
        "matplotlib": "matplotlib",
        "seaborn": "seaborn",
        "joblib": "joblib",
        "tqdm": "tqdm",
        "pyarrow": "pyarrow",
        "psutil": "psutil",
        "cicflowmeter": "cicflowmeter",
        "scapy": "scapy",
    }

    all_ok = True
    for name, import_name in packages.items():
        try:
            mod = __import__(import_name)
            version = getattr(mod, "__version__", "?")
            print(f"  OK: {name} ({version})")
        except ImportError:
            print(f"  MISSING: {name}")
            all_ok = False

    # Check Npcap/libpcap (needed by Scapy for live capture)
    print()
    import os
    if os.name == "nt":
        npcap_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
        wpcap_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll")
        if os.path.exists(npcap_path) or os.path.exists(wpcap_path):
            print("  Npcap: Found (needed for live capture)")
        else:
            print("  Npcap: NOT FOUND — install from https://npcap.com (needed for live capture)")
    else:
        import shutil
        if shutil.which("tcpdump") or os.path.exists("/usr/lib/x86_64-linux-gnu/libpcap.so"):
            print("  libpcap: Found (needed for live capture)")
        else:
            print("  libpcap: NOT FOUND — install libpcap-dev (needed for live capture)")

    # Summary
    print()
    if all_ok:
        print("ALL PACKAGES INSTALLED — environment is ready.")
    else:
        print("MISSING PACKAGES — run: pip install -r requirements.txt")
    print()


if __name__ == "__main__":
    main()
