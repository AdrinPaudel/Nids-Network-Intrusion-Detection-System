#!/usr/bin/env python
"""
Dependency installer for NIDS attack scripts.
Checks and installs required Python packages.
"""

import subprocess
import sys


REQUIRED_PACKAGES = {
    "scapy": {
        "import_name": "scapy",
        "pip_name": "scapy",
        "used_by": "UDP flood (2_ddos_simulation.py)",
    },
    "paramiko": {
        "import_name": "paramiko",
        "pip_name": "paramiko",
        "used_by": "SSH brute force (3_brute_force_ssh.py)",
    },
    "requests": {
        "import_name": "requests",
        "pip_name": "requests",
        "used_by": "HTTP-based attacks (optional, for convenience)",
    },
}


def check_package(import_name):
    """Check if a package is importable"""
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def install_package(pip_name):
    """Install a package using pip"""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pip_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def main():
    print("=" * 60)
    print("NIDS Attack Scripts - Dependency Installer")
    print("=" * 60)
    print()

    missing = []
    installed = []

    for name, info in REQUIRED_PACKAGES.items():
        status = check_package(info["import_name"])
        if status:
            print(f"  [OK]      {name:12s}  (used by: {info['used_by']})")
            installed.append(name)
        else:
            print(f"  [MISSING] {name:12s}  (used by: {info['used_by']})")
            missing.append(name)

    print()

    if not missing:
        print("[+] All dependencies are already installed!")
        print()
        return

    print(f"[!] {len(missing)} package(s) need to be installed: {', '.join(missing)}")
    response = input("\nInstall missing packages now? (y/n): ").strip().lower()

    if response != "y":
        print("[!] Skipping installation. Some attack scripts may not work.")
        return

    print()
    for name in missing:
        info = REQUIRED_PACKAGES[name]
        print(f"  Installing {name}...", end=" ", flush=True)
        if install_package(info["pip_name"]):
            print("OK")
        else:
            print("FAILED")
            print(f"    Try manually: pip install {info['pip_name']}")

    print()
    print("[+] Done! Re-checking packages...")
    print()

    all_ok = True
    for name, info in REQUIRED_PACKAGES.items():
        status = check_package(info["import_name"])
        symbol = "OK" if status else "MISSING"
        print(f"  [{symbol:7s}] {name}")
        if not status:
            all_ok = False

    print()
    if all_ok:
        print("[+] All dependencies ready! You can now run the attack scripts.")
    else:
        print("[!] Some packages are still missing. Try installing them manually.")


if __name__ == "__main__":
    main()
