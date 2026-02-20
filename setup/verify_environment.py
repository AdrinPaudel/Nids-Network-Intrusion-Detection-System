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

    # Check Java (optional, for live capture)
    print()
    import shutil
    java_path = shutil.which("java")
    if java_path:
        print(f"  Java: Found at {java_path}")
    else:
        print("  Java: NOT FOUND (needed only for live capture)")

    # Summary
    print()
    if all_ok:
        print("ALL PACKAGES INSTALLED — environment is ready.")
    else:
        print("MISSING PACKAGES — run: pip install -r requirements.txt")
    print()


if __name__ == "__main__":
    main()
