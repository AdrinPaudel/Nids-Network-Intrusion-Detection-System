"""
Shared venv check utility.
Verifies that the virtual environment exists, is activated, and has required packages.
Used by both classification.py and ml_model.py.
"""

import os
import sys


def check_venv(script_name="this script"):
    """
    Check that venv is active and required packages are importable; exit if not.

    Args:
        script_name: Name of the calling script (for error messages).
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    venv_dir = os.path.join(project_root, "venv")
    is_win = sys.platform.startswith('win')

    # 1. Check if venv directory exists at all
    if not os.path.isdir(venv_dir):
        print("\n" + "="*80)
        print("ERROR: Virtual environment not found.")
        print("="*80)
        print("\n  Run the setup script first (it will create everything):\n")
        if is_win:
            print("      setup\\setup.bat")
        else:
            print("      source setup/setup.sh")
        print("\n  This will create the venv and install all dependencies.")
        print("="*80 + "\n")
        sys.exit(1)

    # 2. Check if venv is activated
    in_venv = (
        hasattr(sys, 'real_prefix') or  # virtualenv
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)  # venv
    )
    if not in_venv:
        print("\n" + "="*80)
        print("ERROR: Virtual environment is not activated.")
        print("="*80)
        print("\n  Activate it first, then run again:\n")
        if is_win:
            print("      venv\\Scripts\\activate")
            print(f"      python {script_name}\n")
        else:
            print("      source venv/bin/activate")
            print(f"      python {script_name}\n")
        print("="*80 + "\n")
        sys.exit(1)

    # 3. Check if required packages are installed
    required = ["sklearn", "pandas", "numpy", "joblib"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("\n" + "="*80)
        print("ERROR: Missing required packages: " + ", ".join(missing))
        print("="*80)
        print("\n  venv is active but dependencies are not installed.")
        print("  Run:\n")
        print("      pip install -r requirements.txt")
        print(f"      python {script_name}\n")
        print("="*80 + "\n")
        sys.exit(1)
