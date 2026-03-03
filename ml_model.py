"""
NIDS CICIDS2018 Project - Main CLI
Command-line interface for running the complete NIDS pipeline
"""

import sys
import os
import argparse

# ============================================================
# VENV CHECK - Verify virtual environment is active
# ============================================================
def check_venv():
    """Check that venv exists and is active; exit with clear instructions if not."""
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
        print("\n  This will create the venv, install dependencies, and build CICFlowMeter.")
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
            print("      python ml_model.py --help\n")
        else:
            print("      source venv/bin/activate")
            print("      python ml_model.py --help\n")
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
        print("      python ml_model.py --help\n")
        print("="*80 + "\n")
        sys.exit(1)


# Check venv early
check_venv()

from ml_model.utils import create_directory_structure, log_message, print_section_header
from ml_model.data_loader import load_data
from ml_model.explorer import explore_data
import config


def run_module_1():
    """Run Module 1: Data Loading"""
    log_message("Starting Module 1: Data Loading", level="INFO")
    df, label_col, protocol_col, stats = load_data()
    return df, label_col, protocol_col, stats


def run_module_2(df, label_col, protocol_col):
    """Run Module 2: Data Exploration"""
    log_message("Starting Module 2: Data Exploration", level="INFO")
    exploration_stats = explore_data(df, label_col, protocol_col)
    return exploration_stats


def run_module_3(df, label_col, protocol_col, use_all_classes=False):
    """Run Module 3: Data Preprocessing
    
    Args:
        use_all_classes (bool): If True, keep Infilteration class (6 classes)
                               If False, remove Infilteration rows (5 classes)
    """
    log_message("Starting Module 3: Data Preprocessing", level="INFO")
    from ml_model.preprocessor import preprocess_data
    preprocessing_result = preprocess_data(
        df, label_col, protocol_col, 
        use_all_classes=use_all_classes
    )
    return preprocessing_result


def run_module_4(use_hypercache=False, use_all_classes=False):
    """Run Module 4: Model Training
    
    Args:
        use_all_classes (bool): If True, load from preprocessed_all variant
                               If False, load from preprocessed variant
    """
    log_message("Starting Module 4: Model Training", level="INFO")
    from ml_model.trainer import train_model
    
    # Get paths based on variant
    paths = config.get_paths(use_all_classes=use_all_classes)
    
    training_results = train_model(
        data_dir=paths['data_preprocessed'],
        model_dir=paths['trained_model'],
        reports_dir=paths['reports_training'],
        n_iter=config.N_ITER_SEARCH,
        cv=config.CV_FOLDS,
        random_state=config.RANDOM_STATE,
        use_hypercache=use_hypercache
    )
    return training_results


def run_module_5(use_all_classes=False):
    """Run Module 5: Model Testing
    
    Args:
        use_all_classes (bool): If True, load from trained_model_all variant
                               If False, load from trained_model variant
    """
    log_message("Starting Module 5: Model Testing", level="INFO")
    from ml_model.tester import test_model
    
    # Get paths based on variant
    paths = config.get_paths(use_all_classes=use_all_classes)
    
    testing_results = test_model(
        model_dir=paths['trained_model'],
        data_dir=paths['data_preprocessed'],
        reports_dir=paths['reports_testing']
    )
    return testing_results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='NIDS CICIDS2018 Project - Network Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run specific module
  python ml_model.py --module 1
  python ml_model.py --module 2
  
  # Run modules 1 and 2
  python ml_model.py --module 1 --module 2
  
  # Run all modules for 6-class variant
  python ml_model.py --module 1 --module 2 --module 3 --module 4 --module 5 --all
  
  # Run module 4 with cached hyperparameters
  python ml_model.py --module 4 --hypercache
        """
    )
    
    parser.add_argument(
        '--module',
        type=int,
        action='append',
        choices=[1, 2, 3, 4, 5],
        help='Run specific module(s). Can be specified multiple times.'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Use ALL classes variant (keep Infilteration, saves to preprocessed_all/trained_model_all). Default: removes Infilteration'
    )
    
    parser.add_argument(
        '--hypercache',
        action='store_true',
        help='Use cached hyperparameters for Module 4 (skip tuning). Use with --module 4'
    )
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if not args.module:
        parser.print_help()
        sys.exit(0)
    
    # Setup directories
    create_directory_structure()
    print()
    
    # Run specific modules
    if args.module:
        modules_to_run = sorted(set(args.module))
        use_all_classes = getattr(args, 'all', False)
        
        # Update config paths based on variant selection
        config.update_variant_paths(use_all_classes=use_all_classes)
        
        variant_name = "5-CLASS (Infilteration removed)" if not use_all_classes else "6-CLASS (with Infilteration)"
        log_message(f"Running variant: {variant_name}", level="INFO")
        print()
        
        df = None
        label_col = None
        protocol_col = None
        exploration_stats = None
        
        for module_num in modules_to_run:
            if module_num == 1:
                df, label_col, protocol_col, load_stats = run_module_1()
            
            elif module_num == 2:
                if df is None:
                    # Check if Module 1 checkpoint exists
                    import os
                    checkpoint_path = config.ML_MODEL_CHECKPOINT
                    
                    if os.path.exists(checkpoint_path):
                        log_message("✓ Module 1 checkpoint found. Loading from checkpoint...", 
                                   level="INFO")
                        from ml_model.data_loader import load_module1_checkpoint
                        df, label_col, protocol_col, load_stats = load_module1_checkpoint()
                    else:
                        log_message("Module 1 checkpoint not found. Running Module 1...", 
                                   level="INFO")
                        df, label_col, protocol_col, load_stats = run_module_1()
                    
                    print()
                
                exploration_stats = run_module_2(df, label_col, protocol_col)
            
            elif module_num == 3:
                if df is None:
                    log_message("Module 3 requires Module 1 data. Loading...", 
                               level="INFO")
                    # Check if Module 1 checkpoint exists first
                    import os
                    checkpoint_path = config.ML_MODEL_CHECKPOINT
                    
                    if os.path.exists(checkpoint_path):
                        log_message("✓ Module 1 checkpoint found. Loading from checkpoint...", 
                                   level="INFO")
                        from ml_model.data_loader import load_module1_checkpoint
                        df, label_col, protocol_col, load_stats = load_module1_checkpoint()
                    else:
                        log_message("Module 1 checkpoint not found. Running Module 1...", 
                                   level="INFO")
                        df, label_col, protocol_col, load_stats = run_module_1()
                    print()
                
                preprocessing_result = run_module_3(df, label_col, protocol_col, use_all_classes=use_all_classes)
            
            elif module_num == 4:
                # Module 4 loads data from preprocessed files
                training_results = run_module_4(use_hypercache=args.hypercache, use_all_classes=use_all_classes)
            
            elif module_num == 5:
                # Module 5 loads trained model and test data from files
                testing_results = run_module_5(use_all_classes=use_all_classes)
        
        print()
        log_message("Requested modules completed!", level="SUCCESS")
        print()


if __name__ == "__main__":
    main()
