"""
Configuration File for NIDS CICIDS2018 Project
All project settings and hyperparameters
"""

import os
import sys

# ============================================================
# PROJECT PATHS
# ============================================================
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_RAW_DIR = os.path.join(PROJECT_ROOT, 'data', 'raw')

# COMBINED: Checkpoint data from Module 1 (shared by both variants)
DATA_COMBINED_DIR = os.path.join(PROJECT_ROOT, 'data', 'combined')

# EXPLORATION: Data and correlation matrices (shared by both variants)
EXPLORATION_CORRELATION_FILE = os.path.join(DATA_COMBINED_DIR, 'exploration_correlation_data.joblib')

# VARIANT 1: Preprocessed (default) - REMOVES Infilteration
DATA_PREPROCESSED_DIR = os.path.join(PROJECT_ROOT, 'data', 'preprocessed')
TRAINED_MODEL_DIR = os.path.join(PROJECT_ROOT, 'trained_model')
RESULTS_DIR = os.path.join(PROJECT_ROOT, 'results')

# VARIANT 2: Preprocessed ALL - KEEPS Infilteration (no removal)
DATA_PREPROCESSED_ALL_DIR = os.path.join(PROJECT_ROOT, 'data', 'preprocessed_all')
TRAINED_MODEL_ALL_DIR = os.path.join(PROJECT_ROOT, 'trained_model_all')

REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')

# ============================================================
# DYNAMIC PATH SELECTION (based on variant)
# ============================================================
def get_paths(use_all_classes=False):
    """
    Get all paths based on variant selection
    Args:
        use_all_classes (bool): If True, use 'preprocessed_all' variant (keeps Infilteration)
                               If False, use 'preprocessed' variant (removes Infilteration)
    Returns:
        dict: Dictionary of all path variables for the selected variant
    """
    if use_all_classes:
        return {
            'data_preprocessed': DATA_PREPROCESSED_ALL_DIR,
            'trained_model': TRAINED_MODEL_ALL_DIR,
            'reports_preprocessing': os.path.join(RESULTS_DIR, 'preprocessing_all'),
            'reports_training': os.path.join(RESULTS_DIR, 'training_all'),
            'reports_testing': os.path.join(RESULTS_DIR, 'testing_all'),
            'remove_infilteration': False,
        }
    else:
        return {
            'data_preprocessed': DATA_PREPROCESSED_DIR,
            'trained_model': TRAINED_MODEL_DIR,
            'reports_preprocessing': os.path.join(RESULTS_DIR, 'preprocessing'),
            'reports_training': os.path.join(RESULTS_DIR, 'training'),
            'reports_testing': os.path.join(RESULTS_DIR, 'testing'),
            'remove_infilteration': True,
        }

# Default variant (keeps Infilteration removed)
PATHS = get_paths(use_all_classes=False)

# Module paths (for imports and orchestration) - DEFAULTS
ML_MODEL_CHECKPOINT = os.path.join(DATA_COMBINED_DIR, 'data_loader_checkpoint.joblib')

# ============================================================
# DYNAMIC PATH UPDATE FUNCTION
# ============================================================
def update_variant_paths(use_all_classes=False):
    """
    Update all variant-specific paths when switching between 5-class and 6-class variants.
    Must be called before running Module 3/4/5 when switching variants.
    
    Args:
        use_all_classes (bool): If True, use 6-class variant (with Infilteration)
                               If False, use 5-class variant (removes Infilteration)
    """
    global PATHS, TRAINED_MODEL_FILE, SCALER_FILE, LABEL_ENCODER_FILE
    global SELECTED_FEATURES_FILE, HYPERPARAMETERS_CACHE_FILE, REMOVE_INFILTERATION
    global REPORTS_EXPLORATION_DIR, REPORTS_PREPROCESSING_DIR, REPORTS_TRAINING_DIR, REPORTS_TESTING_DIR
    
    PATHS = get_paths(use_all_classes=use_all_classes)
    REMOVE_INFILTERATION = PATHS.get('remove_infilteration', True)
    
    # Update all variant-specific paths
    TRAINED_MODEL_FILE = os.path.join(PATHS['trained_model'], 'random_forest_model.joblib')
    SCALER_FILE = os.path.join(PATHS['trained_model'], 'scaler.joblib')
    LABEL_ENCODER_FILE = os.path.join(PATHS['trained_model'], 'label_encoder.joblib')
    SELECTED_FEATURES_FILE = os.path.join(PATHS['trained_model'], 'selected_features.joblib')
    HYPERPARAMETERS_CACHE_FILE = os.path.join(PATHS['trained_model'], 'best_hyperparameters.joblib')
    
    REPORTS_EXPLORATION_DIR = os.path.join(RESULTS_DIR, 'exploration')
    REPORTS_PREPROCESSING_DIR = PATHS['reports_preprocessing']
    REPORTS_TRAINING_DIR = PATHS['reports_training']
    REPORTS_TESTING_DIR = PATHS['reports_testing']

# Initialize with default variant
TRAINED_MODEL_FILE = os.path.join(PATHS['trained_model'], 'random_forest_model.joblib')
SCALER_FILE = os.path.join(PATHS['trained_model'], 'scaler.joblib')
LABEL_ENCODER_FILE = os.path.join(PATHS['trained_model'], 'label_encoder.joblib')
SELECTED_FEATURES_FILE = os.path.join(PATHS['trained_model'], 'selected_features.joblib')
HYPERPARAMETERS_CACHE_FILE = os.path.join(PATHS['trained_model'], 'best_hyperparameters.joblib')

# Report subdirectories - DEFAULTS
REPORTS_EXPLORATION_DIR = os.path.join(RESULTS_DIR, 'exploration')
REPORTS_PREPROCESSING_DIR = PATHS['reports_preprocessing']
REPORTS_TRAINING_DIR = PATHS['reports_training']
REPORTS_TESTING_DIR = PATHS['reports_testing']

# ============================================================
# DATA LOADING SETTINGS
# ============================================================
# Expected label column name variations
LABEL_COLUMN_CANDIDATES = ['Label', 'label', ' Label', 'Label ', 'class', 'Class']
# Expected protocol column name variations (for one-hot encoding)
# Note: Dst Port is NOT encoded - it's a feature, not a categorical variable
PROTOCOL_COLUMN_CANDIDATES = ['Protocol', 'protocol', ' Protocol']

# Data type optimization (DISABLED - data_loader preserves original types)
# OPTIMIZE_DTYPES is not used; data is loaded as-is from CSV files

# ============================================================
# DATA EXPLORATION SETTINGS
# ============================================================
# Correlation analysis
TOP_N_FEATURES_CORRELATION = 30  # Top N features for correlation heatmap (increased for better analysis)
HIGH_CORRELATION_THRESHOLD = 0.9  # Threshold for highly correlated pairs (|r| > 0.9)
CORR_THRESHOLD_STRONG_HIGHLIGHT = 0.95  # Threshold for highlighting strong correlations in visualizations
CORR_THRESHOLD_COMPLETE_REPORT = 0.01  # Report ALL correlations above this threshold

# Visualization settings
FIGURE_DPI = 300  # Resolution for saved figures
FIGURE_FORMAT = 'png'  # Image format

# ============================================================
# DATA PREPROCESSING SETTINGS
# ============================================================

# Columns to drop during preprocessing (identifiers, not features)
PREPROCESSING_DROP_COLUMNS = ['Flow ID', 'Src IP', 'Dst IP', 'Src Port', 'Timestamp']

# Control Flag: Remove Infilteration rows
# Set in PATHS dict via get_paths() function
# If True: Rows with Label == 'Infilteration' will be dropped (6 → 5 classes)
# If False: Infilteration rows kept (6 classes total)
REMOVE_INFILTERATION = PATHS.get('remove_infilteration', True)

# Label Consolidation Mapping
# NOTE: Final class count depends on variant:
#   • Variant 1 (default): 5 classes - Infilteration REMOVED
#     Classes: Benign, Botnet, Brute Force, DDoS, DoS (0-4)
#   • Variant 2 (all): 6 classes - Infilteration KEPT  
#     Classes: Benign, Botnet, Brute Force, DDoS, DoS, Infilteration (0-5)
#
# Classes mapped to __DROP__ (SQL Injection, Heartbleed) are filtered OUT in clean_data()
# BEFORE consolidation, so they never become actual target classes.
LABEL_MAPPING = {
    # Benign
    'Benign': 'Benign',
    'BENIGN': 'Benign',
    
    # DDoS variants → DDoS
    'DDoS attacks-LOIC-HTTP': 'DDoS',
    'DDoS attacks-LOIC-UDP': 'DDoS',
    'DDOS attack-LOIC-UDP': 'DDoS',
    'DDOS attack-HOIC': 'DDoS',
    'DDoS attacks-HOIC': 'DDoS',
    
    # DoS variants → DoS
    'DoS attacks-Hulk': 'DoS',
    'DoS attacks-SlowHTTPTest': 'DoS',
    'DoS attacks-GoldenEye': 'DoS',
    'DoS attacks-Slowloris': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS Hulk': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'DoS slowloris': 'DoS',
    
    # Brute Force variants → Brute Force (including SSH, FTP, Web, XSS)
    'FTP-BruteForce': 'Brute Force',
    'FTP-Patator': 'Brute Force',
    'SSH-Bruteforce': 'Brute Force',
    'SSH-Patator': 'Brute Force',
    'Brute Force -Web': 'Brute Force',
    'Brute Force -XSS': 'Brute Force',
    
    # Botnet
    'Bot': 'Botnet',
    'Botnet': 'Botnet',
    
    # Infilteration (keep original name as user requested)
    'Infilteration': 'Infilteration',
    'Infiltration': 'Infilteration',
    
    # SQL Injection → DROP (will be filtered out)
    'SQL Injection': '__DROP__',
    
    # Heartbleed (if present)
    'Heartbleed': '__DROP__',
}

# Train-test split
TEST_SIZE = 0.20  # 80:20 split
RANDOM_STATE = 42  # For reproducibility
STRATIFY = True  # Maintain class proportions in split

# Feature Scaling
SCALER_TYPE = 'standard'  # 'standard' or 'minmax'

# SMOTE (Synthetic Minority Over-sampling)
APPLY_SMOTE = True  # Enabled for class balancing
SMOTE_K_NEIGHBORS = 5
# SMOTE_STRATEGY options:
#   'dynamic' (RECOMMENDED) - Automatically calculates targets relative to 2nd largest class
#      Formula: target = current + (2nd_largest - current) / 2
#      Brings each minority class halfway to the 2nd largest class (adaptive)
#   'tiered' - Uses fixed percentages from SMOTE_TIERED_TARGETS dictionary below
#   'uniform' - Brings all minorities to same percentage (SMOTE_TARGET_PERCENTAGE)
SMOTE_STRATEGY = 'dynamic'  # Changed from 'tiered' to 'dynamic' for adaptive balancing

# Tiered targets (ONLY used if SMOTE_STRATEGY='tiered')
# NOTE: With 'dynamic' strategy (recommended), these are IGNORED
# If using 'tiered', adjust class indices based on your variant:
# Variant 1 (5 classes, 0-4): 0=Benign, 1=Botnet, 2=Brute Force, 3=DDoS, 4=DoS
# Variant 2 (6 classes, 0-5): 0=Benign, 1=Botnet, 2=Brute Force, 3=DDoS, 4=DoS, 5=Infilteration
SMOTE_TIERED_TARGETS = {
    # Format: class_index: target_percentage_of_train_set
    # Index 0: Benign (83.07%) - no SMOTE needed (majority class)
    # Index 1: Botnet (1.76%) - needs oversampling
    1: 0.015,  # Botnet → 1.5%
    # Index 2: Brute Force (2.35%) - needs oversampling
    2: 0.020,  # Brute Force → 2.0%
    # Index 3: DDoS (7.79%) - likely no SMOTE needed (reasonable size)
    # Index 4: DoS (4.03%) - likely no SMOTE needed
    # Index 5: Infilteration (1.00%) - minority, likely needs oversampling
    5: 0.015,  # Infilteration → 1.5%
}
SMOTE_TARGET_PERCENTAGE = 0.03  # Fallback for uniform strategy

# Feature Selection (RF Importance Method)
ENABLE_RF_IMPORTANCE = True  # ✓ ENABLED - Fast RF Gini importance for feature selection
RF_IMPORTANCE_TREES = 100  # Trees for importance calculation (balance speed/stability)
RF_IMPORTANCE_MAX_DEPTH = 15  # Max depth for importance RF
TARGET_FEATURES_MIN = 40  # Minimum features to keep
TARGET_FEATURES_MAX = 45  # Maximum features to keep
IMPORTANCE_THRESHOLD = 0.005  # Keep features above this importance
RF_IMPORTANCE_SUBSET_THRESHOLD = 5_000_000  # Use subset if dataset > this size
RF_IMPORTANCE_SUBSET_SIZE = 2_000_000  # Subset size for large datasets (balance speed/quality)

# ============================================================
# MODEL TRAINING SETTINGS
# ============================================================

# Hyperparameter Tuning (RandomizedSearchCV)
HYPERPARAMETER_TUNING = True
N_ITER_SEARCH = 15  # 15 iterations × 3 folds = 45 total fits
CV_FOLDS = 3  # Cross-validation folds (3 for memory efficiency)
TUNING_SAMPLE_FRACTION = 0.2  # Sample 20% of training data for tuning to reduce peak RAM
TUNING_SCORING = 'f1_macro'  # Optimization metric

# Memory Management during Training
GARBAGE_COLLECTION_INTERVAL = 5  # Run gc.collect() every N iterations
ENABLE_MEMORY_OPTIMIZATION = True  # Enable periodic memory cleanup

# Random Forest Hyperparameter Search Space (FAST MODE)
PARAM_DISTRIBUTIONS = {
    'n_estimators': [100, 150],  # FAST: Only 2 options
    'max_depth': [20, 25, 30],  # FAST: Focused mid-range
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'max_features': ['sqrt', 'log2'],  # Removed None
    'bootstrap': [True],  # FAST: Only True (faster subsampling)
    'class_weight': ['balanced_subsample', None]  # FAST: Removed 'balanced'
}

# Default hyperparameters (if tuning is skipped)
DEFAULT_RF_PARAMS = {
    'n_estimators': 100,
    'max_depth': 25,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'max_features': 'sqrt',
    'bootstrap': True,
    'class_weight': 'balanced_subsample',
    'random_state': RANDOM_STATE,
    'n_jobs': -1,  # Use all CPU cores
    'verbose': 1
}

# ============================================================
# MODEL TESTING SETTINGS
# ============================================================

# Evaluation metrics
CLASSIFICATION_REPORT_DIGITS = 4  # Decimal places in classification report
CONFUSION_MATRIX_NORMALIZE = None  # None, 'true', 'pred', 'all'

# ROC Curve settings
ROC_MICRO_AVERAGE = True
ROC_MACRO_AVERAGE = True

# ============================================================
# SYSTEM SETTINGS - CPU & RAM RESOURCE MANAGEMENT
# ============================================================

# Auto-detect system resources at runtime (works across VMs, containers, bare metal)
SYSTEM_CPU_COUNT = os.cpu_count() or 4  # Fallback to 4 if detection fails

def _detect_ram_gb():
    """Detect total system RAM in GB. Works on Linux, Windows, and macOS."""
    # Linux: read from /proc/meminfo (most reliable in VMs)
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    return int(line.split()[1]) / (1024 ** 2)  # kB → GB
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    # Windows: use ctypes to call GlobalMemoryStatusEx
    if sys.platform.startswith('win'):
        try:
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            mem = MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)):
                return mem.ullTotalPhys / (1024 ** 3)  # bytes → GB
        except (AttributeError, OSError, ValueError):
            pass

    # macOS: use sysctl
    try:
        import subprocess as _sp
        result = _sp.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return int(result.stdout.strip()) / (1024 ** 3)  # bytes → GB
    except (FileNotFoundError, ValueError, OSError):
        pass

    return 8.0  # Fallback if all detection methods fail

SYSTEM_RAM_GB = _detect_ram_gb()

# Parallel processing - use -1 to utilize all available cores
N_JOBS = -1  # Use all CPUs for all parallel operations

# Memory settings (auto-adjusted based on detected RAM)
LOW_MEMORY = SYSTEM_RAM_GB < 32       # Enable memory optimization if < 32GB RAM
RF_MAX_SAMPLES = 0.5                  # Bootstrap sample cap at 50% for stability

# Logging
VERBOSE = True  # Detailed console output
LOG_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'

# Backend API settings
BACKEND_HOST = '0.0.0.0'
BACKEND_PORT = 8000
BACKEND_WORKERS = max(2, SYSTEM_CPU_COUNT // 2)  # Half of detected CPUs, minimum 2

# ============================================================
# FEATURE CORRELATION ELIMINATION
# ============================================================
CORR_ELIMINATION_THRESHOLD = 0.99  # Remove features with |r| >= 0.99 (perfect/near-perfect)
APPLY_CORRELATION_ELIMINATION = True  # Enable/disable correlation-based feature removal

# ============================================================
# EXPECTED PERFORMANCE TARGETS
# ============================================================
TARGET_MACRO_F1_SCORE = 0.96  # >96%
TARGET_ACCURACY = 0.99  # >99%
TARGET_INFILTRATION_F1 = 0.89  # >89% for hardest class
# ============================================================
# CLASSIFICATION (LIVE DETECTION) SETTINGS
# ============================================================

# Python CICFlowMeter (Scapy-based flow capture) settings
# These control how quickly flows are emitted for classification.
# Matching the original Java CICFlowMeter's real-time behavior.
FLOWMETER_IDLE_THRESHOLD = 15       # Emit flow after N seconds of no new packets
FLOWMETER_AGE_THRESHOLD = 30        # Emit flow after N seconds total duration
FLOWMETER_GC_INTERVAL = 10.0        # Background garbage collection frequency (seconds)

# Default classification parameters
CLASSIFICATION_DEFAULT_DURATION = 120        # 2 minutes (seconds)
CLASSIFICATION_DEFAULT_MODEL = "default"     # "default" (5-class) or "all" (6-class)

# Queue configuration
CLASSIFICATION_QUEUE_MAXSIZE = 10000         # Max items in inter-thread queues
CLASSIFICATION_QUEUE_TIMEOUT = 0.5           # Queue get timeout for live mode (seconds)
CLASSIFICATION_BATCH_QUEUE_TIMEOUT = 0.001   # Queue get timeout for batch mode (seconds) - 1ms for batch speed

# Preprocessing settings
CLASSIFICATION_DROP_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Timestamp", "Label"]
CLASSIFICATION_BATCH_SIZE = 1                # Flows to batch before processing
CLASSIFICATION_BATCH_TIMEOUT = 0.5           # Max seconds to wait for full batch

# Threat assessment settings
CLASSIFICATION_BENIGN_CLASS = "Benign"       # Benign class name
CLASSIFICATION_SUSPICIOUS_THRESHOLD = 0.25   # Confidence threshold for 2nd-highest (YELLOW alert)

# CICFlowMeter source settings
CLASSIFICATION_IDENTIFIER_COLUMNS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp"]
CLASSIFICATION_SUBPROCESS_TIMEOUT_LIST = 30  # Timeout for listing interfaces
CLASSIFICATION_SUBPROCESS_TIMEOUT_MAIN = 45  # Timeout for main process wait (Java needs time to dump remaining flows)
CLASSIFICATION_SUBPROCESS_TIMEOUT_FORCE = 10  # Timeout for forced termination
CLASSIFICATION_SUBPROCESS_TIMEOUT_JOIN = 30  # Timeout for reader thread join (flows trickle in after STOP)

# WiFi interface detection settings
# Windows: matched against interface description (e.g. "Intel(R) Wi-Fi 6 AX201")
# Linux:   matched against interface name (e.g. "wlan0", "wlp2s0") since descriptions are unavailable
CLASSIFICATION_WIFI_KEYWORDS = ["wi-fi", "wifi", "wireless", "wlan", "wlp"]
CLASSIFICATION_ETHERNET_KEYWORDS = ["ethernet", "eth", "enp", "ens", "eno"]
CLASSIFICATION_EXCLUDE_KEYWORDS = ["virtual", "direct", "bluetooth", "loopback", "miniport", "virtualbox",
                                    "docker", "virbr", "br-", "veth", "lo"]

# Periodic status updates
CLASSIFICATION_STATUS_UPDATE_INTERVAL = 30   # Print status every N seconds

# Report generation settings
CLASSIFICATION_REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

# Color codes for terminal output (ANSI escape codes)
COLOR_CYAN = "\033[96m"
COLOR_CYAN_BOLD = "\033[96;1m"
COLOR_RED = "\033[91m"
COLOR_RED_BOLD = "\033[91;1m"
COLOR_YELLOW = "\033[93m"
COLOR_YELLOW_BOLD = "\033[93;1m"
COLOR_GREEN = "\033[92m"
COLOR_BLUE = "\033[94m"
COLOR_DARK_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"

# ============================================================
# CLASSIFICATION - OUTPUT FORMATTING SETTINGS
# ============================================================

# Terminal output widths
CLASSIFICATION_THREAT_DISPLAY_WIDTH = 80          # Width for threat alerts (RED/YELLOW displays)
CLASSIFICATION_REPORT_TABLE_WIDTH = 160           # Width for report table rows

# Report table column definitions (name, width)
CLASSIFICATION_REPORT_TABLE_COLUMNS = [
    ("Timestamp", 19),
    ("Src IP", 18),
    ("Src Port", 8),
    ("Dst IP", 18),
    ("Dst Port", 8),
    ("Protocol", 8),
    ("Class 1", 14),
    ("Conf 1", 8),
    ("Class 2", 14),
    ("Conf 2", 8),
    ("Class 3", 14),
    ("Conf 3", 8),
]

# Progress reporting intervals
CLASSIFICATION_BATCH_PROGRESS_INTERVAL = 100     # Print progress every N flows processed
CLASSIFICATION_REPORT_FLUSH_INTERVAL = 10        # Flush report file every N items

# Timestamp format for classifications
CLASSIFICATION_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
CLASSIFICATION_MINUTE_KEY_FORMAT = "%H-%M"      # Format for minute file naming

# Batch source settings - organized by model variant
CLASSIFICATION_BATCH_DEFAULT_DIR = os.path.join(PROJECT_ROOT, "data", "default", "batch")
CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR = os.path.join(PROJECT_ROOT, "data", "default", "batch_labeled")
CLASSIFICATION_BATCH_ALL_DIR = os.path.join(PROJECT_ROOT, "data", "all", "batch")
CLASSIFICATION_BATCH_ALL_LABELED_DIR = os.path.join(PROJECT_ROOT, "data", "all", "batch_labeled")

# Backward compatibility aliases
CLASSIFICATION_BATCH_DIR = CLASSIFICATION_BATCH_DEFAULT_DIR
CLASSIFICATION_BATCH_LABELED_DIR = CLASSIFICATION_BATCH_DEFAULT_LABELED_DIR
CLASSIFICATION_LABEL_COLUMN = "Label"  # Column name for actual labels in labeled batches

# Session folder naming format
CLASSIFICATION_SESSION_FOLDER_FORMAT = "{mode}_{model}_{timestamp}"  # Used by report generator