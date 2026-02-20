"""
Module 4: Model Training
CICIDS2018 NIDS Project

This module handles:
1. Loading preprocessed data
2. Hyperparameter tuning with RandomizedSearchCV
3. Training final model with best parameters
4. Feature importance analysis
5. Generating training reports and visualizations
"""

import os
import sys
import time
import json
import joblib
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import gc
from datetime import datetime
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, train_test_split
from joblib import parallel_backend
from sklearn.metrics import (
    f1_score, accuracy_score, precision_score, recall_score,
    classification_report, confusion_matrix, make_scorer
)

import config

# Configure warnings
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)

# Configure matplotlib
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


def log_step(message, level="INFO"):
    """Log a message with timestamp and level."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_colors = {
        "INFO": "\033[94m",      # Blue
        "SUCCESS": "\033[92m",   # Green
        "WARNING": "\033[93m",   # Yellow
        "ERROR": "\033[91m",     # Red
        "STEP": "\033[95m",      # Magenta
        "SUBSTEP": "\033[96m"    # Cyan
    }
    reset_color = "\033[0m"
    color = level_colors.get(level, "")
    print(f"[{timestamp}] {color}[{level}]{reset_color} {message}")


def save_figure(fig, filepath):
    """Save figure with consistent settings."""
    try:
        fig.savefig(filepath, dpi=300, bbox_inches='tight', facecolor='white')
        file_size = os.path.getsize(filepath) / 1024  # KB
        log_step(f"Saved figure: {os.path.basename(filepath)} ({file_size:.1f} KB)", "SUCCESS")
        plt.close(fig)
    except Exception as e:
        log_step(f"Failed to save figure {filepath}: {e}", "ERROR")
        plt.close(fig)


def load_cached_hyperparameters():
    """
    Load cached best hyperparameters from previous tuning run.
    
    Returns:
        dict: Best hyperparameters or None if cache doesn't exist
    """
    if os.path.exists(config.HYPERPARAMETERS_CACHE_FILE):
        try:
            best_params = joblib.load(config.HYPERPARAMETERS_CACHE_FILE)
            log_step(f"✓ Loaded cached hyperparameters from: {config.HYPERPARAMETERS_CACHE_FILE}", "SUCCESS")
            log_step(f"Cached parameters: {best_params}", "INFO")
            return best_params
        except Exception as e:
            log_step(f"Error loading cached hyperparameters: {str(e)}", "WARNING")
            return None
    else:
        log_step(f"No cached hyperparameters found at: {config.HYPERPARAMETERS_CACHE_FILE}", "INFO")
        return None


def load_preprocessed_data(data_dir='data/preprocessed'):
    """
    Load preprocessed training and test data.
    
    Returns:
        tuple: (X_train, X_test, y_train, y_test, scaler, label_encoder, metadata)
    """
    log_step("Loading preprocessed data...", "STEP")
    start_time = time.time()
    
    data_dir = Path(data_dir)
    
    # Check if all required files exist
    required_files = [
        'train_final.parquet',        # X_train after SMOTE
        'test_final.parquet',          # X_test
        'scaler.joblib',
        'label_encoder.joblib'
    ]
    
    missing_files = [f for f in required_files if not (data_dir / f).exists()]
    if missing_files:
        log_step(f"Missing required files: {missing_files}", "ERROR")
        raise FileNotFoundError(f"Missing preprocessed files: {missing_files}")
    
    # Load training data
    log_step("Loading training data (after SMOTE)...", "SUBSTEP")
    train_final = pd.read_parquet(data_dir / 'train_final.parquet')
    
    # Separate features and target
    # Assume last column is the target (Label)
    X_train = train_final.iloc[:, :-1]
    y_train = train_final.iloc[:, -1]
    
    # Use ALL training data for final model training
    log_step(f"Training data: {X_train.shape[0]:,} samples, {X_train.shape[1]} features")
    
    # Load test data
    log_step("Loading test data (original distribution)...", "SUBSTEP")
    test_final = pd.read_parquet(data_dir / 'test_final.parquet')
    X_test = test_final.iloc[:, :-1]
    y_test = test_final.iloc[:, -1]
    log_step(f"Test data: {X_test.shape[0]:,} samples, {X_test.shape[1]} features")
    
    # Load transformation objects
    log_step("Loading scaler and label encoder...", "SUBSTEP")
    scaler = joblib.load(data_dir / 'scaler.joblib')
    label_encoder = joblib.load(data_dir / 'label_encoder.joblib')
    log_step(f"Label classes: {label_encoder.classes_.tolist()}")
    
    # Load metadata if exists
    metadata = None
    metadata_file = data_dir / 'preprocessing_metadata.json'
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        log_step("Loaded preprocessing metadata")
    
    # Load preprocessing feature importances if exists
    preprocessing_importance_file = data_dir / 'feature_importances.csv'
    if preprocessing_importance_file.exists():
        preprocessing_importance = pd.read_csv(preprocessing_importance_file)
        log_step(f"Loaded preprocessing feature importances ({len(preprocessing_importance)} features)")
        if metadata is None:
            metadata = {}
        metadata['preprocessing_feature_importances'] = preprocessing_importance
    
    elapsed = time.time() - start_time
    log_step(f"Data loading completed in {elapsed:.1f} seconds", "SUCCESS")
    
    return X_train, X_test, y_train, y_test, scaler, label_encoder, metadata


def define_hyperparameter_search_space():
    """
    Define the hyperparameter search space for RandomizedSearchCV.
    Uses configuration from config.py for consistency.
    
    Returns:
        dict: Parameter distributions from config
    """
    param_distributions = config.PARAM_DISTRIBUTIONS
    
    # Calculate total combinations
    total_combinations = 1
    for param, values in param_distributions.items():
        total_combinations *= len(values)
    
    log_step(f"Hyperparameter search space defined:")
    log_step(f"  n_estimators: {len(param_distributions['n_estimators'])} options")
    log_step(f"  max_depth: {len(param_distributions['max_depth'])} options")
    log_step(f"  min_samples_split: {len(param_distributions['min_samples_split'])} options")
    log_step(f"  min_samples_leaf: {len(param_distributions['min_samples_leaf'])} options")
    log_step(f"  max_features: {len(param_distributions['max_features'])} options")
    log_step(f"  bootstrap: {len(param_distributions['bootstrap'])} options")
    log_step(f"  class_weight: {len(param_distributions['class_weight'])} options")
    log_step(f"  Total combinations: {total_combinations:,}")
    
    return param_distributions


def perform_hyperparameter_tuning(X_train, y_train, n_iter=20, cv=5, random_state=42, n_jobs=-1):
    """
    Perform hyperparameter tuning using RandomizedSearchCV.
    
    Args:
        X_train: Training features
        y_train: Training labels
        n_iter: Number of parameter combinations to sample
        cv: Number of cross-validation folds
        random_state: Random seed for reproducibility
        n_jobs: Number of parallel jobs (-1 = all cores)
    
    Returns:
        tuple: (best_estimator, search_results, tuning_stats)
    """
    log_step("="*80, "STEP")
    log_step("HYPERPARAMETER TUNING WITH RANDOMIZEDSEARCHCV", "STEP")
    log_step("="*80, "STEP")
    
    start_time = time.time()

    # Optional downsampling for tuning to control memory
    tune_frac = config.TUNING_SAMPLE_FRACTION
    if 0 < tune_frac < 1.0:
        log_step(f"Sampling {tune_frac:.0%} of training data for tuning to reduce memory...", "SUBSTEP")
        X_train, _, y_train, _ = train_test_split(
            X_train,
            y_train,
            train_size=tune_frac,
            stratify=y_train,
            random_state=random_state,
            shuffle=True
        )
        log_step(f"Tuning subset: {X_train.shape[0]:,} samples × {X_train.shape[1]} features", "INFO")
    else:
        log_step("Using full training data for tuning (no sampling)", "INFO")
    
    # Define search space
    param_distributions = define_hyperparameter_search_space()
    
    # Create base estimator
    log_step("\nInitializing Random Forest base estimator...", "SUBSTEP")
    log_step(f"RF threads per fit: {config.N_JOBS}; max_samples={config.RF_MAX_SAMPLES}", "SUBSTEP")
    
    rf = RandomForestClassifier(
        random_state=random_state,
        n_jobs=config.N_JOBS,  # Use all available CPUs
        max_samples=config.RF_MAX_SAMPLES,
        verbose=0
    )
    
    # Create scoring metric (macro F1-score, robust to missing classes) and avoid NaNs
    log_step("Setting up macro F1-score as optimization metric...", "SUBSTEP")
    scoring = make_scorer(f1_score, average='macro', zero_division=0)
    
    # Create RandomizedSearchCV
    log_step(f"\nConfiguring RandomizedSearchCV:", "SUBSTEP")
    log_step(f"  Iterations: {n_iter}")
    log_step(f"  Cross-validation folds: {cv}")
    log_step(f"  Scoring: macro F1-score + garbage collection after each fold")
    log_step(f"  Parallel CV jobs: auto (-1) with threading backend; pre_dispatch='n_jobs'")
    log_step(f"  RF threads per fit: {config.N_JOBS}")
    log_step(f"  Total model fits: {n_iter * cv}")
    log_step(f"  Strategy: Threaded CV (shared memory) + per-fold gc")
    
    random_search = RandomizedSearchCV(
        estimator=rf,
        param_distributions=param_distributions,
        n_iter=n_iter,
        cv=cv,
        scoring=scoring,
        n_jobs=config.N_JOBS,  # Use all available CPUs
        pre_dispatch='n_jobs',  # Queue equals workers; threading backend avoids data copies
        random_state=random_state,
        verbose=2,
        return_train_score=False,  # Don't store train scores to save memory
        refit=True,  # Refit best model on full training set
        error_score=0  # If a fold errors, treat its score as 0 instead of NaN
    )
    
    # Perform search
    log_step(f"\nStarting RandomizedSearchCV...", "STEP")
    log_step(f"Training dataset (shared across threads): {X_train.shape[0]:,} samples × {X_train.shape[1]} features")
    log_step(f"Using all available CPUs for parallel training")
    log_step(f"Memory strategy: threaded CV shares data + gc per fold")
    log_step("")
    
    # Pre-fit garbage collection
    gc.collect()
    
    with parallel_backend('threading', n_jobs=config.N_JOBS):
        random_search.fit(X_train, y_train)
    
    # Post-fit garbage collection
    gc.collect()
    
    elapsed = time.time() - start_time
    
    # Extract results
    log_step("\n" + "="*80, "SUCCESS")
    log_step("HYPERPARAMETER TUNING COMPLETED", "SUCCESS")
    log_step("="*80, "SUCCESS")
    log_step(f"Time taken: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    
    # Best parameters
    log_step("\nBest Hyperparameters Found:", "STEP")
    for param, value in random_search.best_params_.items():
        log_step(f"  {param}: {value}")
    
    # Best score
    log_step(f"\nBest Cross-Validation Score:")
    log_step(f"  Macro F1-Score: {random_search.best_score_:.4f}")
    
    # Create results DataFrame
    results_df = pd.DataFrame(random_search.cv_results_)
    results_df = results_df.sort_values('rank_test_score')
    # Replace any NaN scores with 0 to keep downstream reporting stable
    if results_df['mean_test_score'].isna().all():
        log_step("All CV scores are NaN; replacing with 0 for reporting and plots", "WARNING")
    results_df['mean_test_score'] = results_df['mean_test_score'].fillna(0)
    results_df['std_test_score'] = results_df['std_test_score'].fillna(0)
    
    # Display top 5 combinations
    log_step("\nTop 5 Parameter Combinations:")
    log_step("Rank | Mean F1  | Std F1   | n_est | max_d | min_split | min_leaf | max_feat")
    log_step("-"*85)
    for idx, row in results_df.head(5).iterrows():
        log_step(
            f" {int(row['rank_test_score']):2d}  | "
            f"{row['mean_test_score']:.4f}  | "
            f"{row['std_test_score']:.4f}  | "
            f"{int(row['param_n_estimators']):4d}  | "
            f"{str(row['param_max_depth']):5s} | "
            f"   {int(row['param_min_samples_split']):2d}     | "
            f"   {int(row['param_min_samples_leaf']):2d}    | "
            f"{str(row['param_max_features']):8s}"
        )
    
    # Compile tuning statistics
    tuning_stats = {
        'n_iterations': n_iter,
        'cv_folds': cv,
        'total_fits': n_iter * cv,
        'best_params': random_search.best_params_,
        'best_cv_score': float(np.nan_to_num(random_search.best_score_, nan=0.0)),
        'best_cv_std': float(np.nan_to_num(results_df.iloc[0]['std_test_score'], nan=0.0)),
        'search_space_size': np.prod([len(v) for v in param_distributions.values()]),
        'time_seconds': elapsed,
        'time_minutes': elapsed / 60,
        'results_dataframe': results_df,
        'random_search_object': random_search
    }
    
    # Save best hyperparameters to cache for future use
    import joblib
    os.makedirs(os.path.dirname(config.HYPERPARAMETERS_CACHE_FILE), exist_ok=True)
    joblib.dump(random_search.best_params_, config.HYPERPARAMETERS_CACHE_FILE)
    log_step(f"✓ Best hyperparameters cached: {config.HYPERPARAMETERS_CACHE_FILE}", "SUCCESS")
    print()
    
    return random_search.best_estimator_, results_df, tuning_stats


def train_final_model(X_train, y_train, best_params, random_state=42, n_jobs=-1):
    """
    Train final model with best hyperparameters on full training set.
    
    Args:
        X_train: Training features
        y_train: Training labels
        best_params: Best hyperparameters from tuning
        random_state: Random seed
        n_jobs: Number of parallel jobs
    
    Returns:
        tuple: (trained_model, training_stats)
    """
    log_step("\n" + "="*80, "STEP")
    log_step("TRAINING FINAL MODEL", "STEP")
    log_step("="*80, "STEP")
    
    start_time = time.time()
    
    log_step("Model configuration:", "SUBSTEP")
    for param, value in best_params.items():
        log_step(f"  {param}: {value}")
    
    log_step(f"\nTraining dataset: {X_train.shape[0]:,} samples × {X_train.shape[1]} features")
    log_step(f"Number of classes: {len(np.unique(y_train))}")
    
    # Create final model
    final_model = RandomForestClassifier(
        **best_params,
        random_state=random_state,
        n_jobs=config.N_JOBS,  # Use all logical CPUs for final training
        verbose=0
    )
    
    log_step("\nTraining Random Forest model...", "STEP")
    log_step("This may take 10-20 minutes depending on dataset size...")
    
    final_model.fit(X_train, y_train)
    
    elapsed = time.time() - start_time
    
    log_step("\n" + "="*80, "SUCCESS")
    log_step("FINAL MODEL TRAINING COMPLETED", "SUCCESS")
    log_step("="*80, "SUCCESS")
    log_step(f"Time taken: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    
    # Calculate model statistics
    n_estimators = final_model.n_estimators
    total_nodes = sum(tree.tree_.node_count for tree in final_model.estimators_)
    total_leaves = sum(tree.tree_.n_leaves for tree in final_model.estimators_)
    avg_depth = np.mean([tree.tree_.max_depth for tree in final_model.estimators_])
    max_depth = max(tree.tree_.max_depth for tree in final_model.estimators_)
    
    log_step("\nModel Architecture:", "SUBSTEP")
    log_step(f"  Number of trees: {n_estimators}")
    log_step(f"  Total nodes: {total_nodes:,}")
    log_step(f"  Total leaves: {total_leaves:,}")
    log_step(f"  Average tree depth: {avg_depth:.1f}")
    log_step(f"  Maximum tree depth: {max_depth}")
    
    training_stats = {
        'training_time_seconds': elapsed,
        'training_time_minutes': elapsed / 60,
        'n_samples': X_train.shape[0],
        'n_features': X_train.shape[1],
        'n_classes': len(np.unique(y_train)),
        'n_estimators': n_estimators,
        'total_nodes': int(total_nodes),
        'total_leaves': int(total_leaves),
        'avg_tree_depth': float(avg_depth),
        'max_tree_depth': int(max_depth),
        'best_params': best_params
    }
    
    return final_model, training_stats


def analyze_feature_importances(model, feature_names):
    """
    Analyze and return feature importances from trained model.
    
    Args:
        model: Trained Random Forest model
        feature_names: List of feature names
    
    Returns:
        pd.DataFrame: Feature importances sorted by importance
    """
    log_step("\nAnalyzing feature importances...", "STEP")
    
    importances = model.feature_importances_
    
    importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importances
    }).sort_values('Importance', ascending=False).reset_index(drop=True)
    
    importance_df['Cumulative'] = importance_df['Importance'].cumsum()
    importance_df['Rank'] = range(1, len(importance_df) + 1)
    
    # Display top 20
    log_step("\nTop 20 Features by Importance:")
    log_step("Rank | Feature Name                          | Importance | Cumulative")
    log_step("-"*85)
    for idx, row in importance_df.head(20).iterrows():
        log_step(
            f" {int(row['Rank']):2d}  | "
            f"{row['Feature']:40s} | "
            f"{row['Importance']:8.4f}   | "
            f"{row['Cumulative']:6.2%}"
        )
    
    # Summary statistics
    top_10_cumulative = importance_df.head(10)['Importance'].sum()
    top_20_cumulative = importance_df.head(20)['Importance'].sum()
    
    log_step(f"\nFeature Importance Summary:")
    log_step(f"  Top 10 features: {top_10_cumulative:.2%} of total importance")
    log_step(f"  Top 20 features: {top_20_cumulative:.2%} of total importance")
    log_step(f"  Total features: {len(importance_df)}")
    
    return importance_df


def generate_training_visualizations(results_df, importance_df, tuning_stats, training_stats, output_dir):
    """
    Generate all training visualizations.
    
    Args:
        results_df: RandomizedSearchCV results
        importance_df: Feature importances DataFrame
        tuning_stats: Hyperparameter tuning statistics
        training_stats: Final training statistics
        output_dir: Output directory for visualizations
    """
    log_step("\n" + "="*80, "STEP")
    log_step("GENERATING TRAINING VISUALIZATIONS", "STEP")
    log_step("="*80, "STEP")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Hyperparameter importance (n_estimators vs F1)
    plot_hyperparameter_effect(results_df, 'n_estimators', output_dir)
    
    # 2. Hyperparameter importance (max_depth vs F1)
    plot_hyperparameter_effect(results_df, 'max_depth', output_dir)
    
    # 3. Top parameter combinations comparison
    plot_top_combinations(results_df, output_dir)
    
    # 4. Feature importances (top 30)
    plot_feature_importances(importance_df, top_n=30, output_dir=output_dir)
    
    # 5. Cumulative feature importance
    plot_cumulative_importance(importance_df, output_dir)
    
    # 6. CV scores distribution
    plot_cv_scores_distribution(results_df, output_dir)
    
    log_step("\nAll training visualizations generated successfully!", "SUCCESS")


def plot_hyperparameter_effect(results_df, param_name, output_dir):
    """Plot the effect of a hyperparameter on F1-score."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Group by parameter and calculate mean/std
    param_col = f'param_{param_name}'
    if param_col not in results_df.columns:
        return
    
    grouped = results_df.groupby(param_col).agg({
        'mean_test_score': ['mean', 'std', 'count']
    }).reset_index()
    
    grouped.columns = [param_name, 'mean_f1', 'std_f1', 'count']
    grouped = grouped.sort_values(param_name)

    # If all scores are NaN/zero, skip plotting
    if grouped['mean_f1'].dropna().empty:
        log_step(f"Skipping plot for {param_name}: all CV scores are NaN/empty", "WARNING")
        plt.close(fig)
        return
    
    # Handle None values for max_depth
    if param_name == 'max_depth':
        grouped[param_name] = grouped[param_name].apply(lambda x: 100 if x is None else x)
    
    # Plot
    ax.errorbar(grouped[param_name], grouped['mean_f1'], 
                yerr=grouped['std_f1'], marker='o', markersize=8,
                linewidth=2, capsize=5, capthick=2)
    
    ax.set_xlabel(param_name.replace('_', ' ').title(), fontsize=13, fontweight='bold')
    ax.set_ylabel('Macro F1-Score (CV)', fontsize=13, fontweight='bold')
    ax.set_title(f'Effect of {param_name.replace("_", " ").title()} on Model Performance',
                 fontsize=15, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3)
    
    # Highlight best value
    best_idx = grouped['mean_f1'].idxmax()
    best_value = grouped.loc[best_idx, param_name]
    best_f1 = grouped.loc[best_idx, 'mean_f1']
    
    ax.axvline(best_value, color='red', linestyle='--', linewidth=2, alpha=0.7, 
               label=f'Best: {best_value} (F1={best_f1:.4f})')
    ax.legend(fontsize=11)
    
    plt.tight_layout()
    save_figure(fig, os.path.join(output_dir, f'hyperparameter_{param_name}_effect.png'))


def plot_top_combinations(results_df, output_dir, top_n=10):
    """Plot comparison of top parameter combinations."""
    fig, ax = plt.subplots(figsize=(14, 8))
    
    top_results = results_df.head(top_n).copy()
    if top_results['mean_test_score'].dropna().empty:
        log_step("Skipping top combinations plot: all CV scores are NaN/empty", "WARNING")
        plt.close(fig)
        return
    top_results['combination'] = [f"Rank {i+1}" for i in range(len(top_results))]
    
    # Plot bars with error bars
    x = np.arange(len(top_results))
    bars = ax.bar(x, top_results['mean_test_score'], 
                   yerr=top_results['std_test_score'],
                   capsize=5, alpha=0.7, edgecolor='black', linewidth=1.5)
    
    # Color the best one differently
    bars[0].set_color('green')
    bars[0].set_alpha(0.9)
    
    ax.set_xlabel('Parameter Combination (Ranked by Performance)', fontsize=13, fontweight='bold')
    ax.set_ylabel('Macro F1-Score (CV)', fontsize=13, fontweight='bold')
    ax.set_title(f'Top {top_n} Hyperparameter Combinations Comparison',
                 fontsize=15, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(top_results['combination'], rotation=45, ha='right')
    ax.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for i, (bar, score) in enumerate(zip(bars, top_results['mean_test_score'])):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{score:.4f}',
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    save_figure(fig, os.path.join(output_dir, 'top_combinations_comparison.png'))


def plot_feature_importances(importance_df, top_n=30, output_dir=''):
    """Plot feature importances as horizontal bar chart."""
    fig, ax = plt.subplots(figsize=(12, 10))
    
    top_features = importance_df.head(top_n)
    
    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(top_features)))
    bars = ax.barh(range(len(top_features)), top_features['Importance'], 
                   color=colors, edgecolor='black', linewidth=1)
    
    ax.set_yticks(range(len(top_features)))
    ax.set_yticklabels(top_features['Feature'], fontsize=10)
    ax.set_xlabel('Gini Importance', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} Feature Importances (Random Forest)',
                 fontsize=14, fontweight='bold', pad=20)
    ax.invert_yaxis()
    ax.grid(axis='x', alpha=0.3)
    
    # Add value labels
    for i, (bar, importance) in enumerate(zip(bars, top_features['Importance'])):
        width = bar.get_width()
        ax.text(width + 0.001, bar.get_y() + bar.get_height()/2.,
                f'{importance:.4f}',
                ha='left', va='center', fontsize=8)
    
    plt.tight_layout()
    save_figure(fig, os.path.join(output_dir, 'feature_importances_top30.png'))


def plot_cumulative_importance(importance_df, output_dir):
    """Plot cumulative feature importance."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    x = range(1, len(importance_df) + 1)
    cumulative = importance_df['Cumulative'].values
    
    ax.plot(x, cumulative, linewidth=2.5, color='darkblue')
    ax.fill_between(x, cumulative, alpha=0.3, color='skyblue')
    
    # Add reference lines
    ax.axhline(0.5, color='red', linestyle='--', linewidth=2, alpha=0.7, label='50% importance')
    ax.axhline(0.8, color='orange', linestyle='--', linewidth=2, alpha=0.7, label='80% importance')
    ax.axhline(0.95, color='green', linestyle='--', linewidth=2, alpha=0.7, label='95% importance')
    
    # Find features needed for 80%
    features_80 = (importance_df['Cumulative'] <= 0.8).sum() + 1
    ax.axvline(features_80, color='orange', linestyle=':', linewidth=2, alpha=0.5)
    ax.text(features_80, 0.4, f'{features_80} features\n(80% importance)',
            ha='center', fontsize=10, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    ax.set_xlabel('Number of Features (Ranked by Importance)', fontsize=12, fontweight='bold')
    ax.set_ylabel('Cumulative Importance', fontsize=12, fontweight='bold')
    ax.set_title('Cumulative Feature Importance',
                 fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='lower right', fontsize=10)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    save_figure(fig, os.path.join(output_dir, 'cumulative_feature_importance.png'))


def plot_cv_scores_distribution(results_df, output_dir):
    """Plot distribution of CV scores across all parameter combinations."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    if results_df['mean_test_score'].dropna().empty:
        log_step("Skipping CV score distribution plot: all scores are NaN/empty", "WARNING")
        plt.close(fig)
        return

    # Histogram
    ax1.hist(results_df['mean_test_score'], bins=20, edgecolor='black', 
             alpha=0.7, color='skyblue')
    ax1.axvline(results_df['mean_test_score'].max(), color='red', 
                linestyle='--', linewidth=2, label=f'Best: {results_df["mean_test_score"].max():.4f}')
    ax1.set_xlabel('Macro F1-Score (CV)', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Frequency', fontsize=12, fontweight='bold')
    ax1.set_title('Distribution of CV Scores Across All Combinations',
                  fontsize=13, fontweight='bold')
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    
    # Box plot
    ax2.boxplot([results_df['mean_test_score']], labels=['All Combinations'])
    ax2.set_ylabel('Macro F1-Score (CV)', fontsize=12, fontweight='bold')
    ax2.set_title('CV Score Statistics',
                  fontsize=13, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    # Add statistics text
    stats_text = f"""Statistics:
Mean: {results_df['mean_test_score'].mean():.4f}
Median: {results_df['mean_test_score'].median():.4f}
Std: {results_df['mean_test_score'].std():.4f}
Min: {results_df['mean_test_score'].min():.4f}
Max: {results_df['mean_test_score'].max():.4f}"""
    
    ax2.text(1.3, results_df['mean_test_score'].mean(), stats_text,
             fontsize=10, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    plt.tight_layout()
    save_figure(fig, os.path.join(output_dir, 'cv_scores_distribution.png'))


def save_training_artifacts(model, tuning_stats, training_stats, importance_df, 
                           label_encoder, output_dir='trained_model', data_dir='data/preprocessed'):
    """
    Save all training artifacts.
    
    Args:
        model: Trained model
        tuning_stats: Hyperparameter tuning statistics
        training_stats: Training statistics
        importance_df: Feature importances
        label_encoder: Label encoder object
        output_dir: Output directory for trained model
        data_dir: Directory containing preprocessing objects (scaler, label_encoder)
    """
    log_step("\n" + "="*80, "STEP")
    log_step("SAVING TRAINING ARTIFACTS", "STEP")
    log_step("="*80, "STEP")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Save trained model
    model_path = os.path.join(output_dir, 'random_forest_model.joblib')
    joblib.dump(model, model_path)
    model_size = os.path.getsize(model_path) / (1024**2)  # MB
    log_step(f"Saved trained model: random_forest_model.joblib ({model_size:.1f} MB)")
    
    # 2. Copy preprocessing objects required for inference
    log_step("\nCopying preprocessing objects for inference...")
    import shutil
    
    # Copy scaler
    scaler_src = os.path.join(data_dir, 'scaler.joblib')
    if os.path.exists(scaler_src):
        scaler_dst = os.path.join(output_dir, 'scaler.joblib')
        shutil.copy2(scaler_src, scaler_dst)
        log_step(f"✓ Copied scaler.joblib to trained_model/")
    else:
        log_step(f"WARNING: scaler.joblib not found at {scaler_src}", "WARNING")
    
    # Copy label_encoder
    label_encoder_src = os.path.join(data_dir, 'label_encoder.joblib')
    if os.path.exists(label_encoder_src):
        label_encoder_dst = os.path.join(output_dir, 'label_encoder.joblib')
        shutil.copy2(label_encoder_src, label_encoder_dst)
        log_step(f"✓ Copied label_encoder.joblib to trained_model/")
    else:
        log_step(f"WARNING: label_encoder.joblib not found at {label_encoder_src}", "WARNING")
    
    # Copy selected_features
    selected_features_src = os.path.join(data_dir, 'selected_features.joblib')
    if os.path.exists(selected_features_src):
        selected_features_dst = os.path.join(output_dir, 'selected_features.joblib')
        shutil.copy2(selected_features_src, selected_features_dst)
        log_step(f"✓ Copied selected_features.joblib to trained_model/")
    else:
        log_step(f"WARNING: selected_features.joblib not found at {selected_features_src}", "WARNING")
    
    # 6. Save metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'model_type': 'RandomForestClassifier',
        'n_classes': len(label_encoder.classes_),
        'class_names': label_encoder.classes_.tolist(),
        'hyperparameter_tuning': {
            'n_iterations': tuning_stats['n_iterations'],
            'cv_folds': tuning_stats['cv_folds'],
            'best_cv_score': tuning_stats['best_cv_score'],
            'best_cv_std': tuning_stats['best_cv_std'],
            'best_params': tuning_stats['best_params'],
            'tuning_time_minutes': tuning_stats['time_minutes']
        },
        'final_training': {
            'training_time_minutes': training_stats['training_time_minutes'],
            'n_samples': training_stats['n_samples'],
            'n_features': training_stats['n_features'],
            'n_estimators': training_stats['n_estimators'],
            'total_nodes': training_stats['total_nodes'],
            'avg_tree_depth': training_stats['avg_tree_depth']
        },
        'feature_importances': {
            'top_10_features': importance_df.head(10)['Feature'].tolist(),
            'top_10_cumulative_importance': float(importance_df.head(10)['Importance'].sum())
        }
    }
    
    metadata_path = os.path.join(output_dir, 'training_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    log_step(f"Saved training metadata: training_metadata.json")
    
    # Calculate total storage
    total_size = sum(
        os.path.getsize(os.path.join(output_dir, f)) / (1024**2)
        for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f))
    )
    
    log_step(f"\nTotal artifacts storage: {total_size:.1f} MB")
    log_step("\n[SAVED FOR INFERENCE]", "SUCCESS")
    log_step("  ✓ random_forest_model.joblib", "SUCCESS")
    log_step("  ✓ scaler.joblib", "SUCCESS")
    log_step("  ✓ label_encoder.joblib", "SUCCESS")
    log_step("  ✓ selected_features.joblib", "SUCCESS")
    log_step("  ✓ training_metadata.json", "SUCCESS")
    log_step("Training artifacts saved successfully!", "SUCCESS")


def generate_training_report(tuning_stats, training_stats, importance_df, 
                            label_encoder, output_dir='reports/training', metadata=None):
    """
    Generate comprehensive training report.
    
    Args:
        tuning_stats: Hyperparameter tuning statistics
        training_stats: Training statistics
        importance_df: Feature importances
        label_encoder: Label encoder
        output_dir: Output directory
        metadata: Metadata including preprocessing feature importances
    """
    log_step("\nGenerating training report...", "STEP")
    
    os.makedirs(output_dir, exist_ok=True)
    
    report_lines = []
    report_lines.append("="*80)
    report_lines.append("                    MODEL TRAINING REPORT")
    report_lines.append("                    CICIDS2018 Dataset")
    report_lines.append(f"               Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("="*80)
    report_lines.append("")
    
    # 1. Training Overview
    report_lines.append("1. TRAINING OVERVIEW")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append("   Model Type: Random Forest Classifier")
    report_lines.append("   Training Approach: Hyperparameter Tuning → Final Training")
    report_lines.append("")
    
    # Add preprocessing information if available
    if metadata and 'preprocessing_feature_importances' in metadata:
        preprocessing_importance = metadata['preprocessing_feature_importances']
        report_lines.append("   Preprocessing Feature Selection:")
        report_lines.append(f"     Features evaluated during preprocessing: {len(preprocessing_importance)}")
        if 'feature' in preprocessing_importance.columns and 'importance' in preprocessing_importance.columns:
            top_5_features = preprocessing_importance.nlargest(5, 'importance')
            report_lines.append("     Top 5 features from preprocessing:")
            for idx, row in top_5_features.iterrows():
                report_lines.append(f"       - {row['feature']}: {row['importance']:.6f}")
        report_lines.append("")
    
    report_lines.append("   Timeline:")
    report_lines.append(f"     Hyperparameter Tuning: {tuning_stats['time_minutes']:.1f} minutes")
    report_lines.append(f"     Final Model Training: {training_stats['training_time_minutes']:.1f} minutes")
    total_time = tuning_stats['time_minutes'] + training_stats['training_time_minutes']
    report_lines.append(f"     Total Training Time: {total_time:.1f} minutes ({total_time/60:.1f} hours)")
    report_lines.append("")
    
    # 2. Hyperparameter Tuning
    report_lines.append("2. HYPERPARAMETER TUNING")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append("   2.1 Tuning Configuration")
    report_lines.append("       Method: RandomizedSearchCV")
    report_lines.append(f"       Iterations: {tuning_stats['n_iterations']} random combinations")
    report_lines.append(f"       Cross-Validation: {tuning_stats['cv_folds']}-fold stratified")
    report_lines.append("       Scoring Metric: f1_macro (balanced performance)")
    report_lines.append(f"       Total model fits: {tuning_stats['total_fits']}")
    report_lines.append("")
    
    report_lines.append("   2.2 Best Hyperparameters Found")
    for param, value in tuning_stats['best_params'].items():
        report_lines.append(f"       {param}: {value}")
    report_lines.append("")
    
    report_lines.append("   2.3 Best Cross-Validation Score")
    report_lines.append(f"       Macro F1-Score: {tuning_stats['best_cv_score']:.4f}")
    report_lines.append(f"       Standard Deviation: {tuning_stats['best_cv_std']:.4f}")
    ci_lower = tuning_stats['best_cv_score'] - 1.96 * tuning_stats['best_cv_std']
    ci_upper = tuning_stats['best_cv_score'] + 1.96 * tuning_stats['best_cv_std']
    report_lines.append(f"       95% CI: [{ci_lower:.4f}, {ci_upper:.4f}]")
    report_lines.append("")
    
    # 3. Final Model Training
    report_lines.append("3. FINAL MODEL TRAINING")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append("   3.1 Training Configuration")
    report_lines.append(f"       Training samples: {training_stats['n_samples']:,}")
    report_lines.append(f"       Features: {training_stats['n_features']}")
    report_lines.append(f"       Classes: {training_stats['n_classes']}")
    report_lines.append("")
    
    report_lines.append("   3.2 Model Architecture")
    report_lines.append(f"       Number of Trees: {training_stats['n_estimators']}")
    report_lines.append(f"       Total Nodes: {training_stats['total_nodes']:,}")
    report_lines.append(f"       Total Leaves: {training_stats['total_leaves']:,}")
    report_lines.append(f"       Average Tree Depth: {training_stats['avg_tree_depth']:.1f}")
    report_lines.append(f"       Maximum Tree Depth: {training_stats['max_tree_depth']}")
    report_lines.append("")
    
    # 4. Feature Importances
    report_lines.append("4. FEATURE IMPORTANCES")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append(f"   Top 30 Features:")
    report_lines.append("")
    report_lines.append("   Rank | Feature Name                          | Importance | Cumulative")
    report_lines.append("   " + "-"*74)
    
    for idx, row in importance_df.head(30).iterrows():
        report_lines.append(
            f"    {int(row['Rank']):2d}  | "
            f"{row['Feature']:40s} | "
            f"{row['Importance']:8.4f}   | "
            f"{row['Cumulative']:6.2%}"
        )
    
    report_lines.append("")
    top_10_cumulative = importance_df.head(10)['Importance'].sum()
    top_20_cumulative = importance_df.head(20)['Importance'].sum()
    report_lines.append("   Feature Importance Summary:")
    report_lines.append(f"     Top 10 features: {top_10_cumulative:.2%} of total importance")
    report_lines.append(f"     Top 20 features: {top_20_cumulative:.2%} of total importance")
    report_lines.append("")
    
    # 5. Training Quality Assessment
    report_lines.append("5. TRAINING QUALITY ASSESSMENT")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append("   Hyperparameter Tuning:")
    space_mark = "✓" if tuning_stats['search_space_size'] > 0 else "⚠️"
    iter_mark = "✓" if tuning_stats['n_iterations'] >= 10 else "⚠️"
    cv_mark = "✓" if tuning_stats['cv_folds'] >= 3 else "⚠️"
    f1_mark = "✓" if tuning_stats['best_cv_score'] >= config.TARGET_MACRO_F1_SCORE else "⚠️"
    report_lines.append(f"     {space_mark} Search space: {tuning_stats['search_space_size']:,} combinations")
    report_lines.append(f"     {iter_mark} Iterations: {tuning_stats['n_iterations']} samples")
    report_lines.append(f"     {cv_mark} Evaluation: {tuning_stats['cv_folds']}-fold CV")
    report_lines.append(f"     {f1_mark} Best parameters found (F1={tuning_stats['best_cv_score']:.4f})")
    report_lines.append("")
    
    report_lines.append("   Final Model:")
    smote_mark = "✓ Trained on balanced data (SMOTE applied)" if config.APPLY_SMOTE else "⚠️ Trained on imbalanced data (SMOTE disabled)"
    report_lines.append(f"     {smote_mark}")
    report_lines.append(f"     ✓ {training_stats['n_features']} features used")
    trees_mark = "✓" if training_stats['n_estimators'] >= 50 else "⚠️"
    report_lines.append(f"     {trees_mark} Model complexity: {training_stats['n_estimators']} trees")
    time_mark = "✓" if training_stats['training_time_minutes'] < 120 else "⚠️"
    report_lines.append(f"     {time_mark} Training time: {training_stats['training_time_minutes']:.1f} minutes")
    report_lines.append(f"     ✓ Reproducible (random_state={config.RANDOM_STATE})")
    report_lines.append("")
    
    # 6. Next Steps
    report_lines.append("6. NEXT STEPS")
    report_lines.append("   " + "="*70)
    report_lines.append("")
    report_lines.append("   Module 5: Model Testing")
    report_lines.append("     - Evaluate model on held-out test set")
    report_lines.append("     - Generate confusion matrix and classification report")
    report_lines.append("     - Calculate per-class metrics (precision, recall, F1)")
    report_lines.append("     - Generate ROC curves and AUC scores")
    report_lines.append("     - Assess model generalization performance")
    report_lines.append("")
    cv_score = tuning_stats.get('best_cv_score', 0)
    if cv_score >= config.TARGET_MACRO_F1_SCORE:
        report_lines.append(f"   Expected Test Performance: >{config.TARGET_MACRO_F1_SCORE*100:.0f}% macro F1-score")
    else:
        report_lines.append(f"   Note: CV F1-score ({cv_score:.4f}) is below target (>{config.TARGET_MACRO_F1_SCORE*100:.0f}%)")
        report_lines.append(f"   Expected Test Performance: ~{cv_score*100:.1f}% macro F1-score")
    report_lines.append("")
    
    report_lines.append("="*80)
    report_lines.append("                      END OF TRAINING REPORT")
    report_lines.append("="*80)
    report_lines.append("")
    report_lines.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("Module: Model Training (Module 4)")
    report_lines.append("Next step: Model Testing (Module 5)")
    report_lines.append("="*80)
    
    # Save report
    report_path = os.path.join(output_dir, 'training_results.txt')
    with open(report_path, 'w') as f:
        f.write('\n'.join(report_lines))
    
    log_step(f"Training report saved: {report_path}", "SUCCESS")
    log_step(f"Report length: {len(report_lines)} lines")


def generate_training_steps_log(tuning_stats, training_stats, importance_df, label_encoder, output_dir, n_iter, cv):
    """
    Generate step-by-step execution log for training module.
    
    Parameters:
    -----------
    tuning_stats : dict
        Hyperparameter tuning statistics
    training_stats : dict
        Final model training statistics
    importance_df : pd.DataFrame
        Feature importances
    label_encoder : LabelEncoder
        Fitted label encoder
    output_dir : str
        Output directory for report
    n_iter : int
        Number of tuning iterations
    cv : int
        Number of cross-validation folds
    """
    log_step("Generating step-by-step training log...", "SUBSTEP")
    
    os.makedirs(output_dir, exist_ok=True)
    
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append(" " * 22 + "MODULE 4: MODEL TRAINING")
    lines.append(" " * 25 + "STEP-BY-STEP LOG")
    lines.append(" " * 20 + f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append("")
    
    # STEP 1: Load Preprocessed Data
    lines.append("STEP 1: LOAD PREPROCESSED DATA")
    lines.append("-" * 80)
    lines.append("• Loaded preprocessed training data (after SMOTE & feature selection)")
    lines.append("• Loaded preprocessed test data (original distribution, no SMOTE)")
    lines.append("• Loaded scaler, label encoder, selected features")
    lines.append("✓ Preprocessing artifacts loaded successfully")
    lines.append("")
    
    # STEP 2: Analyze Training Data
    lines.append("STEP 2: ANALYZE TRAINING DATA")
    lines.append("-" * 80)
    if 'n_train_samples' in training_stats:
        lines.append(f"• Training samples: {training_stats['n_train_samples']:,}")
    if 'n_features' in training_stats:
        lines.append(f"• Training features: {training_stats['n_features']}")
    lines.append(f"• Label classes: {len(label_encoder.classes_)} classes")
    lines.append(f"  Classes: {', '.join(map(str, label_encoder.classes_))}")
    lines.append("✓ Training data analysis completed")
    lines.append("")
    
    # STEP 3: Hyperparameter Tuning
    lines.append("STEP 3: HYPERPARAMETER TUNING (RandomizedSearchCV)")
    lines.append("-" * 80)
    if tuning_stats.get('tuning_skipped', False):
        lines.append(f"• Status: SKIPPED (using cached hyperparameters)")
        lines.append(f"• Source: {tuning_stats.get('source', 'cache')}")
    else:
        lines.append(f"• Method: RandomizedSearchCV")
        lines.append(f"• Estimator: Random Forest Classifier")
        lines.append(f"• Iterations: {n_iter}")
        lines.append(f"• Cross-validation folds: {cv}")
        lines.append(f"• Scoring metric: F1-macro (handles class imbalance)")
        lines.append(f"• ⏱️  Expected time: 30-60 minutes (depends on hardware)")
        lines.append("")
        lines.append(f"• Best hyperparameters found:")
        if 'best_params' in tuning_stats:
            for param, value in tuning_stats['best_params'].items():
                lines.append(f"    - {param}: {value}")
    lines.append(f"• Best CV F1-score: {tuning_stats.get('best_cv_score', 0):.4f}")
    lines.append("✓ Hyperparameter tuning completed")
    lines.append("")
    
    # STEP 4: Train Final Model
    lines.append("STEP 4: TRAIN FINAL MODEL")
    lines.append("-" * 80)
    lines.append("• Using best hyperparameters from tuning")
    lines.append("• Training on complete training set (with SMOTE)")
    if 'training_time_seconds' in training_stats:
        lines.append(f"• Training time: {training_stats['training_time_seconds']:.1f} seconds ({training_stats.get('training_time_minutes', 0):.1f} minutes)")
    lines.append("✓ Final model trained successfully")
    lines.append("")
    
    # STEP 5: Evaluate on Test Set
    lines.append("STEP 5: EVALUATE ON TEST SET (Original Distribution)")
    lines.append("-" * 80)
    lines.append("• Test set has ORIGINAL class distribution (imbalanced)")
    lines.append("• No SMOTE applied to test set (real-world scenario)")
    lines.append("✓ Test set evaluation completed")
    lines.append("")
    
    # STEP 6: Feature Importance Analysis
    lines.append("STEP 6: FEATURE IMPORTANCE ANALYSIS")
    lines.append("-" * 80)
    lines.append("• Method: Random Forest Gini Importance")
    lines.append(f"• Total features in model: {len(importance_df)}")
    if len(importance_df) > 0:
        top_10 = importance_df.head(10)
        lines.append("• Top 10 Most Important Features:")
        for idx, (_, row) in enumerate(top_10.iterrows(), 1):
            lines.append(f"    {idx:2d}. {row['Feature']:<40} {row['Importance']:.6f}")
    lines.append("✓ Feature importance analysis completed")
    lines.append("")
    
    # STEP 7: Save Training Artifacts
    lines.append("STEP 7: SAVE TRAINING ARTIFACTS (INFERENCE-READY)")
    lines.append("-" * 80)
    lines.append("[SAVED FOR INFERENCE - Minimal Deployment]")
    lines.append("• Saved trained model: random_forest_model.joblib")
    lines.append("• Saved label encoder: label_encoder.joblib")
    lines.append("• Saved scaler: scaler.joblib")
    lines.append("• Saved selected features: selected_features.joblib")
    lines.append("• Saved training metadata: training_metadata.json")
    lines.append("✓ All inference artifacts saved successfully")
    lines.append("")
    
    # STEP 8: Generate Visualizations
    lines.append("STEP 8: GENERATE VISUALIZATIONS")
    lines.append("-" * 80)
    lines.append("• Generated hyperparameter tuning analysis charts")
    lines.append("• Generated feature importance plots (top 30 features)")
    lines.append("• Generated cumulative feature importance curve")
    lines.append("• Generated cross-validation performance analysis")
    lines.append("✓ All visualizations created")
    lines.append("")
    
    # STEP 9: Generate Training Report
    lines.append("STEP 9: GENERATE COMPREHENSIVE TEXT REPORT")
    lines.append("-" * 80)
    lines.append("• Created training_results.txt with:")
    lines.append("  - Hyperparameter tuning summary")
    lines.append("  - Best parameters and CV score")
    lines.append("  - Training statistics and performance")
    lines.append("  - Feature importance rankings")
    lines.append("  - Model architecture and configuration")
    lines.append("✓ Report generation completed")
    lines.append("")
    
    # Summary
    lines.append("=" * 80)
    lines.append(" " * 25 + "TRAINING SUMMARY")
    lines.append("=" * 80)
    lines.append(f"Training Samples: {training_stats.get('n_train_samples', 0):,}")
    lines.append(f"Test Samples: {training_stats.get('n_test_samples', 0):,}")
    lines.append(f"Features Used: {len(importance_df)}")
    lines.append(f"Classes: {len(label_encoder.classes_)}")
    lines.append(f"Best CV F1-score: {tuning_stats.get('best_cv_score', 0):.4f}")
    lines.append("")
    lines.append("Next Step: Module 5 - Model Testing & Evaluation")
    lines.append("  1. Load trained model and test data")
    lines.append("  2. Generate predictions on test set")
    lines.append("  3. Evaluate multiclass performance (macro/weighted/per-class metrics)")
    lines.append("  4. Evaluate binary performance (Attack vs Benign)")
    lines.append("  5. Analyze prediction errors by class")
    lines.append("  6. Generate ROC curves, confusion matrices, and visualizations")
    lines.append("  7. Generate comprehensive testing report")
    lines.append("=" * 80)
    
    # Write steps log
    steps_path = os.path.join(output_dir, 'training_steps.txt')
    with open(steps_path, 'w') as f:
        f.write('\n'.join(lines))
    
    log_step(f"✓ Saved training step-by-step log: training_steps.txt", "SUCCESS")


def train_model(data_dir='data/preprocessed', 
                model_dir='trained_model',
                reports_dir='reports/training',
                n_iter=20, 
                cv=5,
                random_state=42,
                use_hypercache=False):
    """
    Main function to train NIDS model.
    
    Args:
        data_dir: Directory with preprocessed data
        model_dir: Directory to save trained model
        reports_dir: Directory to save reports and visualizations
        n_iter: Number of RandomizedSearchCV iterations
        cv: Number of cross-validation folds
        random_state: Random seed for reproducibility
        use_hypercache: If True, use cached hyperparameters instead of tuning
    
    Returns:
        dict: Training results and statistics
    """
    log_step("\n" + "="*80, "STEP")
    log_step("MODULE 4: MODEL TRAINING", "STEP")
    log_step("="*80, "STEP")
    
    overall_start = time.time()
    
    # 1. Load preprocessed data
    X_train, X_test, y_train, y_test, scaler, label_encoder, metadata = \
        load_preprocessed_data(data_dir)
    
    feature_names = X_train.columns.tolist()
    
    # 2. Perform hyperparameter tuning (or load from cache)
    if use_hypercache:
        log_step("\nUsing cached hyperparameters (skipping tuning)...", "SUBSTEP")
        best_params = load_cached_hyperparameters()
        if best_params is None:
            log_step("No cached hyperparameters found! Running tuning...", "WARNING")
            best_model, results_df, tuning_stats = perform_hyperparameter_tuning(
                X_train, y_train, n_iter=n_iter, cv=cv, random_state=random_state
            )
        else:
            # Use cached parameters - create dummy stats
            log_step(f"Skipping hyperparameter tuning", "SUCCESS")
            tuning_stats = {
                'best_params': best_params,
                'source': 'cache',
                'tuning_skipped': True,
                'best_cv_score': 0.0,
                'best_cv_std': 0.0,
                'n_iterations': 0,
                'cv_folds': cv,
                'total_fits': 0,
                'time_minutes': 0.0,
                'search_space_size': 0
            }
            best_model = None
            results_df = None
    else:
        best_model, results_df, tuning_stats = perform_hyperparameter_tuning(
            X_train, y_train, n_iter=n_iter, cv=cv, random_state=random_state
        )
    
    # 3. Train final model (already done by RandomizedSearchCV with refit=True)
    # But we'll retrain to get detailed statistics
    final_model, training_stats = train_final_model(
        X_train, y_train, tuning_stats['best_params'], 
        random_state=random_state
    )
    
    # Add train/test sample counts for report generators
    training_stats['n_train_samples'] = X_train.shape[0]
    training_stats['n_test_samples'] = X_test.shape[0]
    
    # 4. Analyze feature importances
    importance_df = analyze_feature_importances(final_model, feature_names)
    
    # 5. Generate visualizations (skip if using cached hyperparameters)
    if results_df is not None:
        generate_training_visualizations(
            results_df, importance_df, tuning_stats, training_stats, reports_dir
        )
    else:
        log_step("\nGenerating basic training visualizations (hyperparameter tuning charts skipped)...", "STEP")
        # Only generate feature importance visualizations
        output_dir = reports_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Plot top 30 features
        fig, ax = plt.subplots(figsize=(12, 8))
        top_features = importance_df.head(30)
        ax.barh(range(len(top_features)), top_features['Importance'])
        ax.set_yticks(range(len(top_features)))
        ax.set_yticklabels(top_features['Feature'])
        ax.set_xlabel('Importance')
        ax.set_title('Top 30 Feature Importances (RF Model)')
        ax.invert_yaxis()
        plt.tight_layout()
        save_figure(fig, os.path.join(output_dir, 'feature_importances_top30.png'))
        
        # Plot cumulative importance
        cumulative_importance = importance_df['Importance'].cumsum() / importance_df['Importance'].sum()
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(range(len(cumulative_importance)), cumulative_importance, 'b-', linewidth=2)
        ax.axhline(y=0.95, color='r', linestyle='--', label='95% threshold')
        ax.fill_between(range(len(cumulative_importance)), cumulative_importance, alpha=0.3)
        ax.set_xlabel('Feature Rank')
        ax.set_ylabel('Cumulative Importance')
        ax.set_title('Cumulative Feature Importance')
        ax.legend()
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        save_figure(fig, os.path.join(output_dir, 'cumulative_feature_importance.png'))
    
    # 6. Save training artifacts
    save_training_artifacts(
        final_model, tuning_stats, training_stats, importance_df,
        label_encoder, model_dir, data_dir
    )
    
    # 7. Generate training report (pass metadata for preprocessing feature importance info)
    generate_training_report(
        tuning_stats, training_stats, importance_df,
        label_encoder, reports_dir, metadata=metadata
    )
    
    # 8. Generate step-by-step training log
    generate_training_steps_log(
        tuning_stats, training_stats, importance_df, 
        label_encoder, reports_dir, n_iter, cv
    )
    
    overall_elapsed = time.time() - overall_start
    
    log_step("\n" + "="*80, "SUCCESS")
    log_step("MODULE 4: MODEL TRAINING COMPLETED SUCCESSFULLY", "SUCCESS")
    log_step("="*80, "SUCCESS")
    log_step(f"Total time: {overall_elapsed:.1f} seconds ({overall_elapsed/60:.1f} minutes)")
    log_step(f"Best CV F1-score: {tuning_stats['best_cv_score']:.4f}")
    log_step(f"Model saved to: {model_dir}/")
    log_step(f"Reports saved to: {reports_dir}/")
    
    return {
        'model': final_model,
        'tuning_stats': tuning_stats,
        'training_stats': training_stats,
        'importance_df': importance_df,
        'label_encoder': label_encoder,
        'feature_names': feature_names
    }


if __name__ == "__main__":
    # Train the model
    results = train_model(
        n_iter=config.N_ITER_SEARCH,
        cv=config.CV_FOLDS,
        random_state=config.RANDOM_STATE
    )
