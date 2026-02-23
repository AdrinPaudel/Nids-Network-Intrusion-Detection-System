"""
Attack Report Generator
=======================
Tracks all attacks performed during NIDS testing and generates detailed reports.
Compares attack flows with training data to verify feature patterns match.

Reports generated:
    reports/
        {timestamp}_attack_report/
            attack_summary.txt          # Overall attack report
            attack_details.txt          # Per-attack breakdown
            feature_comparison.txt      # Attack vs Training data feature comparison
            attacks_log.json           # JSON log of all attacks performed
"""

import os
import sys
import json
import threading
import time
from datetime import datetime
from collections import defaultdict
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from config import (
    CLASSIFICATION_REPORTS_DIR, COLOR_GREEN, COLOR_RED, COLOR_YELLOW, COLOR_CYAN, COLOR_RESET
)


class AttackReport:
    """
    Generates comprehensive attack reports comparing live attack flows 
    with training data patterns.
    """
    
    def __init__(self, report_dir=None):
        """
        Args:
            report_dir: root reports directory (default: reports/)
        """
        if report_dir is None:
            report_dir = CLASSIFICATION_REPORTS_DIR
        
        # Create attack report folder
        self.report_start = datetime.now()
        report_ts = self.report_start.strftime("%Y-%m-%d_%H-%M-%S")
        self.report_folder_name = f"{report_ts}_attack_report"
        self.report_folder = os.path.join(report_dir, self.report_folder_name)
        os.makedirs(self.report_folder, exist_ok=True)
        
        # Attack tracking
        self.attacks = []  # List of attack dicts
        self.lock = threading.Lock()
        
        # Feature statistics
        self.attack_features = defaultdict(list)  # attack_type -> list of feature dicts
        self.training_stats = {}  # Loaded from training data
        
        self._load_training_stats()
    
    def _load_training_stats(self):
        """Load feature statistics from training data."""
        try:
            # Load training CSV
            csv_path = os.path.join(PROJECT_ROOT, "data/raw/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv")
            if not os.path.exists(csv_path):
                return
            
            # Sample rows
            df = pd.read_csv(csv_path, nrows=50000)
            
            # Get statistics by class
            for label in df['Label'].unique():
                self.training_stats[label] = {
                    "count": len(df[df['Label'] == label]),
                    "features": {}
                }
                
                # Key features to track
                key_features = [
                    'Fwd Seg Size Min', 'Dst Port', 'TotLen Fwd Pkts', 'Init Fwd Win Byts',
                    'Pkt Len Max', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
                    'Protocol', 'Flow Byts/s', 'RST Flag Cnt', 'SYN Flag Cnt'
                ]
                
                for feat in key_features:
                    if feat in df.columns:
                        vals = pd.to_numeric(df[df['Label'] == label][feat], errors='coerce')
                        self.training_stats[label]["features"][feat] = {
                            "mean": float(vals.mean()),
                            "std": float(vals.std()),
                            "min": float(vals.min()),
                            "max": float(vals.max()),
                        }
        except Exception as e:
            print(f"{COLOR_YELLOW}[ATTACK REPORT] Could not load training stats: {e}{COLOR_RESET}")
    
    def log_attack(self, attack_type, target_ip, duration, status="completed"):
        """
        Log an attack event.
        
        Args:
            attack_type: 'dos', 'ddos', 'brute-force', 'botnet', 'infiltration'
            target_ip: target IP address
            duration: attack duration in seconds
            status: 'started', 'completed', 'failed'
        """
        with self.lock:
            attack = {
                "timestamp": datetime.now().isoformat(),
                "attack_type": attack_type,
                "target_ip": target_ip,
                "duration": duration,
                "status": status,
            }
            self.attacks.append(attack)
    
    def add_flow_features(self, attack_type, flow_dict):
        """
        Add extracted flow features from attack.
        
        Args:
            attack_type: 'dos', 'ddos', 'brute-force', 'botnet', 'infiltration'
            flow_dict: dict with flow features from CICFlowMeter
        """
        with self.lock:
            # Store only key features
            key_features = {
                'Fwd Seg Size Min', 'Dst Port', 'TotLen Fwd Pkts', 'Init Fwd Win Byts',
                'Pkt Len Max', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
                'Protocol', 'Flow Byts/s', 'RST Flag Cnt', 'SYN Flag Cnt'
            }
            
            flow_features = {}
            for feat in key_features:
                if feat in flow_dict:
                    try:
                        flow_features[feat] = float(flow_dict[feat])
                    except (ValueError, TypeError):
                        pass
            
            if flow_features:
                self.attack_features[attack_type].append(flow_features)
    
    def generate_reports(self):
        """Generate all attack reports."""
        print(f"\n{COLOR_CYAN}[ATTACK REPORT] Generating attack reports...{COLOR_RESET}")
        
        self._write_attack_summary()
        self._write_attack_details()
        self._write_feature_comparison()
        self._write_attacks_log()
        
        print(f"{COLOR_GREEN}[ATTACK REPORT] Reports saved to: {self.report_folder}{COLOR_RESET}")
    
    def _write_attack_summary(self):
        """Write attack_summary.txt"""
        summary_path = os.path.join(self.report_folder, "attack_summary.txt")
        report_end = datetime.now()
        elapsed = (report_end - self.report_start).total_seconds()
        
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  NIDS ATTACK REPORT - SUMMARY\n")
            f.write("=" * 100 + "\n\n")
            
            f.write(f"  Report Generated:  {report_end.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Report Folder:     {self.report_folder_name}\n")
            f.write(f"  Report Duration:   {elapsed:.1f}s\n")
            f.write(f"  Total Attacks:     {len(self.attacks)}\n")
            f.write("\n" + "=" * 100 + "\n\n")
            
            # Attack statistics
            attack_counts = defaultdict(int)
            total_attack_time = 0
            for attack in self.attacks:
                attack_counts[attack['attack_type']] += 1
                total_attack_time += attack['duration']
            
            f.write("  ATTACK STATISTICS\n")
            f.write("  " + "-" * 96 + "\n\n")
            f.write(f"  Total Attack Time:  {total_attack_time}s\n\n")
            
            f.write("  By Attack Type:\n")
            for attack_type, count in sorted(attack_counts.items()):
                total_time = sum(a['duration'] for a in self.attacks if a['attack_type'] == attack_type)
                num_flows = len(self.attack_features.get(attack_type, []))
                f.write(f"    {attack_type:20s} x{count:3d}  Total Time: {total_time:6d}s  Flows: {num_flows:6d}\n")
            
            f.write("\n" + "-" * 100 + "\n\n")
            
            # Flow statistics
            f.write("  FLOW EXTRACTION STATISTICS\n")
            f.write("  " + "-" * 96 + "\n\n")
            total_flows = sum(len(flows) for flows in self.attack_features.values())
            f.write(f"  Total Flows Extracted:  {total_flows}\n\n")
            
            f.write("  By Attack Type:\n")
            for attack_type in sorted(self.attack_features.keys()):
                flows = self.attack_features[attack_type]
                if flows:
                    f.write(f"    {attack_type:20s} {len(flows):6d} flows\n")
            
            f.write("\n" + "=" * 100 + "\n")
    
    def _write_attack_details(self):
        """Write attack_details.txt with per-attack breakdown"""
        details_path = os.path.join(self.report_folder, "attack_details.txt")
        
        with open(details_path, "w", encoding="utf-8") as f:
            f.write("=" * 100 + "\n")
            f.write("  NIDS ATTACK REPORT - DETAILED LOG\n")
            f.write("=" * 100 + "\n\n")
            
            f.write(f"{'#':>3s} {'Attack Type':20s} {'Target IP':15s} {'Duration':10s} {'Status':12s} {'Timestamp':25s}\n")
            f.write("-" * 100 + "\n")
            
            for i, attack in enumerate(self.attacks, 1):
                f.write(f"{i:3d} {attack['attack_type']:20s} {attack['target_ip']:15s} "
                       f"{attack['duration']:10d}s {attack['status']:12s} {attack['timestamp']:25s}\n")
            
            f.write("-" * 100 + "\n")
            f.write(f"{'TOTAL':>5s} {len(self.attacks)} attacks\n")
            f.write("=" * 100 + "\n")
    
    def _write_feature_comparison(self):
        """Write feature_comparison.txt comparing attack features with training data"""
        comp_path = os.path.join(self.report_folder, "feature_comparison.txt")
        
        with open(comp_path, "w", encoding="utf-8") as f:
            f.write("=" * 120 + "\n")
            f.write("  NIDS ATTACK REPORT - FEATURE COMPARISON WITH TRAINING DATA\n")
            f.write("=" * 120 + "\n\n")
            
            f.write("  This report compares features extracted from live attacks with CICIDS2018 training data.\n")
            f.write("  Helps verify that attack patterns match expected behavior.\n\n")
            f.write("=" * 120 + "\n\n")
            
            # For each attack type
            for attack_type in sorted(self.attack_features.keys()):
                flows = self.attack_features[attack_type]
                if not flows:
                    continue
                
                f.write(f"\n  ATTACK TYPE: {attack_type.upper()}\n")
                f.write("  " + "-" * 116 + "\n\n")
                f.write(f"  Total Flows: {len(flows)}\n\n")
                
                # Attack statistics
                attack_df = pd.DataFrame(flows)
                
                f.write(f"  {'Feature':35s} {'Attack Mean':>15s} {'Attack Std':>15s} "
                       f"{'Training Mean':>15s} {'Training Std':>15s} {'Match':>10s}\n")
                f.write("  " + "-" * 116 + "\n")
                
                for feature in sorted(attack_df.columns):
                    attack_mean = attack_df[feature].mean()
                    attack_std = attack_df[feature].std()
                    
                    # Compare with training data
                    match = "N/A"
                    train_mean_str = "N/A"
                    train_std_str = "N/A"
                    
                    # Try to find matching training class
                    for class_name in self.training_stats.keys():
                        if attack_type.lower() in class_name.lower() or class_name.lower() in attack_type.lower():
                            if feature in self.training_stats[class_name].get("features", {}):
                                train_stats = self.training_stats[class_name]["features"][feature]
                                train_mean = train_stats["mean"]
                                train_std = train_stats["std"]
                                
                                # Simple comparison: check if ranges overlap
                                attack_range = (attack_mean - 2*attack_std, attack_mean + 2*attack_std)
                                train_range = (train_mean - 2*train_std, train_mean + 2*train_std)
                                
                                # Check overlap
                                if (attack_range[0] <= train_range[1] and attack_range[1] >= train_range[0]):
                                    match = "✓ MATCH"
                                else:
                                    match = "✗ DIFFER"
                                
                                train_mean_str = f"{train_mean:15.2f}"
                                train_std_str = f"{train_std:15.2f}"
                                break
                    
                    f.write(f"  {feature:35s} {attack_mean:15.2f} {attack_std:15.2f} "
                           f"{train_mean_str:>15s} {train_std_str:>15s} {match:>10s}\n")
                
                f.write("\n")
            
            f.write("=" * 120 + "\n")
            f.write("  SUMMARY: ✓ MATCH = Attack patterns align with training data | ✗ DIFFER = Pattern differs\n")
            f.write("=" * 120 + "\n")
    
    def _write_attacks_log(self):
        """Write attacks_log.json for machine-readable format"""
        log_path = os.path.join(self.report_folder, "attacks_log.json")
        
        log_data = {
            "report_generated": self.report_start.isoformat(),
            "total_attacks": len(self.attacks),
            "total_flows": sum(len(flows) for flows in self.attack_features.values()),
            "attacks": self.attacks,
            "attack_features_summary": {
                attack_type: {
                    "count": len(flows),
                    "stats": {
                        feature: {
                            "mean": float(np.array([f.get(feature, np.nan) for f in flows]).mean()),
                            "std": float(np.array([f.get(feature, np.nan) for f in flows]).std()),
                        }
                        for feature in set(f.keys() for flows_list in self.attack_features.values() for f in flows_list)
                    }
                }
                for attack_type, flows in self.attack_features.items()
            }
        }
        
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)


# Global attack report instance
_attack_report = None


def get_attack_report(report_dir=None):
    """Get or create global attack report instance."""
    global _attack_report
    if _attack_report is None:
        _attack_report = AttackReport(report_dir=report_dir)
    return _attack_report


def log_attack(attack_type, target_ip, duration, status="completed"):
    """Log an attack globally."""
    report = get_attack_report()
    report.log_attack(attack_type, target_ip, duration, status)


def add_flow_features(attack_type, flow_dict):
    """Add flow features globally."""
    report = get_attack_report()
    report.add_flow_features(attack_type, flow_dict)


def generate_attack_reports(report_dir=None):
    """Generate attack reports."""
    report = get_attack_report(report_dir=report_dir)
    report.generate_reports()


if __name__ == "__main__":
    # Example usage
    report = AttackReport()
    
    # Simulate some attacks
    report.log_attack("dos", "192.168.56.103", 60, "completed")
    report.log_attack("ddos", "192.168.56.103", 45, "completed")
    
    # Generate reports
    report.generate_reports()
    
    print(f"\n[OK] Attack report generated at: {report.report_folder}")
