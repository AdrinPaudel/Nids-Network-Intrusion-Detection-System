# Attack Report System

## Overview

The Attack Report system tracks all attacks performed during NIDS testing and generates detailed comparison reports against CICIDS2018 training data.

This ensures:
✅ All attacks are properly logged and documented
✅ Attack patterns match training data behavior  
✅ Feature distributions are consistent with labeled data
✅ Model predictions are validated against ground truth

---

## How It Works

### 1. **Attack Logging**
Every attack is logged with:
- Attack type (DoS, DDoS, Brute Force, Botnet, Infiltration)
- Target IP and duration
- Start/completion status
- Exact timestamp

### 2. **Flow Feature Extraction**
Key features extracted from attack flows (same as training):
- Fwd Seg Size Min
- Dst Port  
- TotLen Fwd Pkts
- Init Fwd Win Byts
- Pkt Len Max
- Flow Duration
- Tot Fwd Pkts / Tot Bwd Pkts
- Protocol
- Flow Byts/s
- RST Flag Cnt / SYN Flag Cnt
- ... and others

### 3. **Feature Comparison**
Attack feature statistics are compared with CICIDS2018 training data:
```
Attack vs Training Features:
  Fwd Seg Size Min
    Attack Mean:     20.23   |  Training Mean: 20.15   |  ✓ MATCH
    Attack Std:       2.10   |  Training Std:   1.98   |
    
  Dst Port
    Attack Mean:     443.12  |  Training Mean: 443.05  |  ✓ MATCH
    Attack Std:      120.34  |  Training Std:  115.67  |
```

✓ MATCH = Patterns align (ranges overlap)
✗ DIFFER = Pattern differs (ranges don't overlap)

---

## Report Files Generated

Each attack session creates a folder: `reports/{timestamp}_attack_report/`

### **attack_summary.txt**
High-level overview:
- Total attacks performed
- Attack time breakdown
- Number of flows extracted per attack type
- Total flow count

### **attack_details.txt**
Detailed log table:
```
#   Attack Type         Target IP       Duration   Status      Timestamp
1   dos                 192.168.56.103  500s       completed   2026-02-23T23:45:12.234567
2   ddos                192.168.56.103  300s       completed   2026-02-23T23:58:45.567890
...
```

### **feature_comparison.txt**
Feature-by-feature comparison with training data:
```
ATTACK TYPE: DOS

Total Flows: 234

Feature                           Attack Mean      Attack Std    Training Mean    Training Std    Match
Fwd Seg Size Min                      20.23           2.10          20.15            1.98       ✓ MATCH
Dst Port                             443.12         120.34         443.05          115.67       ✓ MATCH
TotLen Fwd Pkts                     5420.34         892.10        5435.21          875.34       ✓ MATCH
Init Fwd Win Byts                  65535.00           0.00        65535.00            0.00       ✓ MATCH
...
```

### **attacks_log.json**
Machine-readable JSON log:
```json
{
  "report_generated": "2026-02-23T23:50:00.123456",
  "total_attacks": 2,
  "total_flows": 450,
  "attacks": [
    {
      "timestamp": "2026-02-23T23:45:12.234567",
      "attack_type": "dos",
      "target_ip": "192.168.56.103",
      "duration": 500,
      "status": "completed"
    },
    ...
  ],
  "attack_features_summary": {...}
}
```

---

## Usage

### Run Attack + Generate Report
```bash
cd z:\Nids\device_attack

# DoS for 500 seconds (auto-discovers VM)
python device_attack.py --dos --duration 500

# DDoS for 100 seconds (explicit IP)
python device_attack.py --ddos --target 192.168.56.103 --duration 100

# All attacks shuffled for 5 minutes
python device_attack.py --all --duration 300
```

**After attack completes**, attack report is automatically generated in:
```
z:\Nids\reports\{timestamp}_attack_report\
```

### View Reports
```bash
# Open the summary
cat z:\Nids\reports\{timestamp}_attack_report\attack_summary.txt

# Compare features with training data
cat z:\Nids\reports\{timestamp}_attack_report\feature_comparison.txt

# View detailed logs
cat z:\Nids\reports\{timestamp}_attack_report\attack_details.txt
```

---

## Integration with Classification Reports

Both run together:
```
├─ **Attack Report** (z:\Nids\reports\{timestamp}_attack_report\)
│  ├─ attack_summary.txt
│  ├─ attack_details.txt
│  ├─ feature_comparison.txt
│  └─ attacks_log.json
│
└─ **Classification Report** (z:\Nids\reports\live_default_{timestamp}\)
   ├─ minute_HH-MM.txt  (per-minute flows)
   ├─ session_summary.txt
   └─ ...
```

---

## Verification Workflow

1. **Start NIDS** (Terminal 1):
   ```bash
   cd z:\Nids
   python classification.py --vm --debug
   ```

2. **Run Attack** (Terminal 2):
   ```bash
   cd z:\Nids\device_attack
   python device_attack.py --dos --duration 500
   ```
   
   This:
   - Launches DoS for 500 seconds
   - Logs all attacks
   - Generates attack report
   - Compares with training data

3. **Compare Reports**:
   - Check `attack_summary.txt` → confirm attack was logged
   - Check `feature_comparison.txt` → verify patterns match training data
   - Check classification output → should show RED (threat detected)
   - Check `session_summary.txt` → should show DoS predictions

4. **Validate**:
   ```
   ✓ Attack logged in report
   ✓ Features match training data
   ✓ Model correctly classified as DoS
   ✓ Reports align with each other
   ```

---

## Expected Output

### During Attack:
```
[+] Target: 192.168.56.103
[+] Attack types: DoS (HTTP-layer)
[+] Total duration: 500s (continuous)

[ 1] (    0s) DoS (HTTP-layer)         for 500s...   > HULK DoS (500s)...Done

[*] Generating attack report...
[ATTACK REPORT] Generating attack reports...
[ATTACK REPORT] Reports saved to: z:\Nids\reports\2026-02-23_23-45-12_attack_report
```

### Attack Report Shows:
```
ATTACK SUMMARY
  Total Attacks:     1
  Total Attack Time: 500s
  Total Flows:       234

FEATURE COMPARISON
  Fwd Seg Size Min              20.23 ✓ MATCH (training: 20.15)
  Dst Port                     443.12 ✓ MATCH (training: 443.05)
  TotLen Fwd Pkts            5420.34 ✓ MATCH (training: 5435.21)
  ...
```

This confirms everything is working correctly!

---

## Troubleshooting

**No attack report generated?**
- Check if `attack_report.py` exists in `z:\Nids\`
- Verify `device_attack.py` is running without errors
- Check `reports/` directory permissions

**Features don't match?**
- May indicate attack pattern differs from training data
- Check if right attack type is running (verify output)
- Firewall may be blocking some traffic types

**No flows extracted?**
- Ensure NIDS is capturing on correct adapter (`--vm` flag for VirtualBox)
- Verify target IP is reachable (ping test)
- Check NIDS console for capture errors
