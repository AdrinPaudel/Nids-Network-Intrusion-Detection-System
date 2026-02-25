# EXTREME Attack Modifications Applied - 10x Increase

## Summary
Increased all attack intensities by **10x** to generate unmissable threat signatures. Model still correctly classifying attacks as BENIGN instead of DoS/DDoS, so we're going EXTREME.

## Modifications Applied

### _1_dos_attack.py

**HULK HTTP GET Flood:**
- **Before**: 50-200 requests per connection
- **After**: 500-2000 requests per connection ✅ 10x
- **Delay**: 0.001-0.005s → 0.0001-0.0005s ✅ 10x faster

**Slowloris Connection Hold:**
- **Connections**: 200-500 → 2000-5000 ✅ 10x
- **Header lines/round**: 3-5 → 10-20 ✅ 3-4x increase
- **Keep-alive interval**: 3-5s → 0.5-1s ✅ 5-10x faster

### _2_ddos_simulation.py

**LOIC UDP Flood:**
- **Before**: 50-200 packets per flow
- **After**: 500-2000 packets per flow ✅ 10x
- **Delay**: 0.001-0.01s → 0.00001-0.0001s ✅ 100x faster

**LOIC HTTP Flood:**
- **Before**: 100-300 requests per connection
- **After**: 1000-3000 requests per connection ✅ 10x
- **Delay**: 0.001-0.005s → 0.0001-0.0005s ✅ 10x faster

**HOIC POST Flood:**
- **Before**: 50-100 requests per connection
- **After**: 500-1000 requests per connection ✅ 10x
- **Delay**: 0.001-0.005s → 0.0001-0.0005s ✅ 10x faster

## Expected Results

### Network Impact:
- **100-1000x increase in total traffic volume**
- More packets per TCP/UDP flow
- Sustained attack signatures over longer periods
- Feature values (Tot Fwd Pkts, Flow Pkts/s, etc.) should match CICIDS2018 training data much better

### Classification Expected:
- Port 80 flows should now hit 50%+ DoS/DDoS primary predictions (was 20-35% secondary before)
- UDP flows should now show 20%+ DDoS (was 0.7-5.8% before)
- Actual threat detection instead of secondary detection

## Deployment Steps

```bash
# On Windows (local):
git add setup/setup_attacker/_1_dos_attack.py setup/setup_attacker/_2_ddos_simulation.py
git commit -m "EXTREME: 10x attack increase - unmissable threat signatures"
git push

# On Linux VM:
cd ~/Nids  # or wherever cloned
git pull
cd setup/setup_attacker

# Test new attacks (100s duration):
python _1_dos_attack.py 100
python _2_ddos_simulation.py 100

# Monitor results in: /tmp/classification_minute_*.txt
# Or check: ~/Nids/temp/ for latest run
```

## If Still Not Working

If classification still shows BENIGN even after these extreme increases, issues are likely:

1. **Flow Timeout Issue**: Flowmeter might be splitting attacks into multiple 30-60s flows
   - Solution: Extend attack duration to 300-600 seconds
   - Solution: Check flowmeter timeout settings

2. **Model Retraining Needed**: Model may be overfitted to BENIGN (class imbalance)
   - Solution: Retrain with equal benign/attack samples
   - Solution: Lower classification threshold from 50% to 40%

3. **Packet Loss/Filtering**: Network dropping attack packets
   - Solution: Verify no firewall rules blocking attacks
   - Solution: Check network interface settings

## Files Modified

- [z:/Nids/setup/setup_attacker/_1_dos_attack.py](_1_dos_attack.py) ✅
- [z:/Nids/setup/setup_attacker/_2_ddos_simulation.py](_2_ddos_simulation.py) ✅
