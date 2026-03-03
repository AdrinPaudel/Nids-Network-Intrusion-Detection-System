"""
Classification Simulated Pipeline
==================================

Reads pre-generated CSV files from data/simul/ and feeds them
row-by-row into the same live classification pipeline at a
configurable rate (default 5 flows/second), simulating real-time
traffic for testing and demo purposes.

All downstream processing (Preprocessor → Classifier → ThreatHandler
→ ReportGenerator) is identical to classification_live.
"""
