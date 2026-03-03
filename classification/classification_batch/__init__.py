"""
Classification Batch Package for NIDS
Fast vectorized batch classification pipeline.

Components:
    source.BatchSource              → Load CSV data
    preprocessor.BatchPreprocessor  → Vectorized preprocessing (matches training pipeline)
    classifier.BatchClassifier      → Vectorized classification with top-3 predictions
    report.BatchReportGenerator     → Batch report generation

Orchestration is handled by classification.py in the project root.
"""
