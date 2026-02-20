"""
Classification Batch Package for NIDS
Fast vectorized batch classification pipeline.

Pattern mirrors classification/ but uses vectorized ops for speed.
Components:
    BatchSource         → Load CSV data
    BatchPreprocessor   → Vectorized preprocessing (matches training pipeline)
    BatchClassifier     → Vectorized classification with top-3 predictions
    BatchReportGenerator → Batch report generation
    run_batch_classification → Main orchestrator
"""
