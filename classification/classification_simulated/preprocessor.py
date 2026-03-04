"""
Classification Preprocessor (Simulated)
========================================
Re-exports the live Preprocessor — the simulated pipeline uses
identical preprocessing logic.
"""

from classification.classification_live.preprocessor import Preprocessor

__all__ = ["Preprocessor"]
