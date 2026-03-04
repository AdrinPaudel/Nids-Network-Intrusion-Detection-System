"""
Classifier (Simulated)
=======================
Re-exports the live Classifier — the simulated pipeline uses
identical classification logic (including batch-mode guards).
"""

from classification.classification_live.classifier import Classifier

__all__ = ["Classifier"]
