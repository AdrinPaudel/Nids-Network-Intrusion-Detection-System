"""
Threat Handler (Simulated)
==========================
Re-exports the live ThreatHandler — the simulated pipeline has
zero functional differences in threat handling.
"""

from classification.classification_live.threat_handler import ThreatHandler

__all__ = ["ThreatHandler"]
