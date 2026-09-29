"""Phase 2 analysis pipeline: noise filtering + rule-based risk scoring.

    from winvault.analysis import analyze
    analyze(comparison_result)   # annotates each Change in place, returns stats
"""

from .pipeline import AnalysisStats, analyze

__all__ = ["analyze", "AnalysisStats"]
