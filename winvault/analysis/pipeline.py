"""Tie the noise filter and scoring rules together over a ComparisonResult."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ComparisonResult
from .noise import classify_noise
from .rules import level_for, score_change


@dataclass
class AnalysisStats:
    total: int = 0
    noise: int = 0
    by_level: dict[str, int] = field(default_factory=lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0})

    @property
    def signal(self) -> int:
        return self.total - self.noise

    def to_dict(self) -> dict:
        return {"total": self.total, "noise": self.noise, "signal": self.signal, "by_level": self.by_level}


def analyze(result: ComparisonResult) -> AnalysisStats:
    """Annotate every Change with noise/score/level in place; return summary stats."""
    stats = AnalysisStats(total=len(result.changes))
    for change in result.changes:
        change.noise = classify_noise(change)
        if change.noise:
            stats.noise += 1
            change.score, change.level, change.reasons = 0, "noise", []
            continue
        change.score, change.reasons = score_change(change)
        change.level = level_for(change.score)
        stats.by_level[change.level] += 1
    return stats


def sort_key(change):
    """Most interesting first: by score desc, then category, then key."""
    return (-change.score, change.category, change.key)
