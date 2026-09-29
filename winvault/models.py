"""Core data structures shared by the snapshot and comparison layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChangeStatus(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class FieldChange:
    name: str
    before: Any
    after: Any

    def to_dict(self) -> dict:
        return {"field": self.name, "before": self.before, "after": self.after}


@dataclass
class Change:
    """One difference between two snapshots for a single collected object."""

    category: str
    key: str
    status: ChangeStatus
    before: dict | None = None
    after: dict | None = None
    fields: list[FieldChange] = field(default_factory=list)
    # Filled in by the analysis pipeline (Phase 2)
    noise: str | None = None          # reason this is expected Windows activity
    score: int = 0
    level: str = "low"
    reasons: list[str] = field(default_factory=list)
    # Filled in by the correlation engine (Phase 3)
    evidence: list[dict] = field(default_factory=list)
    attribution: dict | None = None

    @property
    def item(self) -> dict:
        """The most relevant view of the object (after for added/modified, before for removed)."""
        return self.after if self.after is not None else (self.before or {})

    def field_names(self) -> set[str]:
        return {f.name for f in self.fields}

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "key": self.key,
            "status": self.status.value,
            "before": self.before,
            "after": self.after,
            "fields": [f.to_dict() for f in self.fields],
            "analysis": {
                "noise": self.noise,
                "score": self.score,
                "level": self.level,
                "reasons": self.reasons,
            },
            "correlation": {
                "attribution": self.attribution,
                "evidence": self.evidence,
            },
        }


@dataclass
class CategorySummary:
    added: int = 0
    removed: int = 0
    modified: int = 0
    unchanged: int = 0

    @property
    def total_changes(self) -> int:
        return self.added + self.removed + self.modified

    def to_dict(self) -> dict:
        return {
            "added": self.added,
            "removed": self.removed,
            "modified": self.modified,
            "unchanged": self.unchanged,
        }


@dataclass
class ComparisonResult:
    baseline_id: str
    current_id: str
    summary: dict[str, CategorySummary] = field(default_factory=dict)
    changes: list[Change] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)       # e.g. audit log cleared
    timeline: list[dict] = field(default_factory=list)
    event_window: dict | None = None

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    def to_dict(self) -> dict:
        return {
            "format": "winvault-comparison/1",
            "baseline_id": self.baseline_id,
            "current_id": self.current_id,
            "total_changes": self.total_changes,
            "summary": {k: v.to_dict() for k, v in self.summary.items()},
            "warnings": self.warnings,
            "alerts": self.alerts,
            "event_window": self.event_window,
            "timeline": self.timeline,
            "changes": [c.to_dict() for c in self.changes],
        }
