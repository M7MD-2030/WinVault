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

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "key": self.key,
            "status": self.status.value,
            "before": self.before,
            "after": self.after,
            "fields": [f.to_dict() for f in self.fields],
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
            "changes": [c.to_dict() for c in self.changes],
        }
