"""Shared entry points used by both the CLI and the GUI.

Keeping the pipeline in one place guarantees the GUI shows exactly what the
CLI prints and what the JSON report contains:

    capture -> compare -> analyze (noise + scoring) -> correlate (evidence)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analysis import AnalysisStats, analyze
from .compare import compare_snapshots
from .correlation import correlate
from .models import ComparisonResult
from .snapshot import SnapshotStore, load_snapshot_file, take_snapshot


@dataclass
class Investigation:
    result: ComparisonResult
    stats: AnalysisStats
    baseline: dict
    current: dict


def investigate(baseline: dict, current: dict) -> Investigation:
    """Run the full analysis pipeline on two snapshots."""
    result = compare_snapshots(baseline, current)
    stats = analyze(result)
    correlate(result, current, baseline)
    return Investigation(result, stats, baseline, current)


def capture(store: SnapshotStore, kind: str, label: str | None = None, only: list[str] | None = None,
            progress=None, events_since: str | None = None) -> tuple[dict, Path]:
    snap = take_snapshot(kind, label, only, progress=progress, events_since=events_since)
    path = store.save(snap)
    return snap, path


def compare_live(store: SnapshotStore, against: str = "latest-baseline", only: list[str] | None = None,
                 events: bool = True, label: str | None = None, progress=None) -> Investigation:
    """Capture the system now and investigate it against a stored baseline."""
    baseline = store.load(against)
    current, _ = capture(store, "snapshot", label, only, progress,
                         events_since=baseline["created_utc"] if events else None)
    return investigate(baseline, current)


def load_ref(store: SnapshotStore, ref: str) -> dict:
    """A snapshot id / prefix from the store, or a path to a snapshot .json file."""
    return load_snapshot_file(ref) if Path(ref).is_file() else store.load(ref)
