"""Comparison Engine: pair up objects across two snapshots and classify
each as added / removed / modified / unchanged.

Fields whose name begins with ``_`` are metadata and never count as a
modification (see collectors/base.py).
"""

from __future__ import annotations

from .models import CategorySummary, Change, ChangeStatus, ComparisonResult, FieldChange


def _significant(item: dict) -> dict:
    return {k: v for k, v in item.items() if not k.startswith("_")}


def diff_fields(before: dict, after: dict) -> list[FieldChange]:
    b, a = _significant(before), _significant(after)
    changes = []
    for name in sorted(set(b) | set(a)):
        if b.get(name) != a.get(name):
            changes.append(FieldChange(name, b.get(name), a.get(name)))
    return changes


def compare_items(category: str, before: dict[str, dict], after: dict[str, dict]):
    summary = CategorySummary()
    changes: list[Change] = []
    for key in sorted(set(before) | set(after)):
        if key not in before:
            summary.added += 1
            changes.append(Change(category, key, ChangeStatus.ADDED, None, after[key]))
        elif key not in after:
            summary.removed += 1
            changes.append(Change(category, key, ChangeStatus.REMOVED, before[key], None))
        else:
            fields = diff_fields(before[key], after[key])
            if fields:
                summary.modified += 1
                changes.append(Change(category, key, ChangeStatus.MODIFIED, before[key], after[key], fields))
            else:
                summary.unchanged += 1
    return summary, changes


def compare_snapshots(baseline: dict, current: dict) -> ComparisonResult:
    result = ComparisonResult(baseline_id=baseline["id"], current_id=current["id"])

    if baseline["host"].get("hostname") != current["host"].get("hostname"):
        result.warnings.append(
            f"snapshots come from different hosts ({baseline['host'].get('hostname')} vs "
            f"{current['host'].get('hostname')})"
        )
    if baseline["host"].get("elevated") != current["host"].get("elevated"):
        result.warnings.append("one snapshot was taken elevated and the other was not — "
                               "visibility differs, expect false added/removed items")

    b_cols, c_cols = baseline["collectors"], current["collectors"]
    for category in [c for c in b_cols if c in c_cols] + [c for c in c_cols if c not in b_cols]:
        b, c = b_cols.get(category), c_cols.get(category)
        if b is None or c is None:
            result.warnings.append(f"collector '{category}' only present in one snapshot — skipped")
            continue
        if b["status"] != "ok" or c["status"] != "ok":
            errs = "; ".join(x.get("error", "") for x in (b, c) if x["status"] != "ok")
            result.warnings.append(f"collector '{category}' failed in one snapshot — skipped ({errs})")
            continue
        summary, changes = compare_items(category, b["items"], c["items"])
        result.summary[category] = summary
        result.changes.extend(changes)
    return result
