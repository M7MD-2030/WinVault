"""Command-line interface (Phase 1). The PySide6 GUI arrives in Phase 4 and
will call the same functions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import PROJECT_NAME, __version__
from .collectors import ALL_COLLECTORS
from .collectors.base import is_admin, is_windows
from .compare import compare_snapshots
from .models import ChangeStatus, ComparisonResult
from .snapshot import IntegrityError, SnapshotStore, load_snapshot_file, take_snapshot

SYMBOL = {ChangeStatus.ADDED: "+", ChangeStatus.REMOVED: "-", ChangeStatus.MODIFIED: "~"}


def _short(value, width: int = 90) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= width else text[: width - 3] + "..."


def display_name(change) -> str:
    """Human-friendly label: users/groups show their name, not just the SID."""
    item = change.after or change.before or {}
    if change.category == "users" and item.get("name"):
        return f"{item.get('kind', 'user')} {item['name']}  ({item.get('sid', change.key)})"
    return change.key


def describe_field(f) -> list[str]:
    """For list fields (e.g. group members) show only what was added/removed."""
    if isinstance(f.before, list) and isinstance(f.after, list):
        added = [x for x in f.after if x not in f.before]
        removed = [x for x in f.before if x not in f.after]
        lines = [f"{f.name}: + {x}" for x in added] + [f"{f.name}: - {x}" for x in removed]
        return lines or [f"{f.name}: order changed"]
    return [f"{f.name}: {_short(f.before)}  ->  {_short(f.after)}"]


def print_result(result: ComparisonResult, show: int) -> None:
    print(f"\nBaseline: {result.baseline_id}\nCurrent:  {result.current_id}\n")
    print(f"{'category':<10} {'added':>7} {'removed':>8} {'modified':>9} {'unchanged':>10}")
    print("-" * 48)
    for cat, s in result.summary.items():
        print(f"{cat:<10} {s.added:>7} {s.removed:>8} {s.modified:>9} {s.unchanged:>10}")
    print(f"\nTotal changes: {result.total_changes}")
    for w in result.warnings:
        print(f"WARNING: {w}")

    if not result.changes or show == 0:
        return
    print()
    for change in result.changes[:show]:
        print(f"[{SYMBOL[change.status]}] {change.category:<9} {display_name(change)}")
        if change.status is ChangeStatus.MODIFIED:
            for f in change.fields:
                for line in describe_field(f):
                    print(f"      {line}")
    if len(result.changes) > show:
        print(f"\n... {len(result.changes) - show} more (use --show N or --json FILE)")


def _progress(msg: str) -> None:
    print(msg, file=sys.stderr)


def _require_live_host() -> bool:
    if not is_windows():
        print("error: live collection only works on Windows. Use `winvault diff` to compare "
              "snapshot files on other systems.", file=sys.stderr)
        return False
    if not is_admin():
        print("warning: not elevated — Scheduled Tasks and some registry/user data will be "
              "missing. Run from an Administrator terminal.", file=sys.stderr)
    return True


def _capture(args, kind: str) -> dict | None:
    if not _require_live_host():
        return None
    store = SnapshotStore(args.store)
    snap = take_snapshot(kind, args.label, args.only, progress=_progress)
    path = store.save(snap)
    for name, col in snap["collectors"].items():
        status = f"{col['count']} items" if col["status"] == "ok" else f"ERROR: {col['error']}"
        print(f"  {name:<10} {status}")
    print(f"\nSaved {kind} {snap['id']}\n  -> {path}")
    return snap


def cmd_baseline(args) -> int:
    return 0 if _capture(args, "baseline") else 1


def cmd_snapshot(args) -> int:
    return 0 if _capture(args, "snapshot") else 1


def cmd_compare(args) -> int:
    store = SnapshotStore(args.store)
    try:
        baseline = store.load(args.against)
    except (KeyError, IntegrityError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    current = _capture(args, "snapshot")
    if current is None:
        return 1
    return _report(compare_snapshots(baseline, current), args)


def cmd_diff(args) -> int:
    store = SnapshotStore(args.store)

    def load(ref):
        return load_snapshot_file(ref) if Path(ref).is_file() else store.load(ref)

    try:
        a, b = load(args.a), load(args.b)
    except (KeyError, IntegrityError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return _report(compare_snapshots(a, b), args)


def _report(result: ComparisonResult, args) -> int:
    print_result(result, args.show)
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")
    return 0


def cmd_list(args) -> int:
    store = SnapshotStore(args.store)
    entries = store.list()
    if not entries:
        print(f"No snapshots in {store.root}")
        return 0
    print(f"Store: {store.root}\n")
    for e in entries:
        label = f"  ({e['label']})" if e.get("label") else ""
        print(f"{e['id']:<40} {e['kind']:<9} {e['hostname']}{label}")
    return 0


def cmd_verify(args) -> int:
    store = SnapshotStore(args.store)
    bad = 0
    for e in store.list():
        ok = store.verify(e["id"])
        bad += not ok
        print(f"{'OK      ' if ok else 'TAMPERED'} {e['id']}")
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="winvault", description=PROJECT_NAME)
    p.add_argument("--version", action="version", version=f"WinVault {__version__}")
    p.add_argument("--store", help="snapshot store directory (default: %%ProgramData%%\\WinVault "
                                   "or $WINVAULT_STORE)")
    sub = p.add_subparsers(dest="command", required=True)

    def capture_opts(sp):
        sp.add_argument("--label", help="free-text label saved with the snapshot")
        sp.add_argument("--only", type=lambda s: s.split(","), metavar="LIST",
                        help=f"comma-separated collectors ({','.join(ALL_COLLECTORS)})")

    def report_opts(sp):
        sp.add_argument("--show", type=int, default=50, help="max changes to print (default 50)")
        sp.add_argument("--json", metavar="FILE", help="write the full comparison as JSON")

    sp = sub.add_parser("baseline", help="capture a new baseline")
    capture_opts(sp)
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("snapshot", help="capture a snapshot without comparing")
    capture_opts(sp)
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("compare", help="capture now and compare against a baseline")
    capture_opts(sp)
    report_opts(sp)
    sp.add_argument("--against", default="latest-baseline", help="snapshot id/prefix (default: latest baseline)")
    sp.set_defaults(func=cmd_compare)

    sp = sub.add_parser("diff", help="compare two stored snapshots or snapshot files (works offline)")
    sp.add_argument("a", help="older snapshot: id, prefix, or path to .json")
    sp.add_argument("b", help="newer snapshot: id, prefix, or path to .json")
    report_opts(sp)
    sp.set_defaults(func=cmd_diff)

    sub.add_parser("list", help="list stored snapshots").set_defaults(func=cmd_list)
    sub.add_parser("verify", help="re-hash every stored snapshot").set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "only", None):
        unknown = [c for c in args.only if c not in ALL_COLLECTORS]
        if unknown:
            print(f"error: unknown collector(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
