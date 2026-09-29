"""Command-line interface. The PySide6 GUI (Phase 4) calls the same functions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import PROJECT_NAME, __version__
from .analysis.pipeline import sort_key
from .collectors import ALL_COLLECTORS
from .collectors.base import is_admin, is_windows
from .models import ChangeStatus, ComparisonResult
from .presentation import describe_field, display_name, grouped_evidence, local_time  # noqa: F401 (re-exported)
from .presentation import short as _short
from .service import investigate
from .snapshot import IntegrityError, SnapshotStore, load_snapshot_file, take_snapshot

SYMBOL = {ChangeStatus.ADDED: "+", ChangeStatus.REMOVED: "-", ChangeStatus.MODIFIED: "~"}
LEVEL_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "low ", "noise": "noise"}


def print_attribution(change) -> None:
    a = change.attribution
    if not a:
        return
    proc = a.get("process") or {}
    who = a.get("user") or "undetermined"
    what = proc.get("image") or "undetermined"
    print(f"        when: {local_time(a.get('when')) if a.get('when') else 'undetermined'}"
          f"{'  (' + a['when_source'] + ')' if a.get('when_source') else ''}")
    print(f"        who:  {who}   process: {what}   confidence: {a['confidence']}")
    if proc.get("command_line"):
        print(f"        cmd:  {_short(proc['command_line'], 110)}")
    if a["confidence"] in ("low", "none", "medium"):
        print(f"        note: {a['note']}")
    for ev, n in grouped_evidence(change.evidence)[:5]:
        times = f" (x{n})" if n > 1 else ""
        print(f"        evidence: [{ev['event_id']}] {_short(ev['summary'], 100)}{times}")


def print_timeline(result: ComparisonResult) -> None:
    if not result.timeline:
        return
    print("\nTimeline (local time)")
    print("-" * 48)
    for e in result.timeline:
        stamp = local_time(e["time"], ms=True) if e.get("time") else "(undated)              "
        marker = {"process": "PROC ", "event": "EVENT", "change": ">>>  ", "alert": "ALERT"}[e["kind"]]
        print(f"{stamp}  {marker} {_short(e['text'], 110)}")


def print_result(result: ComparisonResult, stats, show: int, show_noise: bool = False,
                 timeline: bool = False) -> None:
    print(f"\nBaseline: {result.baseline_id}\nCurrent:  {result.current_id}\n")
    print(f"{'category':<10} {'added':>7} {'removed':>8} {'modified':>9} {'unchanged':>10}")
    print("-" * 48)
    for cat, s in result.summary.items():
        print(f"{cat:<10} {s.added:>7} {s.removed:>8} {s.modified:>9} {s.unchanged:>10}")
    for a in result.alerts:
        print(f"\n!!! ALERT {local_time(a['time'])}: {a['message']}")
    for w in result.warnings:
        print(f"WARNING: {w}")

    lv = stats.by_level
    print(f"\n{stats.total} changes: {stats.noise} filtered as noise, {stats.signal} to review "
          f"(critical {lv['critical']}, high {lv['high']}, medium {lv['medium']}, low {lv['low']})")

    if not result.changes or show == 0:
        return

    shown = [c for c in result.changes if show_noise or not c.noise]
    shown.sort(key=sort_key)
    print()
    for change in shown[:show]:
        tag = LEVEL_TAG.get(change.level, change.level)
        score = "     " if change.noise else f"{change.score:>3}p"
        print(f"[{tag}] {score} [{SYMBOL[change.status]}] {change.category:<9} {display_name(change)}")
        if change.noise:
            print(f"        noise: {change.noise}")
        for r in change.reasons:
            print(f"        {r}")
        if change.status is ChangeStatus.MODIFIED:
            for f in change.fields:
                for line in describe_field(f):
                    print(f"        {line}")
        print_attribution(change)
    hidden = len(shown) - min(len(shown), show)
    if hidden > 0:
        print(f"\n... {hidden} more (use --show N or --json FILE)")
    if stats.noise and not show_noise:
        print(f"({stats.noise} noise change(s) hidden — use --show-noise to see them)")
    if timeline:
        print_timeline(result)


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


def _capture(args, kind: str, events_since: str | None = None) -> dict | None:
    if not _require_live_host():
        return None
    store = SnapshotStore(args.store)
    snap = take_snapshot(kind, args.label, args.only, progress=_progress, events_since=events_since)
    path = store.save(snap)
    for name, col in snap["collectors"].items():
        status = f"{col['count']} items" if col["status"] == "ok" else f"ERROR: {col['error']}"
        print(f"  {name:<10} {status}")
    ev = snap.get("events")
    if ev:
        status = f"{len(ev['events'])} events" if ev["status"] == "ok" else f"ERROR: {ev['errors']}"
        print(f"  {'events':<10} {status}")
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
    since = None if args.no_events else baseline["created_utc"]
    current = _capture(args, "snapshot", events_since=since)
    if current is None:
        return 1
    return _report(baseline, current, args)


def cmd_diff(args) -> int:
    store = SnapshotStore(args.store)

    def load(ref):
        return load_snapshot_file(ref) if Path(ref).is_file() else store.load(ref)

    try:
        a, b = load(args.a), load(args.b)
    except (KeyError, IntegrityError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return _report(a, b, args)


def _report(baseline: dict, current: dict, args) -> int:
    inv = investigate(baseline, current)
    result = inv.result
    print_result(result, inv.stats, args.show, show_noise=args.show_noise, timeline=args.timeline)
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
        sp.add_argument("--show-noise", action="store_true", help="also show changes filtered as noise")
        sp.add_argument("--timeline", action="store_true", help="print a chronological timeline of the evidence")
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
    sp.add_argument("--no-events", action="store_true", help="skip Event Log collection and correlation")
    sp.set_defaults(func=cmd_compare)

    sp = sub.add_parser("diff", help="compare two stored snapshots or snapshot files (works offline)")
    sp.add_argument("a", help="older snapshot: id, prefix, or path to .json")
    sp.add_argument("b", help="newer snapshot: id, prefix, or path to .json")
    report_opts(sp)
    sp.set_defaults(func=cmd_diff)

    sub.add_parser("list", help="list stored snapshots").set_defaults(func=cmd_list)
    sub.add_parser("verify", help="re-hash every stored snapshot").set_defaults(func=cmd_verify)
    sub.add_parser("gui", help="open the desktop app (needs: pip install winvault[gui])").set_defaults(func=cmd_gui)
    return p


def cmd_gui(args) -> int:
    try:
        from .gui import main as gui_main
    except ImportError as exc:
        print(f"error: the GUI needs PySide6 — run: pip install -e \".[gui]\"  ({exc})", file=sys.stderr)
        return 1
    return gui_main(store=args.store)


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
