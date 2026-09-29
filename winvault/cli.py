"""`winvault` — the command-line tool. Works from any terminal once installed:

    winvault baseline
    winvault compare --html report.html

The desktop app (WinVault-GUI.exe / `winvault gui`) calls the same pipeline.

Exit codes: 0 ok · 1 error · 2 usage error · 3 findings at/above --fail-on
"""

from __future__ import annotations

import argparse
import json
import os
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
LEVEL_ORDER = ["low", "medium", "high", "critical"]
EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 3

EXAMPLES = r"""
examples:
  winvault baseline --label "clean"          capture a known-good state
  winvault compare                           what changed since the latest baseline?
  winvault compare --timeline --html r.html  ...with a timeline and an HTML report
  winvault compare --fail-on high            exit code 3 if anything is High or Critical
  winvault diff 2026093 2026100              compare two stored snapshots (id prefixes)
  winvault list                              stored snapshots
  winvault status                            store, elevation and audit settings at a glance
  winvault audit --enable                    one time: turn on evidence auditing (admin)
  winvault install                           put winvault.exe on PATH (standalone .exe)

Run from an Administrator terminal for complete results.
"""


# ---- colours ------------------------------------------------------------------

class Style:
    """ANSI colours when writing to a terminal; off for pipes/files, NO_COLOR or --no-color."""

    enabled = False
    LEVEL = {"critical": "1;91", "high": "91", "medium": "93", "low": "96", "noise": "2"}
    CONF = {"high": "92", "medium": "93", "low": "96", "none": "2"}

    @classmethod
    def setup(cls, no_color: bool = False) -> None:
        cls.enabled = (not no_color and not os.environ.get("NO_COLOR")
                       and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())
        if cls.enabled and os.name == "nt":
            cls.enabled = _enable_windows_vt()


def _enable_windows_vt() -> bool:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError):
        return False


def c(text: str, code: str | None) -> str:
    return f"\033[{code}m{text}\033[0m" if Style.enabled and code else text


def err(msg: str) -> None:
    print(c("error:", "1;91") + " " + msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(c("warning:", "93") + " " + msg, file=sys.stderr)


# ---- output -------------------------------------------------------------------

def print_attribution(change) -> None:
    a = change.attribution
    if not a:
        return
    proc = a.get("process") or {}
    who = a.get("user") or c("undetermined", "2")
    what = proc.get("image") or c("undetermined", "2")
    when = local_time(a.get("when")) if a.get("when") else c("undetermined", "2")
    src = c(f"  ({a['when_source']})", "2") if a.get("when_source") else ""
    print(f"        when: {when}{src}")
    print(f"        who:  {who}   process: {what}   confidence: {c(a['confidence'], Style.CONF.get(a['confidence']))}")
    if proc.get("command_line"):
        print(f"        cmd:  {_short(proc['command_line'], 110)}")
    if a["confidence"] in ("low", "none", "medium"):
        print(c(f"        note: {a['note']}", "2"))
    for ev, n in grouped_evidence(change.evidence)[:5]:
        times = f" (x{n})" if n > 1 else ""
        print(f"        evidence: [{ev['event_id']}] {_short(ev['summary'], 100)}{times}")


def print_timeline(result: ComparisonResult) -> None:
    if not result.timeline:
        return
    print(c("\nTimeline (local time)", "1"))
    print("-" * 48)
    for e in result.timeline:
        stamp = local_time(e["time"], ms=True) if e.get("time") else "(undated)              "
        marker = {"process": "PROC ", "event": "EVENT", "change": ">>>  ", "alert": "ALERT"}[e["kind"]]
        code = Style.LEVEL.get(e.get("level")) if e["kind"] == "change" else ("1;91" if e["kind"] == "alert" else "2")
        print(f"{c(stamp, '2')}  {c(marker, code)} {_short(e['text'], 110)}")


def print_result(result: ComparisonResult, stats, show: int, show_noise: bool = False,
                 timeline: bool = False) -> None:
    print(f"\n{c('Baseline:', '1')} {result.baseline_id}\n{c('Current: ', '1')} {result.current_id}\n")
    print(c(f"{'category':<10} {'added':>7} {'removed':>8} {'modified':>9} {'unchanged':>10}", "1"))
    print("-" * 48)
    for cat, s in result.summary.items():
        print(f"{cat:<10} {s.added:>7} {s.removed:>8} {s.modified:>9} {s.unchanged:>10}")
    for a in result.alerts:
        print(c(f"\n!!! ALERT {local_time(a['time'])}: {a['message']}", "1;91"))
    for w in result.warnings:
        print(c("WARNING:", "93") + f" {w}")

    lv = stats.by_level
    counts = ", ".join(c(f"{k} {lv[k]}", Style.LEVEL[k] if lv[k] else "2") for k in reversed(LEVEL_ORDER))
    print(f"\n{c(str(stats.total), '1')} changes: {stats.noise} filtered as noise, "
          f"{c(str(stats.signal), '1')} to review ({counts})")

    if not result.changes or show == 0:
        return

    shown = [ch for ch in result.changes if show_noise or not ch.noise]
    shown.sort(key=sort_key)
    print()
    for change in shown[:show]:
        tag = c(f"[{LEVEL_TAG.get(change.level, change.level)}]", Style.LEVEL.get(change.level))
        score = "     " if change.noise else f"{change.score:>3}p"
        print(f"{tag} {score} [{SYMBOL[change.status]}] {change.category:<9} {c(display_name(change), '1')}")
        if change.noise:
            print(c(f"        noise: {change.noise}", "2"))
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
        print(c(f"({stats.noise} noise change(s) hidden — use --show-noise to see them)", "2"))
    if timeline:
        print_timeline(result)


def _progress(msg: str) -> None:
    print(c(msg, "2"), file=sys.stderr)


# ---- commands -----------------------------------------------------------------

def _require_live_host() -> bool:
    if not is_windows():
        err("live collection only works on Windows. Use `winvault diff` to compare snapshot files "
            "on other systems.")
        return False
    if not is_admin():
        warn("not running as Administrator — scheduled tasks, other users' registry and the Security "
             "log will be missing. Open an Administrator terminal for complete results.")
    return True


def _capture(args, kind: str, events_since: str | None = None) -> dict | None:
    if not _require_live_host():
        return None
    store = SnapshotStore(args.store)
    snap = take_snapshot(kind, args.label, args.only, progress=_progress, events_since=events_since)
    try:
        path = store.save(snap)
    except (OSError, TimeoutError) as exc:
        err(f"could not save snapshot to {store.root}: {exc}")
        return None
    for name, col in snap["collectors"].items():
        status = f"{col['count']} items" if col["status"] == "ok" else c(f"ERROR: {col['error']}", "91")
        print(f"  {name:<10} {status}")
    ev = snap.get("events")
    if ev:
        status = f"{len(ev['events'])} events" if ev["status"] == "ok" else c(f"ERROR: {ev['errors']}", "91")
        print(f"  {'events':<10} {status}")
    print(f"\nSaved {kind} {c(snap['id'], '1')}\n  -> {path}")
    return snap


def cmd_baseline(args) -> int:
    return EXIT_OK if _capture(args, "baseline") else EXIT_ERROR


def cmd_snapshot(args) -> int:
    return EXIT_OK if _capture(args, "snapshot") else EXIT_ERROR


def cmd_compare(args) -> int:
    store = SnapshotStore(args.store)
    try:
        baseline = store.load(args.against)
    except KeyError as exc:
        err(f"{str(exc).strip(chr(39))} — create one first with: winvault baseline")
        return EXIT_ERROR
    except IntegrityError as exc:
        err(str(exc))
        return EXIT_ERROR
    since = None if args.no_events else baseline["created_utc"]
    current = _capture(args, "snapshot", events_since=since)
    if current is None:
        return EXIT_ERROR
    return _report(baseline, current, args)


def cmd_diff(args) -> int:
    store = SnapshotStore(args.store)

    def load(ref):
        return load_snapshot_file(ref) if Path(ref).is_file() else store.load(ref)

    try:
        a, b = load(args.a), load(args.b)
    except (KeyError, IntegrityError, ValueError) as exc:
        err(str(exc).strip("'"))
        return EXIT_ERROR
    return _report(a, b, args)


def _report(baseline: dict, current: dict, args) -> int:
    inv = investigate(baseline, current)
    result = inv.result
    print_result(result, inv.stats, args.show, show_noise=args.show_noise, timeline=args.timeline)
    try:
        if args.html:
            from .report import render_html, snapshot_hashes
            hashes = snapshot_hashes(SnapshotStore(args.store), baseline["id"], current["id"])
            Path(args.html).write_text(render_html(inv, hashes), encoding="utf-8")
            print(f"\nHTML report written to {args.html}  (open it and Print -> Save as PDF for a PDF)")
        if args.json:
            Path(args.json).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\nJSON report written to {args.json}")
    except OSError as exc:
        err(f"could not write report: {exc}")
        return EXIT_ERROR
    if args.fail_on:
        threshold = LEVEL_ORDER.index(args.fail_on)
        hits = [ch for ch in result.changes if not ch.noise and ch.level in LEVEL_ORDER
                and LEVEL_ORDER.index(ch.level) >= threshold]
        if hits:
            print(c(f"\n{len(hits)} finding(s) at or above '{args.fail_on}' — exit code {EXIT_FINDINGS}", "1;91"),
                  file=sys.stderr)
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_list(args) -> int:
    store = SnapshotStore(args.store)
    entries = store.list()
    if not entries:
        print(f"No snapshots in {store.root} — create one with: winvault baseline")
        return EXIT_OK
    print(c(f"Store: {store.root}\n", "2"))
    print(c(f"{'CREATED (local)':<20} {'KIND':<9} {'HOST':<16} {'LABEL':<16} ID", "1"))
    for e in entries:
        print(f"{local_time(e['created_utc']):<20} {e['kind']:<9} {(e.get('hostname') or '')[:16]:<16} "
              f"{(e.get('label') or '')[:16]:<16} {e['id']}")
    return EXIT_OK


def cmd_verify(args) -> int:
    store = SnapshotStore(args.store)
    bad = 0
    for e in store.list():
        ok = store.verify(e["id"])
        bad += not ok
        print(f"{c('OK      ', '92') if ok else c('TAMPERED', '1;91')} {e['id']}")
    return EXIT_ERROR if bad else EXIT_OK


def cmd_status(args) -> int:
    store = SnapshotStore(args.store)
    entries = store.list() if store.index_path.exists() else []
    baselines = [e for e in entries if e["kind"] == "baseline"]
    print(c(f"WinVault {__version__}", "1"))
    print(f"  store        {store.root}")
    print(f"  snapshots    {len(entries)}  (baselines: {len(baselines)})")
    if baselines:
        print(f"  latest base  {local_time(baselines[-1]['created_utc'])}  {baselines[-1]['id']}")
    else:
        print(f"  latest base  {c('none — run: winvault baseline', '93')}")
    if is_windows():
        print(f"  elevated     {c('yes', '92') if is_admin() else c('no — open an Administrator terminal', '93')}")
        if is_admin():
            from .auditing import is_fully_enabled
            from .auditing import status as audit_status
            try:
                ok = is_fully_enabled(audit_status())
                print(f"  auditing     {c('fully enabled', '92') if ok else c('partly off — run: winvault audit', '93')}")
            except Exception as exc:  # status is informational only
                print(f"  auditing     unknown ({exc})")
    return EXIT_OK


def cmd_audit(args) -> int:
    from .auditing import enable, is_fully_enabled, status
    from .collectors.base import CollectorError
    if not is_windows():
        err("audit settings are only available on Windows")
        return EXIT_ERROR
    if args.enable and not is_admin():
        err("enabling auditing needs an Administrator terminal")
        return EXIT_ERROR
    try:
        items = enable() if args.enable else status()
    except CollectorError as exc:
        err(str(exc))
        return EXIT_ERROR
    mark = {True: c("on ", "92"), False: c("OFF", "91"), None: c("?  ", "93")}
    for i in items:
        print(f"  [{mark[i.enabled]}] {i.name:<32} {c(i.detail, '2')}")
    if is_fully_enabled(items):
        print(c("\nAll evidence sources are enabled.", "92"))
        return EXIT_OK
    print("\nSome evidence sources are off — WinVault still works, but who/which-process answers "
          "will be limited.\nRun `winvault audit --enable` from an Administrator terminal to turn them on.")
    return EXIT_OK if not args.enable else EXIT_ERROR


def cmd_install(args) -> int:
    from .install import install
    try:
        target, system_wide = install(Path(args.dir) if args.dir else None)
    except (RuntimeError, OSError) as exc:
        err(str(exc))
        return EXIT_ERROR
    scope = "all users (system PATH)" if system_wide else "your account (user PATH)"
    print(c(f"Installed to {target}", "92") + f" and added to PATH for {scope}.")
    print("Open a NEW terminal and run:  winvault --help")
    return EXIT_OK


def cmd_uninstall(args) -> int:
    from .install import uninstall
    try:
        folders = uninstall()
    except (RuntimeError, OSError) as exc:
        err(str(exc))
        return EXIT_ERROR
    for f in folders:
        print(f"Removed {f} from PATH")
    print("Snapshots in the store were kept. If winvault.exe is still in that folder (it was running), "
          "delete it by hand.")
    return EXIT_OK


def cmd_gui(args) -> int:
    import importlib.util
    if importlib.util.find_spec("PySide6") is None:
        err("the desktop app isn't part of this build — download WinVault-GUI.exe from the release, "
            "or install from source with: pip install \".[gui]\"")
        return EXIT_ERROR
    from .gui import main as gui_main
    return gui_main(store=args.store)


# ---- parser -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="winvault", description=f"{PROJECT_NAME} — what changed, does it matter, "
                                "who did it, and the evidence.", epilog=EXAMPLES,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"WinVault {__version__}")
    p.add_argument("--store", help="snapshot store directory (default: %%ProgramData%%\\WinVault or $WINVAULT_STORE)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output (also: NO_COLOR=1)")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def capture_opts(sp):
        sp.add_argument("--label", help="free-text label saved with the snapshot")
        sp.add_argument("--only", type=lambda s: s.split(","), metavar="LIST",
                        help=f"comma-separated collectors ({','.join(ALL_COLLECTORS)})")

    def report_opts(sp):
        sp.add_argument("--show", type=int, default=50, help="max findings to print (default 50)")
        sp.add_argument("--show-noise", action="store_true", help="also show changes filtered as noise")
        sp.add_argument("--timeline", action="store_true", help="print a chronological timeline of the evidence")
        sp.add_argument("--json", metavar="FILE", help="write the full result as JSON")
        sp.add_argument("--html", metavar="FILE", help="write a self-contained HTML report (print it to PDF)")
        sp.add_argument("--fail-on", choices=LEVEL_ORDER, metavar="LEVEL",
                        help="exit with code 3 if any finding is at or above LEVEL (low/medium/high/critical)")

    sp = sub.add_parser("baseline", help="capture a baseline (known-good state)")
    capture_opts(sp)
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("compare", help="capture now and compare against the latest baseline")
    capture_opts(sp)
    report_opts(sp)
    sp.add_argument("--against", default="latest-baseline", help="baseline id/prefix (default: latest baseline)")
    sp.add_argument("--no-events", action="store_true", help="skip Event Log collection and correlation")
    sp.set_defaults(func=cmd_compare)

    sp = sub.add_parser("diff", help="compare two stored snapshots or snapshot files (works offline)")
    sp.add_argument("a", help="older snapshot: id, id prefix, or path to .json")
    sp.add_argument("b", help="newer snapshot: id, id prefix, or path to .json")
    report_opts(sp)
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("snapshot", help="capture a snapshot without comparing")
    capture_opts(sp)
    sp.set_defaults(func=cmd_snapshot)

    sub.add_parser("list", help="list stored snapshots").set_defaults(func=cmd_list)
    sub.add_parser("verify", help="re-check every stored snapshot's SHA-256").set_defaults(func=cmd_verify)
    sub.add_parser("status", help="store, elevation and audit settings at a glance").set_defaults(func=cmd_status)

    sp = sub.add_parser("audit", help="show or enable the Windows audit settings WinVault uses as evidence")
    sp.add_argument("--enable", action="store_true", help="turn on all required audit settings (Administrator)")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("install", help="put the standalone winvault.exe on PATH")
    sp.add_argument("--dir", help="install folder (default: Program Files as admin, else your user folder)")
    sp.set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="remove winvault.exe from PATH (keeps snapshots)").set_defaults(func=cmd_uninstall)

    sub.add_parser("gui", help="open the desktop app").set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    Style.setup(args.no_color)
    if not args.command:
        parser.print_help()
        return EXIT_OK
    if getattr(args, "only", None):
        unknown = [x for x in args.only if x not in ALL_COLLECTORS]
        if unknown:
            err(f"unknown collector(s): {', '.join(unknown)} (choose from {', '.join(ALL_COLLECTORS)})")
            return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
