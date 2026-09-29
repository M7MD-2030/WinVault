"""Correlation Engine: connect each detected change to Event Log evidence.

For every change that survived the noise filter we try to answer *when*, *who*
and *which process* — and we say how sure we are:

    high    an audit event names this exact object (who + when) AND a process
            command line references it (which process)
    medium  an audit event names this exact object (who + when), process unknown;
            or only a process command line references it
    low     only the artifact's own timestamp (e.g. registry key last-write time)
    none    nothing in the logs relates to it

Links are made on the *target* (SID, service name, task path, file name), never
on time proximity alone: "the last process that ran before the change" is how
tools confidently blame the wrong program. When the evidence is not there, the
report says "could not be determined".
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta  # noqa: F401  (datetime used in type hints)

from .events.describe import actor_of, summarize
from .events.reader import parse_time
from .models import Change, ChangeStatus, ComparisonResult

PROCESS_LOOKBACK = timedelta(minutes=10)
CLOCK_SLACK = timedelta(seconds=5)

NOTES = {
    "high": "audit event and process command line both reference this object",
    "medium-event": "process undetermined (done inside an already-running process, or command lines not logged)",
    "medium-process": "a process command line references this object; no dedicated audit event found",
    "low": "only the artifact's own timestamp; user and process undetermined",
    "none": "no supporting evidence in the event logs; user and process undetermined",
}


def _eq(a, b) -> bool:
    return a not in (None, "", "-") and b not in (None, "", "-") and str(a).strip().lower() == str(b).strip().lower()


def _path(p) -> str:
    return str(p or "").strip().strip('"').lower()


def _short(name: str | None) -> str:
    return re.split(r"[\\/]", name or "")[-1]


def _member_delta(change: Change) -> tuple[list[str], list[str]]:
    for f in change.fields:
        if f.name == "members" and isinstance(f.before, list) and isinstance(f.after, list):
            return [m for m in f.after if m not in f.before], [m for m in f.before if m not in f.after]
    if change.status is ChangeStatus.ADDED:
        return list(change.item.get("members") or []), []
    return [], []


class EventIndex:
    def __init__(self, events: list[dict]):
        self.events = []
        for e in events or []:
            t = parse_time(e.get("time"))
            if t:
                self.events.append({**e, "_t": t})
        self.events.sort(key=lambda e: e["_t"])

    def by_id(self, *ids: int) -> list[dict]:
        return [e for e in self.events if e["event_id"] in ids]


class Context:
    """Name <-> SID lookups built from both snapshots' user collector."""

    def __init__(self, *snapshots: dict):
        self.sid_by_name: dict[str, str] = {}
        self.name_by_sid: dict[str, str] = {}
        for snap in snapshots:
            users = ((snap or {}).get("collectors", {}).get("users") or {}).get("items") or {}
            for item in users.values():
                if item.get("kind") == "user" and item.get("sid"):
                    self.sid_by_name[item["name"].lower()] = item["sid"]
                    self.name_by_sid[item["sid"]] = item["name"]

    def sid_for(self, member: str) -> str | None:
        return self.sid_by_name.get(_short(member).lower())


# ---- target matchers: events that name this exact object ----------------------

def _match_users(change: Change, idx: EventIndex, ctx: Context) -> list[dict]:
    item = change.item
    if item.get("kind") == "group":
        out = []
        added, removed = _member_delta(change)
        for members, event_id in ((added, 4732), (removed, 4733)):
            for m in members:
                msid = ctx.sid_for(m)
                for e in idx.by_id(event_id):
                    d = e["data"]
                    if _eq(d.get("TargetSid"), item.get("sid")) and (
                            (msid and _eq(d.get("MemberSid"), msid)) or _eq(_short(d.get("MemberName")), _short(m))):
                        out.append(e)
        return out
    ids = {ChangeStatus.ADDED: (4720, 4722, 4724, 4738),
           ChangeStatus.REMOVED: (4726,),
           ChangeStatus.MODIFIED: (4722, 4724, 4725, 4738)}[change.status]
    return [e for e in idx.by_id(*ids) if _eq(e["data"].get("TargetSid"), item.get("sid"))]


def _match_services(change: Change, idx: EventIndex, ctx: Context) -> list[dict]:
    item = change.item
    name, disp, img = item.get("name"), item.get("display_name"), _path(item.get("image_path"))
    out = []
    if change.status is ChangeStatus.ADDED or "image_path" in change.field_names():
        for e in idx.by_id(7045):
            d = e["data"]
            if _eq(d.get("ServiceName"), name) or _eq(d.get("ServiceName"), disp) \
                    or (img and _path(d.get("ImagePath")) == img):
                out.append(e)
        for e in idx.by_id(4697):
            d = e["data"]
            if _eq(d.get("ServiceName"), name) or (img and _path(d.get("ServiceFileName")) == img):
                out.append(e)
    if change.status is ChangeStatus.MODIFIED and "start_type" in change.field_names():
        for e in idx.by_id(7040):
            d = e["data"]
            if _eq(d.get("param4"), name) or _eq(d.get("param1"), disp):
                out.append(e)
    return out


def _match_tasks(change: Change, idx: EventIndex, ctx: Context) -> list[dict]:
    ids = {ChangeStatus.ADDED: (4698, 106),
           ChangeStatus.MODIFIED: (4702, 140),
           ChangeStatus.REMOVED: (4699, 141)}[change.status]
    return [e for e in idx.by_id(*ids) if _eq(e["data"].get("TaskName"), change.key)]


MATCHERS = {"users": _match_users, "services": _match_services, "tasks": _match_tasks}


# ---- helpers -----------------------------------------------------------------

def _tokens(change: Change) -> list[str]:
    """Distinctive strings a process command line would contain if it made this change."""
    it = change.item
    if change.category == "registry":
        toks = [it.get("value_name")]
    elif change.category == "services":
        toks = [it.get("name")]
    elif change.category == "tasks":
        toks = [change.key.split("\\")[-1]]
    elif change.category == "startup":
        toks = [it.get("file_name")]
    elif change.category == "users":
        if it.get("kind") == "group":
            added, removed = _member_delta(change)
            toks = [_short(m) for m in added + removed]
        else:
            toks = [it.get("name")]
    else:
        toks = []
    return [t for t in toks if t and len(t) >= 4 and t != "(Default)"]


def _artifact_time(change: Change) -> tuple[datetime | None, str | None]:
    it = change.item
    for field, label in (("_key_last_write", "registry key last-write time"),
                         ("_file_modified", "task file modified time"),
                         ("_created" if change.status is ChangeStatus.ADDED else "_modified",
                          "file timestamp")):
        t = parse_time(it.get(field))
        if t:
            return t, label
    return None, None


def _find_process(idx: EventIndex, tokens: list[str], when: datetime | None, window_end: datetime | None):
    """Most recent 4688 whose command line contains one of the tokens, before `when`."""
    if not tokens:
        return None
    # Whole-word match: "WinVaultTest" must not match inside "WinVaultTestSvc".
    patterns = [re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(t) + r"(?![A-Za-z0-9_\-])", re.IGNORECASE)
                for t in tokens]
    upper = (when or window_end)
    best = None
    for e in idx.by_id(4688):
        if upper is not None:
            if e["_t"] > upper + CLOCK_SLACK or e["_t"] < upper - PROCESS_LOOKBACK:
                continue
        cmd = e["data"].get("CommandLine") or ""
        if cmd and any(p.search(cmd) for p in patterns):
            best = e  # sorted ascending -> keep the latest match
    return best


def _evidence_entry(e: dict, role: str, sid_names: dict | None = None) -> dict:
    return {"time": e.get("time"), "log": e.get("log"), "event_id": e.get("event_id"),
            "record_id": e.get("record_id"), "role": role, "summary": summarize(e, sid_names)}


def _process_info(e: dict) -> dict:
    d = e["data"]
    return {"image": d.get("NewProcessName"), "command_line": d.get("CommandLine") or None,
            "pid": d.get("NewProcessId"), "parent": d.get("ParentProcessName") or None,
            "time": e.get("time"), "user": actor_of(e).get("user")}


# ---- main entry --------------------------------------------------------------

def correlate(result: ComparisonResult, current: dict, baseline: dict | None = None) -> None:
    """Annotate result.changes with evidence/attribution; fill alerts, warnings, timeline."""
    block = (current or {}).get("events")
    if not block:
        result.warnings.append("no event-log evidence in this snapshot (captured with --no-events, "
                               "or not by `winvault compare`) — who/when/process not available")
        return
    result.event_window = {"start": block.get("window_start"), "end": block.get("window_end")}
    for name, err in (block.get("errors") or {}).items():
        result.warnings.append(f"event query '{name}' failed: {err}")
    if baseline and block.get("window_start"):
        ws, bs = parse_time(block["window_start"]), parse_time(baseline.get("created_utc"))
        if ws and bs and ws > bs + CLOCK_SLACK:
            result.warnings.append(f"event evidence only covers from {block['window_start']} — "
                                   "earlier changes cannot be attributed")

    idx = EventIndex(block.get("events") or [])
    ctx = Context(baseline, current)
    window_end = parse_time(block.get("window_end"))
    _coverage_warnings(result, idx, block)

    for e in idx.by_id(1102, 104):
        result.alerts.append({"time": e["time"], "event_id": e["event_id"], "log": e["log"],
                              "message": summarize(e)})

    for change in result.changes:
        if change.noise:
            continue
        matcher = MATCHERS.get(change.category)
        anchors = matcher(change, idx, ctx) if matcher else []
        # de-duplicate (same event can match on two keys)
        seen, uniq = set(), []
        for e in anchors:
            k = (e["log"], e["record_id"])
            if k not in seen:
                seen.add(k)
                uniq.append(e)
        anchors = sorted(uniq, key=lambda e: e["_t"])

        when, when_source, actor = None, None, None
        if anchors:
            primary = anchors[0]
            when, when_source = primary["_t"], f"event {primary['event_id']}"
            # Prefer an event that carries a full DOMAIN\user subject (e.g. 4697 over 7045).
            with_subject = next((e for e in anchors if (e["data"].get("SubjectUserName") or "-") != "-"), primary)
            actor = actor_of(with_subject, ctx.name_by_sid)
        else:
            when, when_source = _artifact_time(change)

        proc_ev = _find_process(idx, _tokens(change), when, window_end)
        if proc_ev and not actor:
            actor = actor_of(proc_ev, ctx.name_by_sid)
        if proc_ev and not anchors:
            when, when_source = proc_ev["_t"], "process creation (event 4688)"

        if anchors and proc_ev:
            confidence, note = "high", NOTES["high"]
        elif anchors:
            confidence, note = "medium", NOTES["medium-event"]
        elif proc_ev:
            confidence, note = "medium", NOTES["medium-process"]
        elif when:
            confidence, note = "low", NOTES["low"]
        else:
            confidence, note = "none", NOTES["none"]

        change.evidence = [_evidence_entry(e, "target", ctx.name_by_sid) for e in anchors]
        if proc_ev:
            change.evidence.insert(0, _evidence_entry(proc_ev, "process", ctx.name_by_sid))
        change.attribution = {
            "when": when.isoformat() if when else None,
            "when_source": when_source,
            "user": (actor or {}).get("user"),
            "logon_id": (actor or {}).get("logon_id"),
            "process": _process_info(proc_ev) if proc_ev else None,
            "confidence": confidence,
            "note": note,
        }

    result.timeline = build_timeline(result)


def _coverage_warnings(result: ComparisonResult, idx: EventIndex, block: dict) -> None:
    procs = idx.by_id(4688)
    if not procs:
        result.warnings.append("no process-creation events (4688) in the window — process auditing is "
                               "probably off; run scripts\\Enable-WinVaultAuditing.ps1")
    elif not any(e["data"].get("CommandLine") for e in procs):
        result.warnings.append("process events have no command lines — enable command-line logging "
                               "with scripts\\Enable-WinVaultAuditing.ps1")
    if block.get("task_log_enabled") is False:
        result.warnings.append("Task Scheduler operational log is disabled — task attribution relies on "
                               "Security 4698 only")


def build_timeline(result: ComparisonResult) -> list[dict]:
    """Chronological view of every signal change with its evidence and alerts."""
    entries, seen = [], set()
    for change in result.changes:
        if change.noise or not change.attribution:
            continue
        for ev in change.evidence:
            k = (ev["log"], ev["record_id"])
            if k in seen:
                continue
            seen.add(k)
            entries.append({"time": ev["time"], "kind": "process" if ev["role"] == "process" else "event",
                            "text": f"[{ev['event_id']}] {ev['summary']}", "change": change.key})
        when = change.attribution.get("when")
        entries.append({"time": when, "kind": "change", "level": change.level,
                        "text": f"{change.level.upper()} {change.status.value} {change.category}: "
                                f"{change.item.get('name') or change.key}",
                        "change": change.key,
                        "undated": when is None})
    for a in result.alerts:
        entries.append({"time": a["time"], "kind": "alert", "text": a["message"], "change": None})

    dated = sorted((e for e in entries if e.get("time")), key=lambda e: (parse_time(e["time"]),
                                                                         {"process": 0, "event": 1,
                                                                          "change": 2, "alert": 1}[e["kind"]]))
    undated = [e for e in entries if not e.get("time")]
    return dated + undated
