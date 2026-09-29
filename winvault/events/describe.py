"""One-line human summaries and actor extraction for the events WinVault reads."""

from __future__ import annotations

WELL_KNOWN_SIDS = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}


def _d(ev: dict, key: str) -> str:
    value = (ev.get("data") or {}).get(key) or ""
    return "" if value == "-" else value


def _who(ev: dict) -> str:
    user, dom = _d(ev, "SubjectUserName"), _d(ev, "SubjectDomainName")
    return f"{dom}\\{user}" if dom and user else user or "?"


def summarize(ev: dict, sid_names: dict[str, str] | None = None) -> str:
    i = ev.get("event_id")
    sid_names = sid_names or {}
    msid = _d(ev, "MemberSid")
    member = _d(ev, "MemberName") or sid_names.get(msid) or msid
    table = {
        4720: lambda: f"user account created: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4722: lambda: f"user account enabled: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4724: lambda: f"password reset: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4725: lambda: f"user account disabled: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4726: lambda: f"user account deleted: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4738: lambda: f"user account changed: {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4732: lambda: f"{member} added to group {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4733: lambda: f"{member} removed from group {_d(ev, 'TargetUserName')} (by {_who(ev)})",
        4697: lambda: f"service installed: {_d(ev, 'ServiceName')} -> {_d(ev, 'ServiceFileName')} (by {_who(ev)})",
        4698: lambda: f"scheduled task created: {_d(ev, 'TaskName')} (by {_who(ev)})",
        4699: lambda: f"scheduled task deleted: {_d(ev, 'TaskName')} (by {_who(ev)})",
        4702: lambda: f"scheduled task updated: {_d(ev, 'TaskName')} (by {_who(ev)})",
        4688: lambda: f"process started: {_d(ev, 'CommandLine') or _d(ev, 'NewProcessName')} (by {_who(ev)})",
        1102: lambda: f"SECURITY LOG CLEARED (by {_who(ev) if _d(ev, 'SubjectUserName') else ev.get('user_sid') or '?'})",
        104: lambda: f"event log cleared: {_d(ev, 'Channel') or 'System'}",
        7045: lambda: f"service installed: {_d(ev, 'ServiceName')} -> {_d(ev, 'ImagePath')} (account {_d(ev, 'AccountName')})",
        7040: lambda: f"service start type changed: {_d(ev, 'param1')} {_d(ev, 'param2')} -> {_d(ev, 'param3')}",
        106: lambda: f"task registered: {_d(ev, 'TaskName')} (by {_d(ev, 'UserContext')})",
        140: lambda: f"task updated: {_d(ev, 'TaskName')} (by {_d(ev, 'UserName')})",
        141: lambda: f"task deleted: {_d(ev, 'TaskName')} (by {_d(ev, 'UserName')})",
    }
    fn = table.get(i)
    return fn() if fn else f"event {i}"


def actor_of(ev: dict, sid_names: dict[str, str] | None = None) -> dict:
    """Who performed the action recorded by this event, as far as the event says."""
    sid_names = sid_names or {}
    if _d(ev, "SubjectUserName"):
        return {"user": _who(ev), "sid": _d(ev, "SubjectUserSid") or None,
                "logon_id": _d(ev, "SubjectLogonId") or None}
    if ev.get("event_id") == 106 and _d(ev, "UserContext"):
        return {"user": _d(ev, "UserContext"), "sid": None, "logon_id": None}
    if ev.get("event_id") in (140, 141) and _d(ev, "UserName"):
        return {"user": _d(ev, "UserName"), "sid": None, "logon_id": None}
    sid = ev.get("user_sid")
    if sid:
        return {"user": WELL_KNOWN_SIDS.get(sid) or sid_names.get(sid) or sid, "sid": sid, "logon_id": None}
    return {"user": None, "sid": None, "logon_id": None}
