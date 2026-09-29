"""Correlation tests built around the exact sequence Test-WinVaultChanges.ps1
produces: registry value, sc.exe service, task, user + admin group, startup file."""

from winvault.analysis import analyze
from winvault.compare import compare_snapshots
from winvault.correlation import correlate

T0 = "2026-09-30T02:42:00+00:00"          # baseline created


def t(sec: int) -> str:
    return f"2026-09-30T02:42:{sec:02d}.0000000Z"


ANALYST = {"SubjectUserName": "analyst", "SubjectDomainName": "PC", "SubjectUserSid": "S-1-5-21-1-1001",
           "SubjectLogonId": "0x3e7a1"}

EVENTS = [
    # the interactive powershell that ran winvault / the script (no tokens in its command line)
    {"log": "Security", "event_id": 4688, "record_id": 1, "time": t(1),
     "data": {**ANALYST, "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "CommandLine": "powershell.exe -NoProfile", "ParentProcessName": "C:\\Windows\\explorer.exe"}},
    {"log": "Security", "event_id": 4688, "record_id": 2, "time": t(3),
     "data": {**ANALYST, "NewProcessName": "C:\\Windows\\System32\\sc.exe",
              "CommandLine": 'sc.exe create WinVaultTestSvc binPath= "C:\\Windows\\System32\\notepad.exe" start= demand',
              "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "NewProcessId": "0x1a2b"}},
    {"log": "System", "event_id": 7045, "record_id": 3, "time": t(3), "user_sid": "S-1-5-21-1-1001",
     "data": {"ServiceName": "WinVault Test Service", "ImagePath": '"C:\\Windows\\System32\\notepad.exe"',
              "AccountName": "LocalSystem"}},
    {"log": "Security", "event_id": 4698, "record_id": 4, "time": t(4),
     "data": {**ANALYST, "TaskName": "\\WinVaultTest"}},
    {"log": "Security", "event_id": 4720, "record_id": 5, "time": t(5),
     "data": {**ANALYST, "TargetUserName": "wv_testuser", "TargetSid": "S-1-5-21-1-1007"}},
    {"log": "Security", "event_id": 4722, "record_id": 6, "time": t(5),
     "data": {**ANALYST, "TargetUserName": "wv_testuser", "TargetSid": "S-1-5-21-1-1007"}},
    {"log": "Security", "event_id": 4732, "record_id": 7, "time": t(6),
     "data": {**ANALYST, "MemberName": "-", "MemberSid": "S-1-5-21-1-1007",
              "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544"}},
]


def snaps(events=EVENTS, extra_events_block=None):
    base_users = {"user:S-1-5-21-1-1001": {"kind": "user", "name": "analyst", "sid": "S-1-5-21-1-1001"},
                  "group:S-1-5-32-544": {"kind": "group", "name": "Administrators", "sid": "S-1-5-32-544",
                                         "members": ["PC\\Administrator", "PC\\analyst"]}}
    cur_users = dict(base_users)
    cur_users["user:S-1-5-21-1-1007"] = {"kind": "user", "name": "wv_testuser", "sid": "S-1-5-21-1-1007",
                                         "is_admin": True}
    cur_users["group:S-1-5-32-544"] = {**base_users["group:S-1-5-32-544"],
                                       "members": ["PC\\Administrator", "PC\\analyst", "PC\\wv_testuser"]}

    def snap(sid, created, cols, events_block=None):
        s = {"id": sid, "created_utc": created, "host": {"hostname": "PC", "elevated": True},
             "collectors": {k: {"status": "ok", "items": v} for k, v in cols.items()}}
        if events_block is not None:
            s["events"] = events_block
        return s

    base = snap("a", T0, {"registry": {}, "services": {}, "tasks": {}, "users": base_users, "startup": {}})
    block = extra_events_block or {"window_start": "2026-09-30T02:42:00.000Z",
                                   "window_end": "2026-09-30T02:43:00.000Z", "status": "ok", "errors": {},
                                   "task_log_enabled": True, "events": events}
    cur = snap("b", "2026-09-30T02:42:30+00:00", {
        "registry": {"HKLM\\...\\Run\\WinVaultTest": {
            "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "WinVaultTest",
            "value": "notepad.exe", "_key_last_write": "2026-09-30T02:42:02+00:00"}},
        "services": {"WinVaultTestSvc": {"name": "WinVaultTestSvc", "display_name": "WinVault Test Service",
                                         "image_path": '"C:\\Windows\\System32\\notepad.exe"'}},
        "tasks": {"\\WinVaultTest": {"name": "\\WinVaultTest", "actions": []}},
        "users": cur_users,
        "startup": {"C:\\...\\WinVaultTest.txt": {"file_name": "WinVaultTest.txt",
                                                  "_created": "2026-09-30T02:42:07+00:00"}},
    }, block)
    return base, cur


def run(base, cur):
    result = compare_snapshots(base, cur)
    analyze(result)
    correlate(result, cur, base)
    return result, {c.category + ":" + (c.item.get("name") or c.key): c for c in result.changes}


def test_service_high_confidence_with_sc_exe():
    _, by = run(*snaps())
    a = by["services:WinVaultTestSvc"].attribution
    assert a["confidence"] == "high"
    assert a["process"]["image"].endswith("sc.exe")
    assert "WinVaultTestSvc" in a["process"]["command_line"]
    assert a["user"] == "analyst"            # resolved from the 7045 SID


def test_task_is_not_blamed_on_the_previous_process():
    # sc.exe ran 1s before the task was created by the same user — it must NOT be picked
    _, by = run(*snaps())
    a = by["tasks:\\WinVaultTest"].attribution
    assert a["process"] is None
    assert a["confidence"] == "medium"
    assert a["user"] == "PC\\analyst"
    assert a["when"].startswith("2026-09-30T02:42:04")


def test_new_user_and_admin_group_membership():
    _, by = run(*snaps())
    user = by["users:wv_testuser"]
    assert user.attribution["user"] == "PC\\analyst"
    assert {e["event_id"] for e in user.evidence} == {4720, 4722}
    group = by["users:Administrators"]
    assert [e["event_id"] for e in group.evidence] == [4732]     # matched via MemberSid, MemberName is "-"


def test_registry_falls_back_to_key_last_write_honestly():
    _, by = run(*snaps())
    a = by["registry:HKLM\\...\\Run\\WinVaultTest"].attribution
    assert a["confidence"] == "low"
    assert a["user"] is None and a["process"] is None
    assert a["when_source"] == "registry key last-write time"


def test_timeline_is_chronological_and_process_before_its_event():
    result, _ = run(*snaps())
    times = [e["time"] for e in result.timeline if e.get("time")]
    from winvault.events.reader import parse_time
    parsed = [parse_time(x) for x in times]
    assert parsed == sorted(parsed)
    kinds = [e["kind"] for e in result.timeline if e.get("time") and e["time"].startswith("2026-09-30T02:42:03")]
    assert kinds.index("process") < kinds.index("event")


def test_log_cleared_raises_alert():
    events = EVENTS + [{"log": "Security", "event_id": 1102, "record_id": 99, "time": t(9),
                        "data": {"SubjectUserName": "analyst", "SubjectDomainName": "PC"}}]
    result, _ = run(*snaps(events))
    assert result.alerts and "CLEARED" in result.alerts[0]["message"]


def test_missing_process_auditing_is_reported():
    events = [e for e in EVENTS if e["event_id"] != 4688]
    result, _ = run(*snaps(events))
    assert any("4688" in w for w in result.warnings)


def test_no_events_block_warns_and_leaves_changes_unattributed():
    base, cur = snaps()
    del cur["events"]
    result, by = run(base, cur)
    assert any("no event-log evidence" in w for w in result.warnings)
    assert all(c.attribution is None for c in result.changes)


def test_token_must_match_whole_word():
    from winvault.correlation import EventIndex, _find_process
    idx = EventIndex([{"log": "Security", "event_id": 4688, "record_id": 1, "time": t(3),
                       "data": {"CommandLine": "sc.exe create WinVaultTestSvc"}}])
    assert _find_process(idx, ["WinVaultTest"], None, None) is None
    assert _find_process(idx, ["WinVaultTestSvc"], None, None) is not None


def test_log_retention_gap_is_reported():
    block = {"window_start": "2026-09-30T02:42:00.000Z", "window_end": "2026-09-30T02:43:00.000Z",
             "status": "ok", "errors": {}, "task_log_enabled": True, "events": EVENTS,
             "oldest": {"Security": "2026-09-30T02:42:30.0000000Z", "System": "2026-09-01T00:00:00.0000000Z"}}
    result, _ = run(*snaps(extra_events_block=block))
    gaps = [w for w in result.warnings if "only reaches back" in w]
    assert len(gaps) == 1 and "Security" in gaps[0]
