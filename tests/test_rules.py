"""Risk-scoring tests: the WinVaultTest artifacts, plus escalation combinations."""

from winvault.analysis.pipeline import analyze
from winvault.analysis.rules import level_for, score_change
from winvault.compare import compare_snapshots
from winvault.models import Change, ChangeStatus, FieldChange


def added(cat, key, item):
    return Change(cat, key, ChangeStatus.ADDED, None, item)


def test_levels():
    assert level_for(0) == "low"
    assert level_for(29) == "low"
    assert level_for(30) == "medium"
    assert level_for(60) == "high"
    assert level_for(80) == "critical"


def test_new_run_key_is_medium():
    c = added("registry", "HKLM\\...\\Run\\X",
              {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "X", "value": "notepad.exe"})
    score, reasons = score_change(c)
    assert score == 30 and any("autorun" in r for r in reasons)


def test_powershell_task_in_temp_stacks_up():
    c = added("tasks", "\\Evil", {
        "name": "\\Evil", "run_as_user": "S-1-5-18", "run_level": "HighestAvailable", "hidden": True,
        "actions": [{"command": "C:\\Users\\bob\\AppData\\Local\\Temp\\p.ps1 via powershell.exe",
                     "arguments": "-enc AAA"}],
    })
    score, reasons = score_change(c)
    # new task 30 + system 20 + powershell 20 + user-writable 20 + hidden 15 = 105
    assert score >= 80 and level_for(score) == "critical"
    assert len(reasons) >= 4


def test_new_admin_user_is_critical():
    c = added("users", "user:S-1-5-21-1-1005",
              {"kind": "user", "name": "evil", "is_admin": True})
    score, _ = score_change(c)
    assert level_for(score) == "critical"


def test_added_to_administrators_is_medium():
    c = Change("users", "group:S-1-5-32-544", ChangeStatus.MODIFIED,
               {"sid": "S-1-5-32-544"}, {"sid": "S-1-5-32-544"},
               [FieldChange("members", ["PC\\a"], ["PC\\a", "PC\\evil"])])
    score, reasons = score_change(c)
    assert score == 50 and any("Administrators" in r for r in reasons)


def test_defender_disabled_is_high():
    c = Change("services", "WinDefend", ChangeStatus.MODIFIED,
               {"name": "WinDefend", "start_type": "auto"}, {"name": "WinDefend", "start_type": "disabled"},
               [FieldChange("start_type", "auto", "disabled")])
    score, reasons = score_change(c)
    assert score >= 60 and any("security service" in r for r in reasons)


def _snap(sid, users_items):
    return {"id": sid, "host": {"hostname": "LAB", "elevated": True},
            "collectors": {"users": {"status": "ok", "items": users_items}}}


def test_analyze_counts_levels_and_noise():
    # baseline has defaultuser0; current drops it (removed) and adds an admin user
    base = _snap("a", {"user:S-1-5-21-1-1000": {"kind": "user", "name": "defaultuser0"}})
    cur = _snap("b", {"user:S-1-5-21-1-1005": {"kind": "user", "name": "evil", "is_admin": True}})
    result = compare_snapshots(base, cur)
    stats = analyze(result)
    assert stats.by_level["critical"] == 1      # the new admin user
    assert stats.noise == 1                      # defaultuser0 removal
    assert stats.signal == 1
