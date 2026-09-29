from winvault.compare import compare_snapshots, diff_fields
from winvault.models import ChangeStatus


def snap(sid, items_by_cat, host="LAB", elevated=True, status=None):
    status = status or {}
    return {
        "id": sid,
        "host": {"hostname": host, "elevated": elevated},
        "collectors": {
            cat: {"status": status.get(cat, "ok"), "error": "boom", "items": items}
            for cat, items in items_by_cat.items()
        },
    }


def test_added_removed_modified_unchanged():
    a = snap("a", {"services": {
        "Spooler": {"image_path": "spoolsv.exe", "start_type": "auto", "_key_last_write": "t1"},
        "Old": {"image_path": "old.exe"},
        "Same": {"image_path": "same.exe"},
    }})
    b = snap("b", {"services": {
        "Spooler": {"image_path": "spoolsv.exe", "start_type": "disabled", "_key_last_write": "t2"},
        "New": {"image_path": "new.exe"},
        "Same": {"image_path": "same.exe"},
    }})
    result = compare_snapshots(a, b)
    s = result.summary["services"]
    assert (s.added, s.removed, s.modified, s.unchanged) == (1, 1, 1, 1)
    by_key = {c.key: c for c in result.changes}
    assert by_key["New"].status is ChangeStatus.ADDED
    assert by_key["Old"].status is ChangeStatus.REMOVED
    mod = by_key["Spooler"]
    assert mod.status is ChangeStatus.MODIFIED
    assert [f.name for f in mod.fields] == ["start_type"]


def test_metadata_fields_are_ignored():
    assert diff_fields({"a": 1, "_ts": "x"}, {"a": 1, "_ts": "y"}) == []


def test_failed_collector_is_skipped_with_warning():
    a = snap("a", {"tasks": {"\\T": {}}})
    b = snap("b", {"tasks": {}}, status={"tasks": "error"})
    result = compare_snapshots(a, b)
    assert "tasks" not in result.summary
    assert any("tasks" in w for w in result.warnings)


def test_host_and_elevation_mismatch_warn():
    result = compare_snapshots(snap("a", {}, host="A", elevated=True), snap("b", {}, host="B", elevated=False))
    assert len(result.warnings) == 2


def test_to_dict_is_json_serialisable():
    import json
    a = snap("a", {"registry": {}})
    b = snap("b", {"registry": {"HKLM\\Run\\x": {"value": "c:\\x.exe"}}})
    data = compare_snapshots(a, b).to_dict()
    assert json.loads(json.dumps(data))["total_changes"] == 1
