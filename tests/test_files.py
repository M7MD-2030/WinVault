from winvault.analysis.rules import level_for, score_change
from winvault.collectors.files import CriticalFilesCollector
from winvault.compare import compare_snapshots


def snap(sid, items):
    return {"id": sid, "host": {"hostname": "PC", "elevated": True},
            "collectors": {"files": {"status": "ok", "items": items}}}


def test_hash_detects_same_size_content_change(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    before = CriticalFilesCollector([hosts]).collect()
    hosts.write_text("127.0.0.2 localhost\n")          # same size, different content
    after = CriticalFilesCollector([hosts]).collect()
    assert before[str(hosts)]["size"] == after[str(hosts)]["size"]
    result = compare_snapshots(snap("a", before), snap("b", after))
    (change,) = result.changes
    assert [f.name for f in change.fields] == ["sha256"]
    score, reasons = score_change(change)
    assert score == 50 and "hosts" in reasons[0]
    assert level_for(score) == "medium"


def test_missing_file_is_recorded_not_crashing(tmp_path):
    items = CriticalFilesCollector([tmp_path / "nope"]).collect()
    assert items[str(tmp_path / "nope")]["exists"] is False


def test_file_appearing_scores(tmp_path):
    f = tmp_path / "networks"
    before = CriticalFilesCollector([f]).collect()
    f.write_text("x")
    after = CriticalFilesCollector([f]).collect()
    (change,) = compare_snapshots(snap("a", before), snap("b", after)).changes
    score, _ = score_change(change)
    assert score >= 40
