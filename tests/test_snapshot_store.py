import json

import pytest

from winvault.snapshot import IntegrityError, SnapshotStore


def fake(sid, kind="snapshot", created="2026-09-28T10:00:00+00:00"):
    return {
        "format": "winvault-snapshot/1", "id": sid, "kind": kind, "label": None,
        "created_utc": created, "host": {"hostname": "LAB", "elevated": True},
        "collectors": {"services": {"status": "ok", "count": 1, "items": {"X": {"a": 1}}}},
    }


def test_save_load_and_resolve(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(fake("20260928T100000Z-baseline-aaaaaa", "baseline", "2026-09-28T10:00:00+00:00"))
    store.save(fake("20260928T110000Z-snapshot-bbbbbb", "snapshot", "2026-09-28T11:00:00+00:00"))
    assert store.resolve("latest-baseline").endswith("aaaaaa")
    assert store.resolve("latest").endswith("bbbbbb")
    assert store.resolve("20260928T11").endswith("bbbbbb")
    assert store.load("latest")["collectors"]["services"]["items"]["X"] == {"a": 1}


def test_tampering_is_detected(tmp_path):
    store = SnapshotStore(tmp_path)
    path = store.save(fake("s1"))
    data = json.loads(path.read_text())
    data["collectors"]["services"]["items"]["X"]["a"] = 2
    path.write_text(json.dumps(data))
    assert store.verify("s1") is False
    with pytest.raises(IntegrityError):
        store.load("s1")


def test_duplicate_id_rejected(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(fake("dup"))
    with pytest.raises(FileExistsError):
        store.save(fake("dup"))


def test_no_baseline(tmp_path):
    store = SnapshotStore(tmp_path)
    store.save(fake("only-snap"))
    with pytest.raises(KeyError):
        store.resolve("latest-baseline")


def test_concurrent_saves_keep_every_index_entry(tmp_path):
    import threading
    store = SnapshotStore(tmp_path)
    errors = []

    def worker(n):
        try:
            SnapshotStore(tmp_path).save(fake(f"s{n:02d}", created=f"2026-09-28T10:00:{n:02d}+00:00"))
        except Exception as exc:          # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(store.list()) == 20
    assert not (tmp_path / ".lock").exists()


def test_stale_lock_is_recovered(tmp_path):
    import os
    import time
    lock = tmp_path / ".lock"
    lock.write_text("12345")
    old = time.time() - 3600
    os.utime(lock, (old, old))
    SnapshotStore(tmp_path).save(fake("after-crash"))
    assert SnapshotStore(tmp_path).resolve("latest") == "after-crash"
