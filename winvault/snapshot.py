"""Snapshot Manager: create, store, load and verify snapshots.

Snapshots are treated as evidence. Each one is written once as JSON, its
SHA-256 is recorded in ``index.json``, and every load re-hashes the file and
refuses to use it if the hash no longer matches (tamper / corruption check).
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .collectors import ALL_COLLECTORS, CollectorError
from .collectors.base import is_admin

SNAPSHOT_FORMAT = "winvault-snapshot/1"


class IntegrityError(RuntimeError):
    pass


def default_store() -> Path:
    env = os.environ.get("WINVAULT_STORE")
    if env:
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "WinVault"
    return Path.cwd() / "winvault-data"


def host_info() -> dict:
    try:
        user = getpass.getuser()
    except Exception:
        user = None
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "user": user,
        "elevated": is_admin(),
    }


def take_snapshot(kind: str = "snapshot", label: str | None = None,
                  only: list[str] | None = None, progress=None,
                  events_since: str | None = None) -> dict:
    """Run the collectors and return a snapshot dict (not yet saved).

    With ``events_since`` (an ISO time, normally the baseline's creation time),
    the Event Log evidence for [events_since, now] is embedded in the snapshot so
    it is hash-protected together with everything else.
    """
    names = only or list(ALL_COLLECTORS)
    started = datetime.now(timezone.utc)
    collectors: dict[str, dict] = {}
    for name in names:
        cls = ALL_COLLECTORS[name]
        if progress:
            progress(f"collecting {name} ...")
        t0 = datetime.now(timezone.utc)
        try:
            items = cls().collect()
            collectors[name] = {"status": "ok", "count": len(items), "items": items}
        except CollectorError as exc:
            collectors[name] = {"status": "error", "error": str(exc), "count": 0, "items": {}}
        except Exception as exc:  # never lose the whole snapshot to one collector
            collectors[name] = {"status": "error", "error": f"{type(exc).__name__}: {exc}",
                                "count": 0, "items": {}}
        collectors[name]["duration_s"] = round((datetime.now(timezone.utc) - t0).total_seconds(), 3)

    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    snapshot = {
        "format": SNAPSHOT_FORMAT,
        "id": f"{stamp}-{kind}-{uuid.uuid4().hex[:6]}",
        "kind": kind,
        "label": label,
        "created_utc": started.isoformat(),
        "tool": {"name": "WinVault", "version": __version__},
        "host": host_info(),
        "collectors": collectors,
    }
    if events_since:
        from .events import collect_events  # local import keeps collectors import-light
        if progress:
            progress("collecting event logs ...")
        snapshot["events"] = collect_events(events_since, datetime.now(timezone.utc))
    return snapshot


class StoreLock:
    """Cross-process lock around index updates (two WinVault runs at once must not
    lose each other's entries). Uses an exclusive-create lock file; a lock older
    than ``stale_after`` seconds is assumed abandoned (crashed process)."""

    def __init__(self, path: Path, timeout: float = 15.0, stale_after: float = 120.0):
        self.path, self.timeout, self.stale_after = path, timeout, stale_after

    def __enter__(self):
        import time
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale_after:
                        self.path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError(f"snapshot store is locked by another WinVault run ({self.path})")
                time.sleep(0.1)

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except OSError:
            pass


def restrict_to_admins(path: Path) -> bool:
    """Windows: make the store readable/writable only by Administrators and SYSTEM.
    Snapshots contain account names and paths; tampering is also detected by the
    SHA-256 check, but not letting ordinary users touch evidence is better still."""
    if os.name != "nt":
        return False
    import subprocess
    try:
        proc = subprocess.run(["icacls", str(path), "/inheritance:r",
                               "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F"],
                              capture_output=True, timeout=30, check=False)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class SnapshotStore:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else default_store()
        self.snap_dir = self.root / "snapshots"
        self.index_path = self.root / "index.json"

    def _ensure_root(self) -> None:
        if not self.root.exists():
            self.root.mkdir(parents=True, exist_ok=True)
            if is_admin():
                restrict_to_admins(self.root)

    # ---------- index ----------
    def _read_index(self) -> dict:
        if not self.index_path.exists():
            return {"format": "winvault-index/1", "snapshots": {}}
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _write_index(self, index: dict) -> None:
        self._atomic_write(self.index_path, json.dumps(index, indent=2, sort_keys=True).encode())

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())      # evidence must survive a power cut
        os.replace(tmp, path)

    # ---------- public API ----------
    def save(self, snapshot: dict) -> Path:
        self._ensure_root()
        data = json.dumps(snapshot, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
        path = self.snap_dir / f"{snapshot['id']}.json"
        if path.exists():
            raise FileExistsError(f"snapshot {snapshot['id']} already exists")
        self._atomic_write(path, data)
        with StoreLock(self.root / ".lock"):
            index = self._read_index()
            index["snapshots"][snapshot["id"]] = {
                "file": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "kind": snapshot["kind"],
                "label": snapshot.get("label"),
                "created_utc": snapshot["created_utc"],
                "hostname": snapshot["host"]["hostname"],
            }
            self._write_index(index)
        return path

    def list(self) -> list[dict]:
        snaps = self._read_index()["snapshots"]
        return sorted(({"id": k, **v} for k, v in snaps.items()), key=lambda s: s["created_utc"])

    def resolve(self, ref: str) -> str:
        """Accept a full id, a unique prefix, or 'latest' / 'latest-baseline'."""
        entries = self.list()
        if not entries:
            raise KeyError("no snapshots in store")
        if ref == "latest":
            return entries[-1]["id"]
        if ref == "latest-baseline":
            base = [e for e in entries if e["kind"] == "baseline"]
            if not base:
                raise KeyError("no baseline found — run `winvault baseline` first")
            return base[-1]["id"]
        matches = [e["id"] for e in entries if e["id"].startswith(ref)]
        if len(matches) != 1:
            raise KeyError(f"snapshot reference {ref!r} matched {len(matches)} snapshots")
        return matches[0]

    def verify(self, snap_id: str) -> bool:
        entry = self._read_index()["snapshots"][snap_id]
        data = (self.snap_dir / entry["file"]).read_bytes()
        return hashlib.sha256(data).hexdigest() == entry["sha256"]

    def load(self, ref: str) -> dict:
        snap_id = self.resolve(ref)
        entry = self._read_index()["snapshots"][snap_id]
        data = (self.snap_dir / entry["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise IntegrityError(f"snapshot {snap_id} failed SHA-256 verification — file was modified")
        return json.loads(data)


def load_snapshot_file(path: str | Path) -> dict:
    """Load a standalone snapshot JSON (e.g. copied off the VM for offline diffing)."""
    snap = json.loads(Path(path).read_text(encoding="utf-8"))
    if snap.get("format") != SNAPSHOT_FORMAT:
        raise ValueError(f"{path} is not a WinVault snapshot")
    return snap
