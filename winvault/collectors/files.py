"""Critical file integrity: SHA-256 of a fixed list of system configuration files.

A hash comparison catches a content change even when the file's name, size and
location stay the same. The list is deliberately small and stable (files that
should almost never change on a healthy machine), so any change is worth a look.
"""

from __future__ import annotations

import os
from pathlib import Path

from .base import Collector, CollectorError, is_windows, iso_from_timestamp, sha256_file

# Relative to %SystemRoot%.
CRITICAL_FILES = [
    r"System32\drivers\etc\hosts",
    r"System32\drivers\etc\networks",
    r"System32\drivers\etc\protocol",
    r"System32\drivers\etc\services",
    r"System32\drivers\etc\lmhosts.sam",
]


def hash_files(paths: list[Path]) -> dict[str, dict]:
    items: dict[str, dict] = {}
    for path in paths:
        key = str(path)
        try:
            st = path.stat()
        except FileNotFoundError:
            items[key] = {"path": key, "exists": False, "sha256": None, "size": None}
            continue
        except OSError as exc:
            items[key] = {"path": key, "exists": True, "sha256": None, "size": None, "error": str(exc)}
            continue
        items[key] = {
            "path": key,
            "exists": True,
            "sha256": sha256_file(path),
            "size": st.st_size,
            "_modified": iso_from_timestamp(st.st_mtime),
        }
    return items


class CriticalFilesCollector(Collector):
    name = "files"
    description = "SHA-256 of critical system configuration files (hosts, etc.)"

    def __init__(self, paths: list[Path] | None = None):
        self.paths = paths

    def collect(self) -> dict[str, dict]:
        paths = self.paths
        if paths is None:
            if not is_windows():
                raise CollectorError("files collector requires Windows")
            root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            paths = [root / p for p in CRITICAL_FILES]
        return hash_files(paths)
