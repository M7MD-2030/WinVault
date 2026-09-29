"""Startup folder collector: files in the all-users and per-user Startup
folders, with SHA-256 hashes so content changes are detected too."""

from __future__ import annotations

import os
from pathlib import Path

from .base import Collector, CollectorError, is_windows, iso_from_timestamp, sha256_file

USER_STARTUP = Path("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup")


def startup_folders() -> list[tuple[str, Path]]:
    folders: list[tuple[str, Path]] = []
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    folders.append(("AllUsers", program_data / "Microsoft/Windows/Start Menu/Programs/StartUp"))

    users_root = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
    if users_root.is_dir():
        for profile in sorted(users_root.iterdir()):
            if profile.is_dir():
                folders.append((profile.name, profile / USER_STARTUP))
    return folders


def scan_folders(folders: list[tuple[str, Path]]) -> dict[str, dict]:
    items: dict[str, dict] = {}
    for owner, folder in folders:
        try:
            entries = list(folder.iterdir()) if folder.is_dir() else []
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file() or entry.name.lower() == "desktop.ini":
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            items[str(entry)] = {
                "owner": owner,
                "path": str(entry),
                "file_name": entry.name,
                "extension": entry.suffix.lower(),
                "size": st.st_size,
                "sha256": sha256_file(entry),
                "_modified": iso_from_timestamp(st.st_mtime),
                "_created": iso_from_timestamp(st.st_ctime),
            }
    return items


class StartupCollector(Collector):
    name = "startup"
    description = "Startup folder entries (all users + each profile)"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("startup collector requires Windows")
        return scan_folders(startup_folders())
