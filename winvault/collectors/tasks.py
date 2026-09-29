"""Scheduled Tasks collector.

Parses the task XML definitions in %SystemRoot%\\System32\\Tasks directly.
This needs an elevated prompt (the folder is admin-only) but avoids
locale-dependent ``schtasks`` output and gives us a file hash per task.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import Collector, CollectorError, is_windows, iso_from_timestamp, sha256_file

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def _text(node, path) -> str | None:
    el = node.find(path, NS)
    return el.text.strip() if el is not None and el.text else None


def parse_task_xml(raw: bytes) -> dict:
    """Extract the security-relevant fields from a task definition."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        # Some tasks are UTF-16 without a matching declaration.
        text = raw.decode("utf-16", errors="replace")
        root = ET.fromstring(text.split("?>", 1)[-1] if text.startswith("<?xml") else text)

    actions = []
    for exe in root.findall("t:Actions/t:Exec", NS):
        actions.append({
            "type": "exec",
            "command": _text(exe, "t:Command"),
            "arguments": _text(exe, "t:Arguments"),
            "working_directory": _text(exe, "t:WorkingDirectory"),
        })
    for com in root.findall("t:Actions/t:ComHandler", NS):
        actions.append({"type": "com", "class_id": _text(com, "t:ClassId"), "data": _text(com, "t:Data")})

    triggers_node = root.find("t:Triggers", NS)
    triggers = sorted({child.tag.split("}")[-1] for child in triggers_node}) if triggers_node is not None else []

    principal = root.find("t:Principals/t:Principal", NS)
    enabled = _text(root, "t:Settings/t:Enabled")
    hidden = _text(root, "t:Settings/t:Hidden")
    return {
        "author": _text(root, "t:RegistrationInfo/t:Author"),
        "description": _text(root, "t:RegistrationInfo/t:Description"),
        "registered": _text(root, "t:RegistrationInfo/t:Date"),
        "enabled": enabled is None or enabled.lower() == "true",
        "hidden": hidden is not None and hidden.lower() == "true",
        "run_as_user": _text(principal, "t:UserId") if principal is not None else None,
        "run_as_group": _text(principal, "t:GroupId") if principal is not None else None,
        "run_level": _text(principal, "t:RunLevel") if principal is not None else None,
        "triggers": triggers,
        "actions": actions,
    }


class ScheduledTasksCollector(Collector):
    name = "tasks"
    description = "Scheduled task definitions (System32\\Tasks)"

    def __init__(self, tasks_dir: str | Path | None = None):
        self.tasks_dir = Path(tasks_dir) if tasks_dir else None

    def collect(self) -> dict[str, dict]:
        tasks_dir = self.tasks_dir
        if tasks_dir is None:
            if not is_windows():
                raise CollectorError("tasks collector requires Windows")
            tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        if not tasks_dir.is_dir():
            raise CollectorError(f"tasks folder not found: {tasks_dir}")

        items: dict[str, dict] = {}
        for path in tasks_dir.rglob("*"):
            if not path.is_file():
                continue
            task_name = "\\" + str(path.relative_to(tasks_dir)).replace("/", "\\")
            try:
                raw = path.read_bytes()
                info = parse_task_xml(raw)
            except PermissionError:
                raise CollectorError("access denied to Tasks folder — run WinVault from an elevated prompt")
            except (OSError, ET.ParseError) as exc:
                info = {"parse_error": str(exc)}
            info["name"] = task_name
            info["sha256"] = sha256_file(path)
            try:
                info["_file_modified"] = iso_from_timestamp(path.stat().st_mtime)
            except OSError:
                pass
            items[task_name] = info
        return items
