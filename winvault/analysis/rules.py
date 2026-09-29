"""Rule-based risk scoring.

Each rule inspects one Change and, if it matches, contributes points and a short
human reason. The total decides a level. Every score is therefore explainable:
the reasons list *is* the justification, so the tool never shows a bare
"CRITICAL" without saying why.

Levels:  0-29 low · 30-59 medium · 60-79 high · 80+ critical
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..models import Change, ChangeStatus

# Directories any standard user can write to — a persistence item living here is
# more suspicious than one under a protected system path.
USER_WRITABLE = re.compile(
    r"(\\Users\\|\\AppData\\|\\Temp\\|\\Tmp\\|\\ProgramData\\|\\Public\\|\\Downloads\\)",
    re.IGNORECASE,
)
LOLBINS = ("powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
           "rundll32", "regsvr32", "mshta.exe", "certutil", "bitsadmin")
ADMINS_SID = "S-1-5-32-544"

Rule = Callable[[Change], tuple[int, str] | None]
_RULES: list[tuple[str, Rule]] = []


def rule(name: str):
    def deco(fn: Rule):
        _RULES.append((name, fn))
        return fn
    return deco


def _text(change: Change) -> str:
    """Command / image / value text to scan for interpreters and paths."""
    it = change.item
    parts = [str(it.get(k, "")) for k in ("image_path", "value", "command", "service_dll")]
    for action in it.get("actions", []) or []:
        if isinstance(action, dict):
            parts += [str(action.get("command", "")), str(action.get("arguments", ""))]
    return " ".join(parts)


# ---- persistence: new autoruns -------------------------------------------------

@rule("new-run-key")
def new_run_key(change: Change):
    if change.category == "registry" and change.status is ChangeStatus.ADDED:
        key = change.item.get("key", "")
        if re.search(r"\\Run(Once)?$", key) or "Policies\\Explorer\\Run" in key:
            return 30, "new autorun registry value"
    return None


@rule("winlogon-shell-change")
def winlogon_shell_change(change: Change):
    if change.category == "registry" and change.status is ChangeStatus.MODIFIED:
        if "Winlogon" in change.item.get("key", "") and change.item.get("value_name") in ("Shell", "Userinit"):
            return 60, "Winlogon Shell/Userinit modified (classic persistence)"
    return None


@rule("new-service")
def new_service(change: Change):
    if change.category == "services" and change.status is ChangeStatus.ADDED:
        return 30, "new service registered"
    return None


@rule("new-task")
def new_task(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED:
        return 30, "new scheduled task"
    return None


@rule("new-startup-item")
def new_startup_item(change: Change):
    if change.category == "startup" and change.status is ChangeStatus.ADDED:
        return 25, "new startup-folder item"
    return None


# ---- qualifiers that sharpen the above ----------------------------------------

@rule("runs-as-system")
def runs_as_system(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED:
        principal = str(change.item.get("run_as_user") or "")
        if principal in ("S-1-5-18",) or principal.lower().endswith("system"):
            return 20, "runs as SYSTEM"
        if str(change.item.get("run_level", "")).lower() == "highestavailable":
            return 10, "runs with highest privileges"
    return None


@rule("uses-interpreter")
def uses_interpreter(change: Change):
    if change.status is not ChangeStatus.ADDED or change.category not in ("registry", "services", "tasks", "startup"):
        return None
    text = _text(change).lower()
    for lol in LOLBINS:
        if lol in text:
            return 20, f"executes {lol}"
    return None


@rule("user-writable-path")
def user_writable_path(change: Change):
    if change.status is not ChangeStatus.ADDED or change.category not in ("registry", "services", "tasks", "startup"):
        return None
    if USER_WRITABLE.search(_text(change)):
        return 20, "target binary in a user-writable location"
    return None


@rule("hidden-task")
def hidden_task(change: Change):
    if change.category == "tasks" and change.status is ChangeStatus.ADDED and change.item.get("hidden"):
        return 15, "task is hidden"
    return None


# ---- accounts & privileges -----------------------------------------------------

@rule("new-local-user")
def new_local_user(change: Change):
    if change.category == "users" and change.status is ChangeStatus.ADDED and change.item.get("kind", "user") == "user":
        pts, why = 40, "new local user account"
        if change.item.get("is_admin"):
            return 90, "new local user created directly in Administrators"
        return pts, why
    return None


@rule("added-to-administrators")
def added_to_administrators(change: Change):
    if change.category == "users" and change.status is ChangeStatus.MODIFIED and change.item.get("sid") == ADMINS_SID:
        for f in change.fields:
            if f.name == "members" and isinstance(f.after, list) and isinstance(f.before, list):
                if [m for m in f.after if m not in f.before]:
                    return 50, "account added to Administrators group"
    return None


# ---- defender / security weakening --------------------------------------------

@rule("service-disabled")
def service_disabled(change: Change):
    if change.category == "services" and change.status is ChangeStatus.MODIFIED:
        b, a = _field(change, "start_type")
        if a == "disabled" and b != "disabled":
            name = change.item.get("name", "").lower()
            if any(k in name for k in ("windefend", "wdnissvc", "sense", "wscsvc", "mpssvc")):
                return 60, "security service disabled"
            return 20, "service disabled"
    return None


# ---- file integrity -----------------------------------------------------------

@rule("critical-file-changed")
def critical_file_changed(change: Change):
    if change.category != "files":
        return None
    name = re.split(r"[\\/]", str(change.item.get("path", "")))[-1].lower()
    if change.status is ChangeStatus.MODIFIED and "sha256" in change.field_names():
        if name == "hosts":
            return 50, "hosts file content changed (name resolution can be redirected)"
        return 40, "critical system file content changed"
    if change.status is ChangeStatus.MODIFIED and "exists" in change.field_names():
        return 40, "critical system file created or deleted"
    return None


def _field(change: Change, name: str):
    for f in change.fields:
        if f.name == name:
            return f.before, f.after
    return None, None


def score_change(change: Change) -> tuple[int, list[str]]:
    total, reasons = 0, []
    for _name, fn in _RULES:
        hit = fn(change)
        if hit:
            pts, why = hit
            total += pts
            reasons.append(f"+{pts} {why}")
    return total, reasons


def level_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def rule_names() -> list[str]:
    return [n for n, _ in _RULES]
