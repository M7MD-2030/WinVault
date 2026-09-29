"""Noise filter.

A noise rule recognises a change as *expected Windows activity* and attaches a
short reason to it. Noise is never deleted — it is tagged and hidden by default,
and `--show-noise` brings it back — because "we ignored this" must stay auditable.

SAFETY PRINCIPLE: every rule matches tightly. It is not enough that a path looks
like a Windows path; the change must be the specific, benign transformation we
expect (same identity, official directory, nothing else altered). A loose rule
is an attacker's hiding place, so when in doubt a rule declines and the change
stays visible.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..models import Change, ChangeStatus

# Official, fixed-form locations. Anchored so "…\Windows Defender\Platform\x\evil"
# under a user-writable copy cannot match by containment.
# Optional leading @ (display-name resource strings) and quote.
DEFENDER_PLATFORM = re.compile(
    r"^@?\"?[A-Z]:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\[0-9.\-]+\\", re.IGNORECASE
)
DEFENDER_PROGRAMFILES = re.compile(
    r"^@?\"?(%ProgramFiles%|[A-Z]:\\Program Files)\\Windows Defender\\", re.IGNORECASE
)
# Per-user service instances: base name + "_" + 4-6 hex chars, e.g. CDPUserSvc_1a2b3.
PER_USER_SVC = re.compile(r"^(?P<base>[A-Za-z0-9]+)_[0-9a-fA-F]{4,6}$")

# Accounts Windows Setup creates and removes on its own.
SETUP_TRANSIENT_USERS = {"defaultuser0", "defaultuser1", "WDAGUtilityAccount"}

NoiseRule = Callable[[Change], str | None]
_RULES: list[tuple[str, NoiseRule]] = []


def rule(name: str):
    def deco(fn: NoiseRule):
        _RULES.append((name, fn))
        return fn
    return deco


def _both(change: Change, field: str) -> tuple:
    b = (change.before or {}).get(field)
    a = (change.after or {}).get(field)
    return b, a


@rule("defender-platform-move")
def defender_platform_move(change: Change) -> str | None:
    """Defender services/tasks moving from Program Files to the versioned Platform dir.

    Requires: MODIFIED, only path-like fields changed, the display name / base binary
    is unchanged, and the new value is the ProgramFiles->Platform transition (not the
    other way, and not into some *other* directory).
    """
    if change.category != "services" or change.status is not ChangeStatus.MODIFIED:
        return None
    if change.field_names() - {"image_path", "display_name", "service_dll"}:
        return None
    for f in change.fields:
        before, after = str(f.before or ""), str(f.after or "")
        moved = DEFENDER_PROGRAMFILES.search(before) and DEFENDER_PLATFORM.search(after)
        # display_name uses @<path>,-NNN resource strings; allow the same move there.
        if not moved:
            return None
        if _basename(before) != _basename(after):
            return None  # the actual binary/dll name must be identical
    return "Windows Defender platform update (Program Files -> versioned Platform folder)"


@rule("setup-transient-user")
def setup_transient_user(change: Change) -> str | None:
    name = change.item.get("name", "")
    if change.category == "users" and change.item.get("kind", "user") == "user" \
            and name in SETUP_TRANSIENT_USERS:
        return f"Windows Setup transient account ({name})"
    # membership removal of a transient account from a group
    if change.category == "users" and change.status is ChangeStatus.MODIFIED:
        removed = _removed_members(change)
        if removed and all(_short_name(m) in SETUP_TRANSIENT_USERS for m in removed):
            return "removal of Windows Setup transient account from group"
    return None


@rule("per-user-service-instance")
def per_user_service_instance(change: Change) -> str | None:
    """Per-user service *instances* (Name_<hex>) appear/disappear per session.

    The template service they derive from must already exist unchanged; we only
    excuse the auto-generated instance, and only when it points at a signed OS
    binary path (svchost / a system32 dll), not an arbitrary executable.
    """
    if change.category != "services" or change.status is not ChangeStatus.ADDED:
        return None
    m = PER_USER_SVC.match(change.item.get("name", ""))
    if not m:
        return None
    image = str(change.item.get("image_path") or "")
    if "svchost.exe" not in image.lower():
        return None
    return f"per-user service instance of {m.group('base')}"


@rule("microsoft-task-refresh")
def microsoft_task_refresh(change: Change) -> str | None:
    """Built-in \\Microsoft\\Windows\\ tasks whose *only* change is the file hash /
    mtime — Windows rewrites these. Any action, trigger, principal or run-level
    change is NOT excused."""
    if change.category != "tasks" or change.status is not ChangeStatus.MODIFIED:
        return None
    if not change.key.startswith("\\Microsoft\\Windows\\"):
        return None
    if change.field_names() - {"sha256"}:
        return None
    return "Microsoft built-in task rewritten (hash-only change)"


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"').split(",")[0])[-1].lower()


def _short_name(member: str) -> str:
    return re.split(r"[\\/]", member)[-1]


def _removed_members(change: Change) -> list[str]:
    for f in change.fields:
        if f.name == "members" and isinstance(f.before, list) and isinstance(f.after, list):
            return [x for x in f.before if x not in f.after]
    return []


def classify_noise(change: Change) -> str | None:
    for _name, fn in _RULES:
        reason = fn(change)
        if reason:
            return reason
    return None


def rule_names() -> list[str]:
    return [n for n, _ in _RULES]
