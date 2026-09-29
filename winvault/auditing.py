"""Check and enable the Windows audit settings WinVault uses as evidence.

This is the Python equivalent of scripts/Enable-WinVaultAuditing.ps1, so users
of the standalone winvault.exe can run `winvault audit --enable` (or click
*Enable Auditing* in WinVault-GUI.exe) without any script.

Subcategory GUIDs are language-independent, so this works on non-English Windows.
"""

from __future__ import annotations

import csv
import io
import subprocess
from dataclasses import dataclass

from .collectors.base import CollectorError, is_windows

SUBCATEGORIES: list[tuple[str, str, str]] = [
    ("Process Creation", "{0CCE922B-69AE-11D9-BED3-505054503030}", "4688 — which process made a change"),
    ("User Account Management", "{0CCE9235-69AE-11D9-BED3-505054503030}", "4720-4738 — account changes"),
    ("Security Group Management", "{0CCE9237-69AE-11D9-BED3-505054503030}", "4732/4733 — group membership"),
    ("Other Object Access Events", "{0CCE9227-69AE-11D9-BED3-505054503030}", "4698/4702 — scheduled tasks"),
    ("Security System Extension", "{0CCE9211-69AE-11D9-BED3-505054503030}", "4697 — service installs"),
]
CMDLINE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
CMDLINE_VALUE = "ProcessCreationIncludeCmdLine_Enabled"
LSA_KEY = r"System\CurrentControlSet\Control\Lsa"
TASK_LOG = "Microsoft-Windows-TaskScheduler/Operational"
SECURITY_LOG_BYTES = 256 * 1024 * 1024


@dataclass
class AuditItem:
    name: str
    enabled: bool | None      # None = could not determine
    detail: str


def _run(args: list[str]) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"{args[0]} failed: {exc}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).decode("utf-8", errors="replace").strip()
        raise CollectorError(f"{' '.join(args[:2])} exited {proc.returncode}: {err[:300]}")
    return proc.stdout.decode("utf-8", errors="replace")


def parse_auditpol_csv(text: str) -> bool | None:
    """True if the subcategory audits Success. auditpol /r prints a CSV whose
    'Inclusion Setting' value is localized, so we compare against known forms
    and fall back to 'contains Success'."""
    rows = list(csv.reader(io.StringIO(text.strip())))
    if len(rows) < 2:
        return None
    header, values = rows[0], rows[1]
    try:
        setting = values[header.index("Inclusion Setting")]
    except (ValueError, IndexError):
        setting = values[-2] if len(values) >= 2 else ""
    s = setting.strip().lower()
    if not s:
        return None
    if "no auditing" in s:
        return False
    return "success" in s or None


def _reg_dword(hive_key: str, value: str) -> int | None:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive_key) as k:
            return int(winreg.QueryValueEx(k, value)[0])
    except OSError:
        return None


def status() -> list[AuditItem]:
    if not is_windows():
        raise CollectorError("audit settings are only available on Windows")
    items = []
    for name, guid, why in SUBCATEGORIES:
        try:
            enabled = parse_auditpol_csv(_run(["auditpol.exe", "/get", f"/subcategory:{guid}", "/r"]))
        except CollectorError:
            enabled = None
        items.append(AuditItem(name, enabled, why))
    items.append(AuditItem("Command line in 4688", _reg_dword(CMDLINE_KEY, CMDLINE_VALUE) == 1,
                           "full command lines for process attribution"))
    try:
        out = _run(["wevtutil.exe", "gl", TASK_LOG])
        enabled = "enabled: true" in out.lower()
    except CollectorError:
        enabled = None
    items.append(AuditItem("Task Scheduler Operational log", enabled, "106/140/141 — task registration"))
    return items


def enable() -> list[AuditItem]:
    """Enable every setting. Requires Administrator. Persists across reboots."""
    if not is_windows():
        raise CollectorError("audit settings are only available on Windows")
    import winreg
    for _name, guid, _why in SUBCATEGORIES:
        _run(["auditpol.exe", "/set", f"/subcategory:{guid}", "/success:enable"])
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, LSA_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "SCENoApplyLegacyAuditPolicy", 0, winreg.REG_DWORD, 1)
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, CMDLINE_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, CMDLINE_VALUE, 0, winreg.REG_DWORD, 1)
    _run(["wevtutil.exe", "sl", TASK_LOG, "/e:true"])
    _run(["wevtutil.exe", "sl", "Security", f"/ms:{SECURITY_LOG_BYTES}"])
    return status()


def is_fully_enabled(items: list[AuditItem]) -> bool:
    return all(i.enabled for i in items)
