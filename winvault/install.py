"""`winvault install` / `winvault uninstall`: put winvault.exe on PATH so it works
from any terminal, like `ls` or `git`.

- From an Administrator terminal: installs to %ProgramFiles%\\WinVault and adds
  it to the system PATH (all users).
- Otherwise: installs to %LOCALAPPDATA%\\Programs\\WinVault and adds it to the
  user PATH (no admin needed).
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .collectors.base import is_admin

EXE_NAME = "winvault.exe"
GUI_NAME = "WinVault-GUI.exe"
MACHINE_ENV = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
USER_ENV = "Environment"


def add_to_path(path_value: str, entry: str) -> str:
    """Append entry to a ';'-separated PATH unless it is already there (case/trailing-slash insensitive)."""
    parts = [p for p in path_value.split(";") if p.strip()]
    norm = entry.rstrip("\\/").lower()
    if any(p.rstrip("\\/").lower() == norm for p in parts):
        return ";".join(parts)
    return ";".join(parts + [entry])


def remove_from_path(path_value: str, entry: str) -> str:
    norm = entry.rstrip("\\/").lower()
    return ";".join(p for p in path_value.split(";") if p.strip() and p.rstrip("\\/").lower() != norm)


def default_dir(system_wide: bool) -> Path:
    if system_wide:
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WinVault"
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "Programs" / "WinVault"


def _env_key(system_wide: bool):
    import winreg
    if system_wide:
        return winreg.HKEY_LOCAL_MACHINE, MACHINE_ENV
    return winreg.HKEY_CURRENT_USER, USER_ENV


def _read_path(system_wide: bool) -> str:
    import winreg
    hive, key = _env_key(system_wide)
    try:
        with winreg.OpenKey(hive, key) as k:
            return str(winreg.QueryValueEx(k, "Path")[0])
    except OSError:
        return ""


def _write_path(system_wide: bool, value: str) -> None:
    import winreg
    hive, key = _env_key(system_wide)
    with winreg.CreateKeyEx(hive, key, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ, value)
    _broadcast_env_change()


def _broadcast_env_change() -> None:
    """Tell Explorer the environment changed, so new terminals see the new PATH."""
    try:
        import ctypes
        HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG = 0xFFFF, 0x001A, 0x0002
        result = ctypes.c_ulong()
        ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
                                                 SMTO_ABORTIFHUNG, 5000, ctypes.byref(result))
    except (AttributeError, OSError):
        pass


def install(target: Path | None = None) -> tuple[Path, bool]:
    """Copy the running winvault.exe (and WinVault-GUI.exe if next to it) and add to PATH."""
    if sys.platform != "win32":
        raise RuntimeError("install is only for the Windows winvault.exe")
    if not getattr(sys, "frozen", False):
        raise RuntimeError("install is for the standalone winvault.exe — with pip, `winvault` is already on PATH")
    system_wide = is_admin()
    target = target or default_dir(system_wide)
    target.mkdir(parents=True, exist_ok=True)
    src = Path(sys.executable)
    if src.resolve() != (target / EXE_NAME).resolve():
        shutil.copy2(src, target / EXE_NAME)
    gui = src.with_name(GUI_NAME)
    if gui.exists() and gui.resolve() != (target / GUI_NAME).resolve():
        shutil.copy2(gui, target / GUI_NAME)
    _write_path(system_wide, add_to_path(_read_path(system_wide), str(target)))
    return target, system_wide


def uninstall() -> list[Path]:
    """Remove WinVault's folders from PATH and delete the installed files (snapshots are kept)."""
    if sys.platform != "win32":
        raise RuntimeError("uninstall is only for the Windows winvault.exe")
    removed = []
    for system_wide in ((True, False) if is_admin() else (False,)):
        folder = default_dir(system_wide)
        current = _read_path(system_wide)
        updated = remove_from_path(current, str(folder))
        if updated != ";".join(p for p in current.split(";") if p.strip()):
            _write_path(system_wide, updated)
        running = Path(sys.executable).resolve()
        for name in (EXE_NAME, GUI_NAME):
            f = folder / name
            if f.exists() and f.resolve() != running:
                f.unlink()
        removed.append(folder)
    return removed
