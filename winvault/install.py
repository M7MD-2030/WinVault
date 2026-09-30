"""`winvault install` / `winvault uninstall`: put winvault.exe on PATH so it works
from any terminal, like `ls` or `git`.

- From an Administrator terminal: installs to %ProgramFiles%\\WinVault and adds
  it to the system PATH (all users).
- Otherwise: installs to %LOCALAPPDATA%\\Programs\\WinVault and adds it to the
  user PATH (no admin needed).

It also adds WinVault to the Start menu and, on Windows 11 from an Administrator
terminal, pins it to the taskbar next to File Explorer. Windows has no API that
lets a program pin itself, so this uses the documented taskbar-layout policy
(the same mechanism IT departments use), scoped to the current user.
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
POLICY_KEY = r"Software\Policies\Microsoft\Windows\Explorer"
LAYOUT_NAME = "TaskbarLayout.xml"
WIN11_BUILD = 22000


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


def install(target: Path | None = None, pin: bool = True) -> tuple[Path, bool, str | None]:
    """Copy the running winvault.exe (and WinVault-GUI.exe if next to it), add to PATH,
    add the Start menu entry and pin it to the taskbar. Returns (folder, system_wide, pin_status)."""
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
    pin_status = None
    if (target / GUI_NAME).exists():
        link = start_menu_shortcut(system_wide)
        if create_shortcut(link, target / GUI_NAME) and pin:
            pin_status = pin_to_taskbar(link, target)
    return target, system_wide, pin_status


def start_menu_shortcut(system_wide: bool) -> Path:
    """Where the WinVault Start menu entry lives (searchable, and pinnable to the taskbar)."""
    if system_wide:
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    else:
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return base / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "WinVault.lnk"


def create_shortcut(link: Path, target: Path) -> bool:
    """Create a .lnk via the WScript.Shell COM object (built into Windows, no extra modules).
    Paths are passed through environment variables, so spaces/quotes can't break the command."""
    import subprocess
    script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:WV_LINK); "
              "$s.TargetPath = $env:WV_TARGET; $s.WorkingDirectory = $env:WV_DIR; "
              "$s.IconLocation = $env:WV_TARGET + ',0'; "
              "$s.Description = 'WinVault - Digital Evidence & Forensic Analysis'; $s.Save()")
    env = {**os.environ, "WV_LINK": str(link), "WV_TARGET": str(target), "WV_DIR": str(target.parent)}
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                              env=env, capture_output=True, timeout=60, check=False)
        return proc.returncode == 0 and link.exists()
    except (OSError, subprocess.TimeoutExpired):
        return False


# ── Taskbar pin ────────────────────────────────────────────────────────────────

def taskbar_pins_dir() -> Path:
    """Where Explorer keeps the current user's pinned taskbar shortcuts."""
    base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    return base / "Microsoft" / "Internet Explorer" / "Quick Launch" / "User Pinned" / "TaskBar"


def is_pinned() -> bool:
    d = taskbar_pins_dir()
    return d.is_dir() and any(f.name.lower().startswith("winvault") for f in d.glob("*.lnk"))


def taskbar_layout_xml(link: Path) -> str:
    """Taskbar layout that *appends* WinVault to the user's existing pins (nothing is removed)."""
    from xml.sax.saxutils import quoteattr
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<LayoutModificationTemplate\n'
        '    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"\n'
        '    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"\n'
        '    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"\n'
        '    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"\n'
        '    Version="1">\n'
        '  <CustomTaskbarLayoutCollection PinListPlacement="Append">\n'
        '    <defaultlayout:TaskbarLayout>\n'
        '      <taskbar:TaskbarPinList>\n'
        f'        <taskbar:DesktopApp DesktopApplicationLinkPath={quoteattr(str(link))} />\n'
        '      </taskbar:TaskbarPinList>\n'
        '    </defaultlayout:TaskbarLayout>\n'
        '  </CustomTaskbarLayoutCollection>\n'
        '</LayoutModificationTemplate>\n'
    )


def _windows_build() -> int:
    try:
        return sys.getwindowsversion().build          # type: ignore[attr-defined]
    except AttributeError:
        return 0


def _read_policy() -> str | None:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY) as k:
            return str(winreg.QueryValueEx(k, "StartLayoutFile")[0])
    except OSError:
        return None


def _same_file(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.expandvars(str(a))) == os.path.normcase(str(b))


def _restart_shell() -> None:
    """Restart Explorer so the taskbar reloads. Windows starts it again by itself (non-elevated)."""
    import subprocess
    import time
    subprocess.run(["taskkill.exe", "/f", "/im", "explorer.exe"], capture_output=True, check=False)
    for _ in range(20):                               # Windows normally brings it back within ~2 s
        time.sleep(0.5)
        out = subprocess.run(["tasklist.exe", "/fi", "imagename eq explorer.exe", "/nh"],
                             capture_output=True, text=True, check=False).stdout
        if "explorer.exe" in out.lower():
            return
    subprocess.Popen(["explorer.exe"])                # AutoRestartShell is off: start it ourselves


def pin_to_taskbar(link: Path, layout_dir: Path) -> str:
    """Pin the Start menu shortcut to the taskbar. Returns one of:
    "already", "pinned", "next-sign-in", "manual:<reason>"."""
    if is_pinned():
        return "already"
    if _windows_build() < WIN11_BUILD:
        # On Windows 10 this policy would also lock the Start menu tiles — not worth it.
        return "manual:Windows 10 doesn't let programs pin themselves"
    existing = _read_policy()
    layout = layout_dir / LAYOUT_NAME
    if existing and _same_file(existing, layout) and layout.exists():
        return "manual:you unpinned it earlier, so it was left off"     # Windows applies a layout once
    if existing and not _same_file(existing, layout):
        return "manual:a taskbar layout is already set by your organization"
    try:
        import winreg
        layout.write_text(taskbar_layout_xml(link), encoding="utf-8")
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "LockedStartLayout", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(k, "StartLayoutFile", 0, winreg.REG_EXPAND_SZ, str(layout))
    except OSError:
        return "manual:run the install from an Administrator terminal to pin automatically"
    _restart_shell()
    import time
    for _ in range(20):
        if is_pinned():
            return "pinned"
        time.sleep(0.5)
    return "next-sign-in"


def unpin_from_taskbar() -> bool:
    """Remove WinVault's taskbar pin and the layout policy (only if it is ours). True if a pin was removed."""
    import winreg
    existing = _read_policy()
    if existing and Path(os.path.expandvars(existing)).name == LAYOUT_NAME and "winvault" in existing.lower():
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, POLICY_KEY, 0, winreg.KEY_SET_VALUE) as k:
                for name in ("StartLayoutFile", "LockedStartLayout"):
                    try:
                        winreg.DeleteValue(k, name)
                    except OSError:
                        pass
        except OSError:
            pass
    removed = False
    d = taskbar_pins_dir()
    if d.is_dir():
        for f in d.glob("*.lnk"):
            if f.name.lower().startswith("winvault"):
                f.unlink(missing_ok=True)
                removed = True
    if removed:
        _restart_shell()
    return removed


def uninstall() -> list[Path]:
    """Remove WinVault's folders from PATH and delete the installed files (snapshots are kept)."""
    if sys.platform != "win32":
        raise RuntimeError("uninstall is only for the Windows winvault.exe")
    removed = []
    unpin_from_taskbar()
    for system_wide in ((True, False) if is_admin() else (False,)):
        folder = default_dir(system_wide)
        current = _read_path(system_wide)
        updated = remove_from_path(current, str(folder))
        if updated != ";".join(p for p in current.split(";") if p.strip()):
            _write_path(system_wide, updated)
        running = Path(sys.executable).resolve()
        for name in (EXE_NAME, GUI_NAME, LAYOUT_NAME):
            f = folder / name
            if f.exists() and f.resolve() != running:
                f.unlink()
        start_menu_shortcut(system_wide).unlink(missing_ok=True)
        removed.append(folder)
    return removed
