"""Registry collector: autorun / persistence-relevant keys and values.

HKLM locations are read directly. Per-user locations are read from every
user hive currently loaded under HKEY_USERS (so an elevated run still sees
the logged-on user's HKCU\\...\\Run), keyed by SID.
"""

from __future__ import annotations

import re

from .base import Collector, CollectorError, filetime_to_iso, is_windows

# (path, value filter). A filter of None means "every value in the key".
MACHINE_KEYS: list[tuple[str, tuple[str, ...] | None]] = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", None),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx", None),
    (r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", None),
    (r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", None),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", None),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ("Shell", "Userinit", "Taskman")),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", ("AppInit_DLLs", "LoadAppInit_DLLs", "Load", "Run")),
    (r"System\CurrentControlSet\Control\Session Manager", ("BootExecute", "SetupExecute")),
    (r"System\CurrentControlSet\Control\Lsa", ("Authentication Packages", "Notification Packages", "Security Packages")),
]

USER_KEYS: list[tuple[str, tuple[str, ...] | None]] = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", None),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", None),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ("Shell",)),
    (r"Software\Microsoft\Windows NT\CurrentVersion\Windows", ("Load", "Run")),
    (r"Environment", ("UserInitMprLogonScript",)),
]

_USER_SID = re.compile(r"^S-1-5-21-[\d-]+$")

# winreg type constants (duplicated so this module imports on Linux for tests)
REG_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD", 7: "REG_MULTI_SZ", 11: "REG_QWORD",
}


def normalize_value(data, reg_type: int):
    """Make a registry value JSON-serialisable and stable."""
    if isinstance(data, (bytes, bytearray)):
        return data.hex()
    if isinstance(data, list):
        return [str(x) for x in data]
    return data


class RegistryCollector(Collector):
    name = "registry"
    description = "Autorun and persistence-related registry values"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("registry collector requires Windows")
        import winreg

        items: dict[str, dict] = {}
        for path, only in MACHINE_KEYS:
            self._read_key(winreg, winreg.HKEY_LOCAL_MACHINE, "HKLM", path, only, items)

        for sid in self._loaded_user_sids(winreg):
            for path, only in USER_KEYS:
                self._read_key(winreg, winreg.HKEY_USERS, f"HKU\\{sid}", sid + "\\" + path, only, items,
                               display_path=path, user_sid=sid)
        return items

    @staticmethod
    def _loaded_user_sids(winreg) -> list[str]:
        sids = []
        with winreg.OpenKey(winreg.HKEY_USERS, "") as root:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(root, i)
                except OSError:
                    break
                if _USER_SID.match(name):
                    sids.append(name)
                i += 1
        return sids

    @staticmethod
    def _read_key(winreg, hive, hive_name, path, only, items, display_path=None, user_sid=None):
        display_path = display_path or path
        # Always read the native 64-bit view; WOW6432Node paths are listed explicitly.
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            return  # key does not exist on this system: nothing to record
        with key:
            _, n_values, last_write = winreg.QueryInfoKey(key)
            for i in range(n_values):
                try:
                    vname, data, vtype = winreg.EnumValue(key, i)
                except OSError:
                    continue
                if only is not None and vname not in only:
                    continue
                full = f"{hive_name}\\{display_path}\\{vname or '(Default)'}"
                items[full] = {
                    "hive": hive_name,
                    "key": display_path,
                    "value_name": vname or "(Default)",
                    "value": normalize_value(data, vtype),
                    "type": REG_TYPES.get(vtype, str(vtype)),
                    "user_sid": user_sid,
                    "_key_last_write": filetime_to_iso(last_write),
                }
