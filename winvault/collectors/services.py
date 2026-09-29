"""Services collector: every service/driver registered under
HKLM\\SYSTEM\\CurrentControlSet\\Services, read straight from the registry
(no pywin32 needed, and it includes disabled and never-started services)."""

from __future__ import annotations

from .base import Collector, CollectorError, filetime_to_iso, is_windows

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"

START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
SERVICE_TYPES = {
    0x1: "kernel_driver", 0x2: "fs_driver", 0x4: "adapter", 0x8: "recognizer_driver",
    0x10: "own_process", 0x20: "share_process", 0x50: "user_own_process",
    0x60: "user_share_process", 0x110: "own_process_interactive",
    0x120: "share_process_interactive",
}


def describe_type(value) -> str | None:
    if value is None:
        return None
    return SERVICE_TYPES.get(value, hex(value))


class ServicesCollector(Collector):
    name = "services"
    description = "Windows services and drivers (registry view)"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("services collector requires Windows")
        import winreg

        def get(key, name):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except OSError:
                return None

        items: dict[str, dict] = {}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY) as root:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, svc) as k:
                        image = get(k, "ImagePath")
                        stype = get(k, "Type")
                        if image is None and stype is None:
                            continue  # not a real service entry (e.g. event-log sub keys)
                        last_write = winreg.QueryInfoKey(k)[2]
                        service_dll = None
                        try:
                            with winreg.OpenKey(k, "Parameters") as p:
                                service_dll = get(p, "ServiceDll")
                        except OSError:
                            pass
                        start = get(k, "Start")
                        items[svc] = {
                            "name": svc,
                            "display_name": get(k, "DisplayName"),
                            "image_path": image,
                            "service_dll": service_dll,
                            "start_type": START_TYPES.get(start, start),
                            "service_type": describe_type(stype),
                            "account": get(k, "ObjectName"),
                            "_key_last_write": filetime_to_iso(last_write),
                        }
                except OSError:
                    continue
        return items
