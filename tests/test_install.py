from winvault.install import add_to_path, remove_from_path


def test_add_to_path_appends_once():
    p = r"C:\Windows\system32;C:\Windows"
    once = add_to_path(p, r"C:\Program Files\WinVault")
    assert once.endswith(r";C:\Program Files\WinVault")
    assert add_to_path(once, "c:\\program files\\winvault\\") == once       # case / trailing slash


def test_add_to_empty_and_messy_path():
    assert add_to_path("", r"C:\X") == r"C:\X"
    assert add_to_path(r"C:\A;;C:\B;", r"C:\X") == r"C:\A;C:\B;C:\X"


def test_remove_from_path_only_removes_ours():
    p = r"C:\A;C:\Program Files\WinVault\;C:\B"
    assert remove_from_path(p, r"C:\Program Files\WinVault") == r"C:\A;C:\B"
    assert remove_from_path(r"C:\A;C:\WinVaultOther", r"C:\WinVault") == r"C:\A;C:\WinVaultOther"


def test_start_menu_shortcut_locations(monkeypatch):
    from winvault.install import start_menu_shortcut
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setenv("APPDATA", r"C:\Users\a\AppData\Roaming")
    assert str(start_menu_shortcut(True)).replace("/", "\\").endswith(
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\WinVault.lnk")
    assert "Roaming" in str(start_menu_shortcut(False))


def test_taskbar_layout_is_valid_xml_and_appends(tmp_path):
    import xml.etree.ElementTree as ET

    from winvault.install import taskbar_layout_xml
    link = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\WinVault & Co.lnk"
    root = ET.fromstring(taskbar_layout_xml(link))
    ns = {"d": "http://schemas.microsoft.com/Start/2014/LayoutModification",
          "t": "http://schemas.microsoft.com/Start/2014/TaskbarLayout"}
    coll = root.find("d:CustomTaskbarLayoutCollection", ns)
    assert coll.get("PinListPlacement") == "Append"            # never replaces the user's own pins
    app = root.find(".//t:DesktopApp", ns)
    assert app.get("DesktopApplicationLinkPath") == link          # special characters escaped


def test_is_pinned_reads_user_pinned_folder(tmp_path, monkeypatch):
    from winvault.install import is_pinned, taskbar_pins_dir
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert not is_pinned()
    d = taskbar_pins_dir()
    d.mkdir(parents=True)
    (d / "File Explorer.lnk").write_bytes(b"")
    assert not is_pinned()
    (d / "WinVault.lnk").write_bytes(b"")
    assert is_pinned()


def test_pin_skips_when_already_pinned_or_windows_10(tmp_path, monkeypatch):
    import winvault.install as inst
    monkeypatch.setattr(inst, "is_pinned", lambda: True)
    assert inst.pin_to_taskbar(tmp_path / "WinVault.lnk", tmp_path) == "already"
    monkeypatch.setattr(inst, "is_pinned", lambda: False)
    monkeypatch.setattr(inst, "_windows_build", lambda: 19045)
    status = inst.pin_to_taskbar(tmp_path / "WinVault.lnk", tmp_path)
    assert status.startswith("manual:")
    assert not (tmp_path / inst.LAYOUT_NAME).exists()              # nothing written on Windows 10
