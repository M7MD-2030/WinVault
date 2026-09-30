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
