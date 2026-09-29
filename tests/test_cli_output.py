from winvault.cli import describe_field, display_name
from winvault.models import Change, ChangeStatus, FieldChange


def test_user_shows_name_and_sid():
    c = Change("users", "user:S-1-5-21-1-1002", ChangeStatus.ADDED, None,
               {"kind": "user", "name": "wv_testuser", "sid": "S-1-5-21-1-1002"})
    assert display_name(c) == "user wv_testuser  (S-1-5-21-1-1002)"


def test_non_user_uses_key():
    c = Change("services", "WinVaultTestSvc", ChangeStatus.ADDED, None, {"name": "WinVaultTestSvc"})
    assert display_name(c) == "WinVaultTestSvc"


def test_list_field_shows_only_delta():
    f = FieldChange("members", ["PC\\Administrator", "PC\\analyst"],
                    ["PC\\Administrator", "PC\\analyst", "PC\\wv_testuser"])
    assert describe_field(f) == ["members: + PC\\wv_testuser"]


def test_scalar_field():
    assert describe_field(FieldChange("start_type", "auto", "disabled")) == ['start_type: auto  ->  disabled']


def test_gui_command_without_pyside_is_friendly(monkeypatch, capsys):
    import importlib.util
    from winvault.cli import main
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda n, *a: None if n == "PySide6" else real(n, *a))
    assert main(["gui"]) == 1
    assert "needs PySide6" in capsys.readouterr().err
