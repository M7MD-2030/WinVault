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
    assert "WinVault-GUI.exe" in capsys.readouterr().err


def test_audit_command_off_windows_is_clean_error(monkeypatch, capsys):
    import winvault.cli as cli
    monkeypatch.setattr(cli, "is_windows", lambda: False)
    assert cli.main(["audit"]) == 1
    assert "only available on Windows" in capsys.readouterr().err


def _stored(tmp_path):
    import os
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from test_correlation import snaps

    from winvault.snapshot import SnapshotStore
    store = SnapshotStore(tmp_path)
    base, cur = snaps()
    for s, kind in ((base, "baseline"), (cur, "snapshot")):
        s.update(format="winvault-snapshot/1", kind=kind, label=None)
        store.save(s)
    return store


def test_fail_on_exit_codes(tmp_path, capsys):
    from winvault.cli import main
    _stored(tmp_path)
    assert main(["--store", str(tmp_path), "diff", "a", "b"]) == 0
    assert main(["--store", str(tmp_path), "diff", "a", "b", "--fail-on", "critical"]) == 3
    assert main(["--store", str(tmp_path), "diff", "b", "b", "--fail-on", "low"]) == 0     # no changes


def test_no_args_prints_help(capsys):
    from winvault.cli import main
    assert main([]) == 0
    assert "examples:" in capsys.readouterr().out


def test_output_is_plain_when_not_a_terminal(tmp_path, capsys):
    from winvault.cli import main
    _stored(tmp_path)
    main(["--store", str(tmp_path), "diff", "a", "b"])
    assert "\033[" not in capsys.readouterr().out


def test_list_and_status(tmp_path, capsys):
    from winvault.cli import main
    _stored(tmp_path)
    assert main(["--store", str(tmp_path), "list"]) == 0
    out = capsys.readouterr().out
    assert "baseline" in out and "CREATED" in out
    assert main(["--store", str(tmp_path), "status"]) == 0
    assert "baselines: 1" in capsys.readouterr().out


def test_install_refuses_outside_standalone_exe(capsys):
    from winvault.cli import main
    assert main(["install"]) == 1
    assert "error" in capsys.readouterr().err
