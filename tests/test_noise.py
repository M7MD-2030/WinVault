"""Noise-filter tests. Cases mirror real Windows churn seen on the dev VM, plus
adversarial look-alikes that MUST stay visible."""

from winvault.analysis.noise import classify_noise
from winvault.models import Change, ChangeStatus, FieldChange


def svc_mod(name, field, before, after, extra_fields=None):
    fields = [FieldChange(field, before, after)] + (extra_fields or [])
    return Change("services", name, ChangeStatus.MODIFIED,
                  {"name": name, field: before}, {"name": name, field: after}, fields)


# ---- real Defender platform move (should be noise) ----

def test_defender_platform_move_is_noise():
    c = svc_mod("WinDefend", "image_path",
                '"%ProgramFiles%\\Windows Defender\\MsMpEng.exe"',
                '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\MsMpEng.exe"')
    assert classify_noise(c) and "Defender" in classify_noise(c)


def test_defender_display_name_move_is_noise():
    c = svc_mod("WdFilter", "display_name",
                "@%ProgramFiles%\\Windows Defender\\MpAsDesc.dll,-330",
                "@C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\MpAsDesc.dll,-330")
    assert classify_noise(c)


# ---- adversarial look-alikes (must NOT be noise) ----

def test_different_binary_into_defender_path_is_not_noise():
    # attacker points a Defender service at a *different* exe in the platform dir
    c = svc_mod("WinDefend", "image_path",
                '"%ProgramFiles%\\Windows Defender\\MsMpEng.exe"',
                '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\evil.exe"')
    assert classify_noise(c) is None


def test_move_out_of_defender_dir_is_not_noise():
    c = svc_mod("WinDefend", "image_path",
                '"%ProgramFiles%\\Windows Defender\\MsMpEng.exe"',
                '"C:\\Users\\bob\\AppData\\Local\\Temp\\MsMpEng.exe"')
    assert classify_noise(c) is None


def test_extra_field_change_blocks_defender_noise():
    # path moved AND start_type changed → not a plain platform move
    c = svc_mod("WinDefend", "image_path",
                '"%ProgramFiles%\\Windows Defender\\MsMpEng.exe"',
                '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26080.4-0\\MsMpEng.exe"',
                extra_fields=[FieldChange("start_type", "auto", "disabled")])
    assert classify_noise(c) is None


# ---- setup transient accounts ----

def test_defaultuser0_removed_is_noise():
    c = Change("users", "user:S-1-5-21-1-1000", ChangeStatus.REMOVED,
               {"kind": "user", "name": "defaultuser0"}, None)
    assert classify_noise(c)


def test_real_user_removed_is_not_noise():
    c = Change("users", "user:S-1-5-21-1-1000", ChangeStatus.REMOVED,
               {"kind": "user", "name": "wv_testuser"}, None)
    assert classify_noise(c) is None


# ---- microsoft task hash churn ----

def test_microsoft_task_hash_only_is_noise():
    c = Change("tasks", "\\Microsoft\\Windows\\Flighting\\OneSettings\\RefreshCache", ChangeStatus.MODIFIED,
               {"sha256": "a"}, {"sha256": "b"}, [FieldChange("sha256", "a", "b")])
    assert classify_noise(c)


def test_microsoft_task_action_change_is_not_noise():
    c = Change("tasks", "\\Microsoft\\Windows\\Foo", ChangeStatus.MODIFIED,
               {"sha256": "a", "actions": []}, {"sha256": "b", "actions": [{"command": "evil.exe"}]},
               [FieldChange("sha256", "a", "b"), FieldChange("actions", [], [{"command": "evil.exe"}])])
    assert classify_noise(c) is None


def test_non_microsoft_task_hash_change_is_not_noise():
    c = Change("tasks", "\\WinVaultTest", ChangeStatus.MODIFIED,
               {"sha256": "a"}, {"sha256": "b"}, [FieldChange("sha256", "a", "b")])
    assert classify_noise(c) is None


# ---- per-user service instance ----

def test_per_user_service_instance_is_noise():
    c = Change("services", "CDPUserSvc_1a2b3", ChangeStatus.ADDED, None,
               {"name": "CDPUserSvc_1a2b3", "image_path": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup"})
    assert classify_noise(c)


def test_fake_per_user_service_with_odd_binary_is_not_noise():
    c = Change("services", "Evil_dead", ChangeStatus.ADDED, None,
               {"name": "Evil_dead", "image_path": "C:\\Users\\bob\\evil.exe"})
    assert classify_noise(c) is None
