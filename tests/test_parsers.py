from winvault.collectors.registry import normalize_value
from winvault.collectors.startup import scan_folders
from winvault.collectors.tasks import ScheduledTasksCollector, parse_task_xml
from winvault.collectors.users import build_items

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>LAB\\analyst</Author><Description>demo</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger><TimeTrigger/></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
  <Actions Context="Author">
    <Exec><Command>C:\\Windows\\System32\\notepad.exe</Command><Arguments>a.txt</Arguments></Exec>
  </Actions>
</Task>"""


def test_parse_task_xml_utf16():
    info = parse_task_xml(TASK_XML.encode("utf-16"))
    assert info["run_as_user"] == "S-1-5-18"
    assert info["run_level"] == "HighestAvailable"
    assert info["hidden"] is True
    assert info["triggers"] == ["LogonTrigger", "TimeTrigger"]
    assert info["actions"][0]["command"].endswith("notepad.exe")


def test_tasks_collector_on_folder(tmp_path):
    (tmp_path / "Microsoft").mkdir()
    (tmp_path / "Microsoft" / "Demo").write_bytes(TASK_XML.encode("utf-16"))
    items = ScheduledTasksCollector(tmp_path).collect()
    assert list(items) == ["\\Microsoft\\Demo"]
    assert len(items["\\Microsoft\\Demo"]["sha256"]) == 64


def test_normalize_registry_values():
    assert normalize_value(b"\x01\xff", 3) == "01ff"
    assert normalize_value(["a", "b"], 7) == ["a", "b"]
    assert normalize_value(5, 4) == 5


def test_users_build_items_handles_single_objects():
    # ConvertTo-Json collapses 1-element arrays into objects
    data = {
        "users": {"Name": "bob", "SID": "S-1-5-21-1-1001", "Enabled": True, "LastLogon": "x"},
        "groups": [
            {"Name": "Administrators", "SID": "S-1-5-32-544",
             "Members": {"Name": "LAB\\bob", "SID": "S-1-5-21-1-1001"}},
            {"Name": "Users", "SID": "S-1-5-32-545", "Members": None},
        ],
    }
    items = build_items(data)
    bob = items["user:S-1-5-21-1-1001"]
    assert bob["is_admin"] is True and bob["groups"] == ["Administrators"]
    assert items["group:S-1-5-32-544"]["members"] == ["LAB\\bob"]
    assert items["group:S-1-5-32-545"]["members"] == []


def test_startup_scan(tmp_path):
    (tmp_path / "evil.lnk").write_bytes(b"x")
    (tmp_path / "desktop.ini").write_text("ignored")
    items = scan_folders([("AllUsers", tmp_path)])
    assert len(items) == 1
    (item,) = items.values()
    assert item["extension"] == ".lnk" and item["owner"] == "AllUsers"
