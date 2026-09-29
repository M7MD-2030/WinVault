from datetime import datetime, timezone

from winvault.events.describe import actor_of, summarize
from winvault.events.reader import build_xpath, parse_event_xml, parse_time

EVENT_4720 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID>
<TimeCreated SystemTime='2026-09-30T02:42:08.1234567Z'/><Computer>DESKTOP-6D0DBPP</Computer><Security/></System>
<EventData>
<Data Name='TargetUserName'>wv_testuser</Data><Data Name='TargetDomainName'>DESKTOP-6D0DBPP</Data>
<Data Name='TargetSid'>S-1-5-21-1-1007</Data><Data Name='SubjectUserSid'>S-1-5-21-1-1001</Data>
<Data Name='SubjectUserName'>analyst</Data><Data Name='SubjectDomainName'>DESKTOP-6D0DBPP</Data>
<Data Name='SubjectLogonId'>0x3e7a1</Data>
</EventData></Event>"""

EVENT_7045 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>7045</EventID><Computer>DESKTOP-6D0DBPP</Computer>
<Security UserID='S-1-5-21-1-1001'/></System>
<EventData><Data Name='ServiceName'>WinVault Test Service</Data>
<Data Name='ImagePath'>"C:\\Windows\\System32\\notepad.exe"</Data>
<Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>demand start</Data>
<Data Name='AccountName'>LocalSystem</Data></EventData></Event>"""


def test_parse_named_event_data():
    ev = parse_event_xml(EVENT_4720)
    assert ev["data"]["TargetSid"] == "S-1-5-21-1-1007"
    assert ev["computer"] == "DESKTOP-6D0DBPP"


def test_parse_system_security_sid():
    ev = parse_event_xml(EVENT_7045)
    assert ev["user_sid"] == "S-1-5-21-1-1001"
    assert ev["data"]["ServiceName"] == "WinVault Test Service"


def test_parse_dotnet_time_with_7_fraction_digits():
    t = parse_time("2026-09-30T02:42:08.1234567Z")
    assert t == datetime(2026, 9, 30, 2, 42, 8, 123456, tzinfo=timezone.utc)
    assert parse_time("garbage") is None
    assert parse_time(None) is None


def test_xpath_is_utc_and_bounded():
    xp = build_xpath([4720, 4732], datetime(2026, 9, 30, 2, 42, tzinfo=timezone.utc),
                     datetime(2026, 9, 30, 2, 43, tzinfo=timezone.utc))
    assert "EventID=4720 or EventID=4732" in xp
    assert "@SystemTime>='2026-09-30T02:42:00.000Z'" in xp
    assert "@SystemTime<='2026-09-30T02:43:00.000Z'" in xp


def test_summaries_and_actor():
    ev = {"event_id": 4720, **parse_event_xml(EVENT_4720)}
    assert "wv_testuser" in summarize(ev) and "analyst" in summarize(ev)
    assert actor_of(ev)["user"] == "DESKTOP-6D0DBPP\\analyst"
    svc = {"event_id": 7045, **parse_event_xml(EVENT_7045)}
    assert actor_of(svc, {"S-1-5-21-1-1001": "analyst"})["user"] == "analyst"
    system = {"event_id": 7045, "user_sid": "S-1-5-18", "data": {}}
    assert actor_of(system)["user"] == "NT AUTHORITY\\SYSTEM"
