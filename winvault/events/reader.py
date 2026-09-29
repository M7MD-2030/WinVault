"""Read the Windows Event Log entries that can explain a change.

Events are queried for the exact window between the baseline and the current
snapshot and stored *inside* the current snapshot, so they are covered by the
same SHA-256 integrity check as the rest of the evidence and `winvault diff`
can re-correlate offline.

Queries use an XPath filter on UTC ``SystemTime`` (no locale or time-zone
ambiguity) through ``Get-WinEvent``, which returns each event as XML; only the
parsed fields are kept.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from ..collectors.base import CollectorError, as_list, is_windows, run_powershell_json

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
TASK_LOG = "Microsoft-Windows-TaskScheduler/Operational"

# (name, log, event ids, max events). 4688 gets its own query so a flood of
# process events can never push account/service/task events out of the cap.
QUERIES: list[tuple[str, str, list[int], int]] = [
    ("accounts", "Security", [4720, 4722, 4724, 4725, 4726, 4732, 4733, 4738], 2000),
    ("tasks-services", "Security", [4697, 4698, 4699, 4702], 2000),
    ("log-cleared", "Security", [1102], 50),
    ("processes", "Security", [4688], 5000),
    ("system", "System", [104, 7040, 7045], 2000),
    ("task-scheduler", TASK_LOG, [106, 140, 141], 2000),
]

PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$specs = ConvertFrom-Json @'
__SPECS__
'@
$events = New-Object System.Collections.Generic.List[object]
$errors = @{}
foreach ($s in $specs) {
  try {
    $found = Get-WinEvent -LogName $s.log -FilterXPath $s.xpath -MaxEvents $s.max -ErrorAction Stop
    foreach ($e in $found) {
      $events.Add([pscustomobject]@{
        log = $e.LogName; id = $e.Id; record = $e.RecordId
        time = $e.TimeCreated.ToUniversalTime().ToString('o'); xml = $e.ToXml()
      })
    }
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
      $errors[$s.name] = $_.Exception.Message
    }
  }
}
$taskLog = $null
try { $taskLog = (Get-WinEvent -ListLog '__TASKLOG__' -ErrorAction Stop).IsEnabled } catch {}
# Oldest surviving event per log: tells us whether the log still reaches back to the baseline.
$oldest = @{}
foreach ($log in @('Security', 'System')) {
  try {
    $o = Get-WinEvent -LogName $log -MaxEvents 1 -Oldest -ErrorAction Stop
    $oldest[$log] = $o.TimeCreated.ToUniversalTime().ToString('o')
  } catch {}
}
[pscustomobject]@{ events = $events.ToArray(); errors = $errors; task_log_enabled = $taskLog; oldest = $oldest } |
  ConvertTo-Json -Depth 4 -Compress
"""

_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def parse_time(value: str | None) -> datetime | None:
    """Parse ISO-8601 from .NET ('o' format, 7 fractional digits, 'Z') or Python."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION.sub(r"\1", text, count=1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def build_xpath(ids: list[int], start: datetime, end: datetime) -> str:
    id_filter = " or ".join(f"EventID={i}" for i in ids)
    return (f"*[System[({id_filter}) and TimeCreated[@SystemTime>='{iso_utc(start)}' "
            f"and @SystemTime<='{iso_utc(end)}']]]")


def parse_event_xml(xml: str) -> dict:
    """Pull EventData (named or positional), the System security SID and computer."""
    root = ET.fromstring(xml)
    data: dict[str, str] = {}
    for i, node in enumerate(root.findall("e:EventData/e:Data", NS)):
        name = node.get("Name") or f"param{i + 1}"
        data[name] = (node.text or "").strip()
    sec = root.find("e:System/e:Security", NS)
    computer = root.find("e:System/e:Computer", NS)
    return {
        "user_sid": sec.get("UserID") if sec is not None else None,
        "computer": computer.text if computer is not None else None,
        "data": data,
    }


def normalize(raw: dict) -> dict | None:
    try:
        parsed = parse_event_xml(raw["xml"])
    except (ET.ParseError, KeyError, TypeError):
        return None
    return {
        "log": raw.get("log"),
        "event_id": int(raw.get("id")),
        "record_id": raw.get("record"),
        "time": raw.get("time"),
        **parsed,
    }


def collect_events(since: str, until: datetime | None = None) -> dict:
    """Query all evidence logs for [since, until] and return the snapshot 'events' block."""
    start = parse_time(since)
    end = until or datetime.now(timezone.utc)
    block = {
        "window_start": iso_utc(start) if start else None,
        "window_end": iso_utc(end),
        "status": "ok",
        "errors": {},
        "task_log_enabled": None,
        "events": [],
    }
    if not is_windows():
        block.update(status="error", errors={"host": "event logs require Windows"})
        return block
    if start is None:
        block.update(status="error", errors={"window": f"bad start time {since!r}"})
        return block

    specs = [{"name": n, "log": log, "xpath": build_xpath(ids, start, end), "max": mx}
             for n, log, ids, mx in QUERIES]
    script = PS_TEMPLATE.replace("__SPECS__", json.dumps(specs)).replace("__TASKLOG__", TASK_LOG)
    try:
        out = run_powershell_json(script, timeout=300)
    except (CollectorError, json.JSONDecodeError) as exc:
        block.update(status="error", errors={"query": str(exc)})
        return block

    events = [e for e in (normalize(r) for r in as_list(out.get("events"))) if e]
    events.sort(key=lambda e: (e["time"] or "", e["log"] or "", e["record_id"] or 0))
    block["events"] = events
    block["errors"] = out.get("errors") or {}
    block["task_log_enabled"] = out.get("task_log_enabled")
    block["oldest"] = out.get("oldest") or {}
    return block


def window_margin(dt: datetime, seconds: int) -> datetime:
    return dt + timedelta(seconds=seconds)
