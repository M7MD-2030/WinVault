"""Presentation helpers shared by the CLI, the GUI and the HTML report.

No Qt imports here, so the same rendering is available everywhere.
"""

from __future__ import annotations

import html
import json

from .events.reader import parse_time
from .models import Change, ChangeStatus

LEVEL_COLORS = {
    "critical": "#e5484d",
    "high": "#f76b15",
    "medium": "#e2a336",
    "low": "#6e8cae",
    "noise": "#5b6068",
}
CONFIDENCE_COLORS = {"high": "#46a758", "medium": "#e2a336", "low": "#6e8cae", "none": "#5b6068"}
KIND_COLORS = {"process": "#8e7cc3", "event": "#6e8cae", "change": "#e2a336", "alert": "#e5484d"}
STATUS_SYMBOL = {ChangeStatus.ADDED: "+", ChangeStatus.REMOVED: "-", ChangeStatus.MODIFIED: "~"}
CATEGORY_LABEL = {"registry": "Registry", "services": "Service", "tasks": "Scheduled task",
                  "users": "Account", "startup": "Startup item"}


def short(value, width: int = 90) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= width else text[: width - 3] + "..."


def display_name(change: Change) -> str:
    """Human-friendly label: users/groups show their name, not just the SID."""
    item = change.after or change.before or {}
    if change.category == "users" and item.get("name"):
        return f"{item.get('kind', 'user')} {item['name']}  ({item.get('sid', change.key)})"
    return change.key


def describe_field(f) -> list[str]:
    """For list fields (e.g. group members) show only what was added/removed."""
    if isinstance(f.before, list) and isinstance(f.after, list):
        added = [x for x in f.after if x not in f.before]
        removed = [x for x in f.before if x not in f.after]
        lines = [f"{f.name}: + {x}" for x in added] + [f"{f.name}: - {x}" for x in removed]
        return lines or [f"{f.name}: order changed"]
    return [f"{f.name}: {short(f.before)}  ->  {short(f.after)}"]


def local_time(iso: str | None, ms: bool = False) -> str:
    """Render an ISO timestamp in this machine's local time, e.g. 2026-09-30 05:42:08(.123)."""
    t = parse_time(iso)
    if not t:
        return "unknown time"
    t = t.astimezone()
    return t.strftime("%Y-%m-%d %H:%M:%S") + (f".{t.microsecond // 1000:03d}" if ms else "")


def grouped_evidence(evidence: list[dict]) -> list[tuple[dict, int]]:
    """Collapse identical evidence lines (e.g. two 4738s) into (entry, count), keeping order."""
    out: list[list] = []
    index: dict[tuple, int] = {}
    for ev in evidence:
        key = (ev.get("event_id"), ev.get("summary"))
        if key in index:
            out[index[key]][1] += 1
        else:
            index[key] = len(out)
            out.append([ev, 1])
    return [(ev, n) for ev, n in out]


# ---- rich HTML for one finding (GUI details pane + HTML report) ---------------

def _e(value) -> str:
    if value is None or value == "":
        return "<span style='color:#9aa1ab'>—</span>"
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    return html.escape(value)


def badge(text: str, color: str) -> str:
    return (f"<span style='background:{color};color:#0d0f12;font-weight:700;"
            f"padding:2px 8px;border-radius:4px'>&nbsp;{html.escape(text)}&nbsp;</span>")


def _rows(pairs) -> str:
    return "".join(f"<tr><td style='color:#9aa1ab;padding:2px 14px 2px 0;vertical-align:top'>{html.escape(k)}</td>"
                   f"<td style='padding:2px 0'>{v}</td></tr>" for k, v in pairs)


def change_details_html(change: Change) -> str:
    level = change.level if not change.noise else "noise"
    color = LEVEL_COLORS.get(level, "#5b6068")
    parts = [f"<h2 style='margin:0 0 6px 0'>{badge(level.upper(), color)}"
             f"{'' if change.noise else f'&nbsp; {change.score} points'}</h2>",
             f"<h3 style='margin:4px 0 10px 0'>{html.escape(display_name(change))}</h3>",
             f"<table>{_rows([('Type', html.escape(CATEGORY_LABEL.get(change.category, change.category))), ('Status', html.escape(change.status.value.upper())), ('Location', _e(change.key))])}</table>"]

    if change.noise:
        parts.append(f"<h4>Filtered as normal Windows activity</h4><p>{html.escape(change.noise)}</p>")
    elif change.reasons:
        parts.append("<h4>Why it matters</h4><ul>" +
                     "".join(f"<li>{html.escape(r)}</li>" for r in change.reasons) + "</ul>")

    if change.status is ChangeStatus.MODIFIED and change.fields:
        rows = []
        for f in change.fields:
            if isinstance(f.before, list) and isinstance(f.after, list):
                # lists (e.g. group members): show only the delta
                added = [x for x in f.after if x not in f.before]
                removed = [x for x in f.before if x not in f.after]
                delta = "<br>".join([f"<span style='color:#46a758'>+ {html.escape(str(x))}</span>" for x in added] +
                                    [f"<span style='color:#e5484d'>− {html.escape(str(x))}</span>" for x in removed])
                rows.append(f"<tr><td style='padding:2px 12px 2px 0;color:#9aa1ab'>{html.escape(f.name)}</td>"
                            f"<td colspan='2' style='padding:2px 0'>{delta or 'order changed'}</td></tr>")
            else:
                rows.append(f"<tr><td style='padding:2px 12px 2px 0;color:#9aa1ab'>{html.escape(f.name)}</td>"
                            f"<td style='padding:2px 12px 2px 0'>{_e(f.before)}</td>"
                            f"<td style='padding:2px 0'>{_e(f.after)}</td></tr>")
        parts.append("<h4>What changed</h4><table><tr><th align='left'>Field</th><th align='left'>Before</th>"
                     f"<th align='left'>After</th></tr>{''.join(rows)}</table>")
    else:
        item = change.item
        visible = [(k, _e(v)) for k, v in item.items() if not k.startswith("_")]
        meta = [(k.lstrip("_"), _e(v)) for k, v in item.items() if k.startswith("_")]
        title = "Object (now)" if change.status is ChangeStatus.ADDED else "Object (before removal)"
        parts.append(f"<h4>{title}</h4><table>{_rows(visible + meta)}</table>")

    a = change.attribution
    if a:
        conf = a["confidence"]
        proc = a.get("process") or {}
        parts.append("<h4>Attribution</h4><table>" + _rows([
            ("When", _e(local_time(a["when"], ms=True) if a.get("when") else None) +
             (f" <span style='color:#9aa1ab'>({html.escape(a['when_source'])})</span>" if a.get("when_source") else "")),
            ("Who", _e(a.get("user")) if a.get("user") else "<i>undetermined</i>"),
            ("Process", _e(proc.get("image")) if proc.get("image") else "<i>undetermined</i>"),
            ("Command line", _e(proc.get("command_line"))),
            ("Parent", _e(proc.get("parent"))),
            ("Confidence", badge(conf.upper(), CONFIDENCE_COLORS.get(conf, "#5b6068"))),
            ("Note", _e(a.get("note"))),
        ]) + "</table>")
    if change.evidence:
        rows = "".join(
            f"<tr><td style='padding:2px 12px 2px 0;color:#9aa1ab;white-space:nowrap'>"
            f"{html.escape(local_time(ev['time'], ms=True)[11:])}</td>"
            f"<td style='padding:2px 12px 2px 0'><b>{ev['event_id']}</b></td>"
            f"<td style='padding:2px 12px 2px 0;color:#9aa1ab'>{html.escape(ev.get('log') or '')}</td>"
            f"<td style='padding:2px 0'>{html.escape(ev['summary'])}{f' <b>×{n}</b>' if n > 1 else ''}</td></tr>"
            for ev, n in grouped_evidence(change.evidence))
        parts.append(f"<h4>Evidence</h4><table>{rows}</table>")
    return "".join(parts)
