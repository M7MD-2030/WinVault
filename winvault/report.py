"""Investigation report: one self-contained HTML file (no external assets).

Open it in any browser; use the browser's Print -> "Save as PDF" for a PDF.
Print CSS keeps each finding on one page where possible.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from . import PROJECT_NAME, __version__
from .analysis.pipeline import sort_key
from .presentation import (
    KIND_COLORS, LEVEL_COLORS, change_details_html, display_name, local_time,
)
from .service import Investigation

CSS = """
:root { --bg:#ffffff; --panel:#f6f7f9; --border:#e2e5ea; --text:#15181d; --muted:#5d6570; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
       font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
.sub { color: var(--muted); margin: 0 0 20px; }
table.meta td { padding: 2px 16px 2px 0; vertical-align: top; }
table.meta td:first-child { color: var(--muted); white-space: nowrap; }
code, .mono { font-family: Consolas, "SFMono-Regular", Menlo, monospace; font-size: 12.5px; word-break: break-all; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0 8px; }
.tile { flex: 1 1 120px; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.tile .n { font-size: 26px; font-weight: 700; }
.tile .c { color: var(--muted); font-size: 12px; }
.banner { border-radius: 6px; padding: 10px 12px; margin: 8px 0; border: 1px solid; }
.alert { background: #fdecec; border-color: #e5484d; }
.warn { background: #fdf4e3; border-color: #e2a336; }
.finding { background: var(--panel); border: 1px solid var(--border); border-left: 5px solid; border-radius: 8px;
           padding: 14px 18px; margin: 12px 0; break-inside: avoid; }
.finding h2 { border: none; margin: 0 0 6px; padding: 0; font-size: 18px; }
.finding h3 { font-size: 15px; } .finding h4 { margin: 14px 0 4px; font-size: 13.5px; }
.finding table td, .finding table th { font-size: 13px; }
table.grid { width: 100%; border-collapse: collapse; }
table.grid th { text-align: left; color: var(--muted); font-weight: 600; border-bottom: 1px solid var(--border); padding: 6px 8px; }
table.grid td { border-bottom: 1px solid var(--border); padding: 5px 8px; vertical-align: top; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
@media print {
  body { font-size: 11.5px; } main { padding: 0; max-width: none; }
  .finding { break-inside: avoid; } h2 { break-after: avoid; }
}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def render_html(inv: Investigation, snapshot_hashes: dict[str, str] | None = None) -> str:
    r, s = inv.result, inv.stats
    b, c = inv.baseline, inv.current
    hashes = snapshot_hashes or {}
    generated = datetime.now(timezone.utc).isoformat()
    host = c.get("host", {})

    host_line = _e(host.get("hostname") or "unknown host") + (f" &nbsp;·&nbsp; {_e(host['os'])}" if host.get("os") else "")
    elevated = {True: "yes", False: "NO — results incomplete"}.get(host.get("elevated"), "unknown")
    meta_rows = [
        ("Host", host_line),
        ("Collected by", f"{_e(host.get('user') or 'unknown user')} (elevated: {elevated})"),
        ("Baseline", f"<code>{_e(b['id'])}</code> — {_e(local_time(b.get('created_utc')))}"
                     + (f"<br><span class='mono'>sha256 {_e(hashes[b['id']])}</span>" if b["id"] in hashes else "")),
        ("Current", f"<code>{_e(c['id'])}</code> — {_e(local_time(c.get('created_utc')))}"
                    + (f"<br><span class='mono'>sha256 {_e(hashes[c['id']])}</span>" if c["id"] in hashes else "")),
    ]
    if r.event_window:
        meta_rows.append(("Event window", f"{_e(local_time(r.event_window.get('start')))} → "
                                          f"{_e(local_time(r.event_window.get('end')))}"))
    meta_rows.append(("Generated", f"{_e(local_time(generated))} by WinVault v{_e(__version__)}"))

    tiles = "".join(
        f"<div class='tile'><div class='n' style='color:{LEVEL_COLORS[lvl]}'>{n}</div>"
        f"<div class='c'>{label}</div></div>"
        for lvl, n, label in [("critical", s.by_level["critical"], "Critical"),
                              ("high", s.by_level["high"], "High"),
                              ("medium", s.by_level["medium"], "Medium"),
                              ("low", s.by_level["low"], "Low"),
                              ("noise", s.noise, "Filtered as noise")])

    banners = "".join(f"<div class='banner alert'><b>ALERT</b> {_e(local_time(a['time']))} — {_e(a['message'])}</div>"
                      for a in r.alerts)
    banners += "".join(f"<div class='banner warn'>{_e(w)}</div>" for w in r.warnings)

    signal = sorted((ch for ch in r.changes if not ch.noise), key=sort_key)
    findings = "".join(
        f"<section class='finding' style='border-left-color:{LEVEL_COLORS.get(ch.level, '#5b6068')}'>"
        f"{change_details_html(ch)}</section>" for ch in signal) or "<p>No security-relevant changes.</p>"

    timeline_rows = "".join(
        f"<tr><td class='mono' style='white-space:nowrap'>{_e(local_time(e['time'], ms=True) if e.get('time') else '(undated)')}</td>"
        f"<td style='color:{LEVEL_COLORS.get(e.get('level'), KIND_COLORS[e['kind']]) if e['kind'] == 'change' else KIND_COLORS[e['kind']]};"
        f"font-weight:600'>{_e(e['kind'].upper())}</td><td>{_e(e['text'])}</td></tr>"
        for e in r.timeline)
    timeline = (f"<table class='grid'><tr><th>Time (local)</th><th>Kind</th><th>What happened</th></tr>"
                f"{timeline_rows}</table>") if timeline_rows else "<p>No event evidence in this comparison.</p>"

    noise = [ch for ch in r.changes if ch.noise]
    noise_rows = "".join(f"<tr><td>{_e(ch.category)}</td><td class='mono'>{_e(display_name(ch))}</td>"
                         f"<td>{_e(ch.noise)}</td></tr>" for ch in noise)
    noise_html = (f"<table class='grid'><tr><th>Category</th><th>Object</th><th>Why it was filtered</th></tr>"
                  f"{noise_rows}</table>") if noise else "<p>Nothing was filtered.</p>"

    summary_rows = "".join(f"<tr><td>{_e(cat)}</td><td>{x.added}</td><td>{x.removed}</td><td>{x.modified}</td>"
                           f"<td>{x.unchanged}</td></tr>" for cat, x in r.summary.items())

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinVault report — {_e(host.get('hostname'))} — {_e(c['id'])}</title><style>{CSS}</style></head>
<body><main>
<h1>{_e(PROJECT_NAME)}</h1>
<p class="sub">Investigation report — {s.total} changes, {s.signal} to review, {s.noise} filtered as normal Windows activity</p>
<table class="meta">{''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in meta_rows)}</table>
<div class="tiles">{tiles}</div>
{banners}
<h2>Findings</h2>
{findings}
<h2>Timeline</h2>
{timeline}
<h2>Change summary</h2>
<table class="grid"><tr><th>Category</th><th>Added</th><th>Removed</th><th>Modified</th><th>Unchanged</th></tr>{summary_rows}</table>
<h2>Filtered as noise</h2>
{noise_html}
<footer>Snapshots are stored as JSON with SHA-256 recorded at capture time and re-verified on every load.
Attribution confidence: <b>high</b> = audit event and process command line both name the object; <b>medium</b> = audit
event gives who/when; <b>low</b> = artifact timestamp only; <b>none</b> = no evidence. WinVault never guesses a
user or process it cannot support with evidence.</footer>
</main></body></html>
"""


def snapshot_hashes(store, *snapshot_ids: str) -> dict[str, str]:
    """SHA-256 values recorded in the store index for these snapshots (if stored there)."""
    out = {}
    for entry in store.list():
        if entry["id"] in snapshot_ids:
            out[entry["id"]] = entry["sha256"]
    return out
