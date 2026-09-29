import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from test_correlation import snaps  # noqa: E402

from winvault.report import render_html  # noqa: E402
from winvault.service import investigate  # noqa: E402


def test_report_contains_findings_timeline_and_metadata():
    base, cur = snaps()
    out = render_html(investigate(base, cur), {"a": "ab" * 32})
    assert out.startswith("<!doctype html>")
    assert "wv_testuser" in out and "WinVaultTestSvc" in out
    assert "CRITICAL" in out and "sc.exe" in out
    assert "Timeline" in out and "4720" in out
    assert "sha256 " + "ab" * 32 in out                       # baseline hash shown
    assert "<script" not in out and "http" not in out.split("<body>")[1]   # self-contained, no external assets


def test_report_escapes_untrusted_values():
    base, cur = snaps()
    cur["collectors"]["registry"]["items"]["HKLM\\...\\Run\\<b>x"] = {
        "key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "<img src=x onerror=alert(1)>",
        "value": "<script>alert(1)</script>"}
    out = render_html(investigate(base, cur))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
    assert "<img src=x" not in out


def test_group_change_shows_only_delta():
    base, cur = snaps()
    out = render_html(investigate(base, cur))
    assert "+ PC\\wv_testuser" in out
