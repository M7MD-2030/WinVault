"""Headless smoke test of the desktop app (runs with QT_QPA_PLATFORM=offscreen).

Skipped automatically when PySide6 isn't installed.
"""

import os
import sys

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(__file__))
from test_correlation import snaps  # noqa: E402

from winvault.service import investigate  # noqa: E402
from winvault.snapshot import SnapshotStore  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication

    from winvault.gui.theme import apply_theme
    app = QApplication.instance() or QApplication([])
    apply_theme(app)
    return app


def make_window(tmp_path):
    from winvault.gui.main_window import MainWindow
    return MainWindow(SnapshotStore(tmp_path))


def test_window_shows_investigation(app, tmp_path):
    w = make_window(tmp_path)
    w.show_investigation(investigate(*snaps()))
    assert w.findings.rowCount() == 6
    assert w.findings.item(0, 0).text() == "CRITICAL"          # most severe first
    assert w.tiles["critical"].value.text() == "1"
    assert w.timeline.rowCount() > 6
    assert "wv_testuser" in w.details.toPlainText()             # first row auto-selected
    assert w.act_export.isEnabled()
    assert w.act_report.isEnabled()


def test_filter_and_selection_details(app, tmp_path):
    w = make_window(tmp_path)
    w.show_investigation(investigate(*snaps()))
    w.filter.setText("WinVaultTestSvc")
    assert w.findings.rowCount() == 1
    w.findings.selectRow(0)
    text = w.details.toPlainText()
    assert "sc.exe" in text and "HIGH" in text
    w.filter.setText("no-such-thing")
    assert w.findings.rowCount() == 0


def test_snapshots_tab_lists_store(app, tmp_path):
    store = SnapshotStore(tmp_path)
    base, cur = snaps()
    for s, kind in ((base, "baseline"), (cur, "snapshot")):
        s.update(format="winvault-snapshot/1", kind=kind, label=None)
        store.save(s)
    w = make_window(tmp_path)
    assert w.snapshots.rowCount() == 2
    w._refresh_snapshots_verified()
    assert {w.snapshots.item(r, 4).text() for r in range(2)} == {"OK"}
