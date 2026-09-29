"""WinVault main window.

Layout
    toolbar     Create Baseline · Compare Now · Compare Snapshots · Export JSON · Refresh
    banner      elevation / alert / warning messages
    tiles       Critical · High · Medium · Low · Noise
    tabs        Findings (table + details) · Timeline · Snapshots
"""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextBrowser, QToolBar, QVBoxLayout, QWidget,
)

from .. import PROJECT_NAME, __version__
from ..analysis.pipeline import sort_key
from ..collectors.base import is_admin, is_windows
from ..models import Change
from ..presentation import (
    CATEGORY_LABEL, CONFIDENCE_COLORS, KIND_COLORS, LEVEL_COLORS, STATUS_SYMBOL,
    change_details_html, display_name, local_time,
)
from ..service import Investigation, capture, compare_live, investigate
from ..snapshot import SnapshotStore
from .workers import Worker

LEVELS = ("critical", "high", "medium", "low", "noise")
FINDING_COLUMNS = ("Level", "Score", "Category", "", "Object", "When", "Who", "Confidence")


class SortItem(QTableWidgetItem):
    """Table item that sorts on a hidden key (numbers, times) instead of display text."""

    def __init__(self, text: str, key=None):
        super().__init__(text)
        self._key = key if key is not None else text

    def __lt__(self, other):
        try:
            return self._key < other._key
        except TypeError:
            return str(self._key) < str(other._key)


class Tile(QFrame):
    def __init__(self, caption: str, color: str):
        super().__init__()
        self.setObjectName("tile")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        self.value = QLabel("–")
        self.value.setObjectName("tileValue")
        self.value.setStyleSheet(f"color: {color};")
        cap = QLabel(caption)
        cap.setObjectName("tileCaption")
        layout.addWidget(self.value)
        layout.addWidget(cap)

    def set(self, n: int | None) -> None:
        self.value.setText("–" if n is None else str(n))


class MainWindow(QMainWindow):
    def __init__(self, store: SnapshotStore | None = None):
        super().__init__()
        self.store = store or SnapshotStore()
        self.inv: Investigation | None = None
        self.worker: Worker | None = None
        self.setWindowTitle(f"{PROJECT_NAME}  ·  v{__version__}")
        self.resize(1360, 820)
        self._build()
        self._refresh_snapshots()
        self._update_banner()

    # ------------------------------------------------------------------ layout
    def _build(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)
        self.act_baseline = QAction("Create Baseline", self, triggered=self.on_baseline)
        self.act_compare = QAction("Compare Now", self, triggered=self.on_compare)
        self.act_diff = QAction("Compare Snapshots…", self, triggered=self.on_diff_selected)
        self.act_report = QAction("Export Report…", self, triggered=self.on_export_report)
        self.act_export = QAction("Export JSON…", self, triggered=self.on_export)
        self.act_store = QAction("Snapshot Store…", self, triggered=self.on_choose_store)
        for act in (self.act_baseline, self.act_compare, self.act_diff):
            tb.addAction(act)
        tb.addSeparator()
        tb.addAction(self.act_report)
        tb.addAction(self.act_export)
        tb.addAction(self.act_store)
        self.act_export.setEnabled(False)
        self.act_report.setEnabled(False)
        live = is_windows()
        for act in (self.act_baseline, self.act_compare):
            act.setEnabled(live)
            if not live:
                act.setToolTip("Live capture only works on Windows — use Compare Snapshots")

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 10, 12, 8)
        root.setSpacing(10)

        self.banner = QLabel()
        self.banner.setObjectName("banner")
        self.banner.setWordWrap(True)
        self.banner.hide()
        root.addWidget(self.banner)

        tiles = QHBoxLayout()
        self.tiles = {lvl: Tile(lvl.capitalize() if lvl != "noise" else "Filtered noise", LEVEL_COLORS[lvl])
                      for lvl in LEVELS}
        for t in self.tiles.values():
            tiles.addWidget(t)
        self.summary = QLabel("Create a baseline, use the system, then Compare Now.")
        self.summary.setStyleSheet("color:#9aa1ab")
        self.summary.setWordWrap(True)
        tiles.addWidget(self.summary, 2)
        root.addLayout(tiles)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.tabs.addTab(self._build_timeline_tab(), "Timeline")
        self.tabs.addTab(self._build_snapshots_tab(), "Snapshots")
        root.addWidget(self.tabs, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        root.addWidget(self.progress)
        self.setCentralWidget(central)
        self.statusBar().showMessage(f"Store: {self.store.root}")

    def _table(self, headers) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(list(headers))
        t.verticalHeader().hide()
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setAlternatingRowColors(True)
        t.setShowGrid(False)
        t.setWordWrap(False)
        t.horizontalHeader().setHighlightSections(False)
        return t

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        bar = QHBoxLayout()
        self.filter = QLineEdit(placeholderText="Filter findings (object, user, category, reason…)")
        self.filter.textChanged.connect(self._fill_findings)
        self.show_noise = QCheckBox("Show filtered noise")
        self.show_noise.toggled.connect(self._fill_findings)
        bar.addWidget(self.filter, 1)
        bar.addWidget(self.show_noise)
        lay.addLayout(bar)

        split = QSplitter(Qt.Horizontal)
        self.findings = self._table(FINDING_COLUMNS)
        self.findings.setSortingEnabled(True)
        self.findings.setSelectionMode(QAbstractItemView.SingleSelection)
        hdr = self.findings.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setSortIndicator(0, Qt.AscendingOrder)   # most severe first by default
        self.findings.itemSelectionChanged.connect(self._show_selected)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(False)
        self.details.setHtml("<p style='color:#9aa1ab'>Select a finding to see why it matters, "
                             "who made it, and the evidence.</p>")
        split.addWidget(self.findings)
        split.addWidget(self.details)
        split.setSizes([760, 560])
        lay.addWidget(split, 1)
        return w

    def _build_timeline_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        self.timeline = self._table(("Time (local)", "Kind", "What happened"))
        self.timeline.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.timeline.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.timeline.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        lay.addWidget(self.timeline)
        return w

    def _build_snapshots_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        bar = QHBoxLayout()
        hint = QLabel("Select two snapshots (older first is automatic) and compare them — works offline.")
        hint.setStyleSheet("color:#9aa1ab")
        self.btn_diff = QPushButton("Compare selected", clicked=self.on_diff_selected)
        self.btn_verify = QPushButton("Verify integrity", clicked=self._refresh_snapshots_verified)
        bar.addWidget(hint, 1)
        bar.addWidget(self.btn_verify)
        bar.addWidget(self.btn_diff)
        lay.addLayout(bar)
        self.snapshots = self._table(("Created (local)", "Kind", "Label", "Host", "Integrity", "ID"))
        self.snapshots.setSelectionMode(QAbstractItemView.MultiSelection)
        self.snapshots.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.snapshots.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        lay.addWidget(self.snapshots)
        return w

    # ------------------------------------------------------------------ state
    def _update_banner(self, extra: list[tuple[str, str]] | None = None) -> None:
        msgs: list[tuple[str, str]] = []
        if is_windows() and not is_admin():
            msgs.append(("warn", "Not running as Administrator — scheduled tasks, other users' registry "
                                 "hives and the Security event log will be missing. Restart WinVault elevated."))
        if not is_windows():
            msgs.append(("info", "Live capture is available on Windows only. You can still open and "
                                 "compare stored snapshots here."))
        msgs += extra or []
        if not msgs:
            self.banner.hide()
            return
        worst = "alert" if any(k == "alert" for k, _ in msgs) else "warn" if any(k == "warn" for k, _ in msgs) else "info"
        # rgba(): Qt reads 8-digit hex as #AARRGGBB, not #RRGGBBAA
        color, tint = {"alert": ("#e5484d", "rgba(229,72,77,0.14)"),
                       "warn": ("#e2a336", "rgba(226,163,54,0.14)"),
                       "info": ("#3e8ed0", "rgba(62,142,208,0.14)")}[worst]
        self.banner.setStyleSheet(f"background:{tint}; border:1px solid {color}; color:#e6e8eb;")
        self.banner.setText("<br>".join(("⚠ " if k != "info" else "") + m for k, m in msgs))
        self.banner.show()

    def _busy(self, on: bool, message: str = "") -> None:
        self.progress.setVisible(on)
        for act in (self.act_baseline, self.act_compare):
            act.setEnabled(not on and is_windows())
        self.act_diff.setEnabled(not on)
        self.btn_diff.setEnabled(not on)
        if message:
            self.statusBar().showMessage(message)

    def _run(self, fn, on_done, start_message: str) -> None:
        if self.worker and self.worker.isRunning():
            return
        self._busy(True, start_message)
        self.worker = Worker(fn, self)
        self.worker.progress.connect(self.statusBar().showMessage)
        self.worker.done.connect(lambda res: (self._busy(False), on_done(res)))
        self.worker.failed.connect(self._failed)
        self.worker.start()

    def _failed(self, detail: str) -> None:
        self._busy(False, "Failed")
        QMessageBox.critical(self, "WinVault", detail)

    # ------------------------------------------------------------------ actions
    def on_baseline(self) -> None:
        label, ok = QInputDialog.getText(self, "Create Baseline", "Label (optional):", text="clean")
        if not ok:
            return
        self._run(lambda progress: capture(self.store, "baseline", label or None, progress=progress),
                  self._baseline_done, "Capturing baseline…")

    def _baseline_done(self, res) -> None:
        snap, path = res
        counts = ", ".join(f"{k} {v['count']}" for k, v in snap["collectors"].items())
        self.statusBar().showMessage(f"Baseline saved: {snap['id']}  ({counts})")
        self._refresh_snapshots()

    def on_compare(self) -> None:
        try:
            self.store.resolve("latest-baseline")
        except KeyError as exc:
            QMessageBox.information(self, "WinVault", str(exc).strip("'"))
            return
        self._run(lambda progress: compare_live(self.store, progress=progress),
                  self.show_investigation, "Capturing and comparing…")

    def on_diff_selected(self) -> None:
        rows = sorted({i.row() for i in self.snapshots.selectedIndexes()})
        if len(rows) != 2:
            self.tabs.setCurrentIndex(2)
            QMessageBox.information(self, "WinVault", "Select exactly two snapshots in the Snapshots tab.")
            return
        ids = sorted((self.snapshots.item(r, 5).text() for r in rows),
                     key=lambda i: self.snapshots.item(self._row_of(i), 0).data(Qt.UserRole))

        def work(progress):
            progress("Loading and verifying snapshots…")
            return investigate(self.store.load(ids[0]), self.store.load(ids[1]))
        self._run(work, self.show_investigation, "Comparing snapshots…")

    def _row_of(self, snap_id: str) -> int:
        for r in range(self.snapshots.rowCount()):
            if self.snapshots.item(r, 5).text() == snap_id:
                return r
        return -1

    def on_export(self) -> None:
        if not self.inv:
            return
        default = str(Path.home() / f"winvault-{self.inv.result.current_id}.json")
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON report", default, "JSON (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.inv.result.to_dict(), indent=2, ensure_ascii=False),
                                  encoding="utf-8")
            self.statusBar().showMessage(f"Report written to {path}")

    def on_export_report(self) -> None:
        if not self.inv:
            return
        from ..report import render_html, snapshot_hashes
        default = str(Path.home() / f"winvault-report-{self.inv.result.current_id}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML report", default, "HTML (*.html)")
        if not path:
            return
        hashes = snapshot_hashes(self.store, self.inv.baseline["id"], self.inv.current["id"])
        Path(path).write_text(render_html(self.inv, hashes), encoding="utf-8")
        self.statusBar().showMessage(f"Report written to {path} — open it and Print → Save as PDF for a PDF")
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def on_choose_store(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose snapshot store", str(self.store.root))
        if path:
            self.store = SnapshotStore(path)
            self.statusBar().showMessage(f"Store: {self.store.root}")
            self._refresh_snapshots()

    # ------------------------------------------------------------------ rendering
    def show_investigation(self, inv: Investigation) -> None:
        self.inv = inv
        r, s = inv.result, inv.stats
        for lvl in ("critical", "high", "medium", "low"):
            self.tiles[lvl].set(s.by_level[lvl])
        self.tiles["noise"].set(s.noise)
        self.summary.setText(f"{s.total} changes · {s.noise} filtered as noise · {s.signal} to review\n"
                             f"{r.baseline_id}  →  {r.current_id}")
        extra = [("alert", f"{local_time(a['time'])}: {a['message']}") for a in r.alerts]
        extra += [("warn", w) for w in r.warnings]
        self._update_banner(extra)
        self._fill_findings()
        self._fill_timeline()
        self.act_export.setEnabled(True)
        self.act_report.setEnabled(True)
        self.tabs.setCurrentIndex(0)
        self._refresh_snapshots()
        self.statusBar().showMessage(f"Done — {s.signal} findings to review, {s.noise} noise filtered")
        if self.findings.rowCount():
            self.findings.selectRow(0)

    def _visible_changes(self) -> list[Change]:
        if not self.inv:
            return []
        needle = self.filter.text().strip().lower()
        out = []
        for c in sorted(self.inv.result.changes, key=sort_key):
            if c.noise and not self.show_noise.isChecked():
                continue
            if needle:
                a = c.attribution or {}
                hay = " ".join([c.category, c.key, display_name(c), c.level, " ".join(c.reasons),
                                str(a.get("user") or ""), str((a.get("process") or {}).get("image") or ""),
                                c.noise or ""]).lower()
                if needle not in hay:
                    continue
            out.append(c)
        return out

    def _fill_findings(self) -> None:
        t = self.findings
        t.setSortingEnabled(False)
        t.setRowCount(0)
        self._row_changes: list[Change] = []
        order = {lvl: i for i, lvl in enumerate(LEVELS)}
        for c in self._visible_changes():
            row = t.rowCount()
            t.insertRow(row)
            level = "noise" if c.noise else c.level
            a = c.attribution or {}
            conf = a.get("confidence") or "—"
            cells = [
                SortItem(level.upper(), (order[level], -c.score)),
                SortItem(str(c.score) if not c.noise else "", c.score),
                SortItem(CATEGORY_LABEL.get(c.category, c.category)),
                SortItem(STATUS_SYMBOL[c.status]),
                SortItem(display_name(c)),
                SortItem(local_time(a["when"]) if a.get("when") else "—", a.get("when") or ""),
                SortItem(a.get("user") or "—"),
                SortItem(conf),
            ]
            cells[0].setForeground(QColor(LEVEL_COLORS[level]))
            f = QFont()
            f.setBold(True)
            cells[0].setFont(f)
            cells[7].setForeground(QColor(CONFIDENCE_COLORS.get(conf, "#9aa1ab")))
            cells[1].setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            cells[3].setTextAlignment(Qt.AlignCenter)
            cells[0].setData(Qt.UserRole, len(self._row_changes))
            for col, item in enumerate(cells):
                t.setItem(row, col, item)
            self._row_changes.append(c)
        t.setSortingEnabled(True)
        hdr = t.horizontalHeader()
        t.sortItems(hdr.sortIndicatorSection(), hdr.sortIndicatorOrder())
        if not t.rowCount():
            self.details.setHtml("<p style='color:#9aa1ab'>No findings match.</p>")

    def _show_selected(self) -> None:
        rows = self.findings.selectionModel().selectedRows()
        if not rows:
            return
        idx = self.findings.item(rows[0].row(), 0).data(Qt.UserRole)
        self.details.setHtml(change_details_html(self._row_changes[idx]))

    def _fill_timeline(self) -> None:
        t = self.timeline
        t.setRowCount(0)
        for e in (self.inv.result.timeline if self.inv else []):
            row = t.rowCount()
            t.insertRow(row)
            when = QTableWidgetItem(local_time(e["time"], ms=True) if e.get("time") else "(undated)")
            kind = QTableWidgetItem({"process": "PROCESS", "event": "EVENT", "change": "CHANGE",
                                     "alert": "ALERT"}[e["kind"]])
            kind.setForeground(QColor(KIND_COLORS[e["kind"]]))
            what = QTableWidgetItem(e["text"])
            if e["kind"] in ("change", "alert"):
                f = QFont()
                f.setBold(True)
                what.setFont(f)
                color = LEVEL_COLORS.get(e.get("level"), KIND_COLORS["alert"]) if e["kind"] == "change" \
                    else KIND_COLORS["alert"]
                what.setForeground(QColor(color))
                kind.setForeground(QColor(color))
            for col, item in enumerate((when, kind, what)):
                t.setItem(row, col, item)

    def _refresh_snapshots(self, verify: bool = False) -> None:
        t = self.snapshots
        t.setRowCount(0)
        try:
            entries = self.store.list()
        except (OSError, ValueError) as exc:
            self.statusBar().showMessage(f"Cannot read store: {exc}")
            return
        for e in reversed(entries):
            row = t.rowCount()
            t.insertRow(row)
            created = QTableWidgetItem(local_time(e["created_utc"]))
            created.setData(Qt.UserRole, e["created_utc"])
            integrity = "not checked"
            color = "#9aa1ab"
            if verify:
                try:
                    ok = self.store.verify(e["id"])
                except OSError:
                    ok = False
                integrity, color = ("OK", "#46a758") if ok else ("TAMPERED", "#e5484d")
            integ = QTableWidgetItem(integrity)
            integ.setForeground(QColor(color))
            for col, item in enumerate((created, QTableWidgetItem(e["kind"]), QTableWidgetItem(e.get("label") or ""),
                                        QTableWidgetItem(e.get("hostname") or ""), integ,
                                        QTableWidgetItem(e["id"]))):
                t.setItem(row, col, item)

    def _refresh_snapshots_verified(self) -> None:
        self._refresh_snapshots(verify=True)
        self.statusBar().showMessage("Integrity check finished")
