"""Colours and the dark Fusion palette used by the desktop app."""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

# Level / confidence / kind colours live in winvault.presentation (shared with the HTML report).

BG = "#16181c"
PANEL = "#1e2127"
BORDER = "#2c3038"
TEXT = "#e6e8eb"
MUTED = "#9aa1ab"
ACCENT = "#3e8ed0"

STYLESHEET = f"""
QMainWindow, QWidget {{ background: {BG}; color: {TEXT}; font-size: 10pt; }}
QMenuBar {{ background: {PANEL}; border-bottom: 1px solid {BORDER}; padding: 2px 4px; }}
QMenuBar::item {{ padding: 4px 10px; border-radius: 4px; background: transparent; }}
QMenuBar::item:selected {{ background: {BORDER}; }}
QMenu {{ background: {PANEL}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 12px; border-radius: 4px; }}
QMenu::item:selected {{ background: #2b3a4d; }}
QMenu::item:disabled {{ color: {MUTED}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 8px; }}
QToolBar {{ background: {PANEL}; border-bottom: 1px solid {BORDER}; spacing: 6px; padding: 6px; }}
QToolButton {{ padding: 6px 12px; border-radius: 6px; }}
QToolButton:hover {{ background: {BORDER}; }}
QToolButton:disabled {{ color: {MUTED}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{ background: {PANEL}; padding: 8px 16px; border: 1px solid {BORDER};
               border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; }}
QTabBar::tab:selected {{ background: {BG}; color: {TEXT}; }}
QTabBar::tab:!selected {{ color: {MUTED}; }}
QTableWidget {{ background: {PANEL}; gridline-color: {BORDER}; border: 1px solid {BORDER};
               border-radius: 6px; selection-background-color: #2b3a4d; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 6px; border: none;
                       border-bottom: 1px solid {BORDER}; font-weight: 600; }}
QTextBrowser {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 8px; }}
QLineEdit {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 8px; }}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QPushButton {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 14px; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {MUTED}; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; border-top: 1px solid {BORDER}; }}
QSplitter::handle {{ background: {BORDER}; }}
QFrame#tile {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 8px; }}
QFrame#tile QLabel {{ background: transparent; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {MUTED}; border-radius: 3px;
                        background: {PANEL}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QLabel#tileValue {{ font-size: 22pt; font-weight: 700; }}
QLabel#tileCaption {{ color: {MUTED}; font-size: 9pt; }}
QLabel#banner {{ border-radius: 6px; padding: 8px 10px; }}
QProgressBar {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 4px; max-height: 6px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}
"""


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    pal = QPalette()
    for role, color in (
        (QPalette.Window, BG), (QPalette.WindowText, TEXT), (QPalette.Base, PANEL),
        (QPalette.AlternateBase, "#20242b"), (QPalette.Text, TEXT), (QPalette.Button, PANEL),
        (QPalette.ButtonText, TEXT), (QPalette.Highlight, "#2b3a4d"), (QPalette.HighlightedText, TEXT),
        (QPalette.ToolTipBase, PANEL), (QPalette.ToolTipText, TEXT), (QPalette.PlaceholderText, MUTED),
    ):
        pal.setColor(role, QColor(color))
    app.setPalette(pal)
    app.setStyleSheet(STYLESHEET)
