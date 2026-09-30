"""WinVault desktop app (Phase 4). Start with `winvault gui` or `winvault-gui`."""

from __future__ import annotations

import sys
from pathlib import Path


ICON = Path(__file__).parent / "assets" / "winvault.png"


def main(store: str | None = None) -> int:
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    from ..snapshot import SnapshotStore
    from .main_window import MainWindow
    from .theme import apply_theme

    if sys.platform == "win32" and not getattr(sys, "frozen", False):
        # Running from source under python.exe: give the window its own taskbar identity so
        # Windows shows the WinVault icon instead of Python's. NOT done for WinVault-GUI.exe:
        # there Windows already identifies it by the .exe, and an explicit ID would make a
        # pinned taskbar shortcut and the running window show up as two separate buttons.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("M7MD-2030.WinVault")
        except (AttributeError, OSError):
            pass

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("WinVault")
    if ICON.exists():
        app.setWindowIcon(QIcon(str(ICON)))
    apply_theme(app)
    win = MainWindow(SnapshotStore(store) if store else None)
    win.show()
    return app.exec()


def run() -> None:
    """Console-script entry point for `winvault-gui`."""
    sys.exit(main())
