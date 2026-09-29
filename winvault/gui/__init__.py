"""WinVault desktop app (Phase 4). Start with `winvault gui` or `winvault-gui`."""

from __future__ import annotations

import sys


def main(store: str | None = None) -> int:
    from PySide6.QtWidgets import QApplication

    from ..snapshot import SnapshotStore
    from .main_window import MainWindow
    from .theme import apply_theme

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("WinVault")
    apply_theme(app)
    win = MainWindow(SnapshotStore(store) if store else None)
    win.show()
    return app.exec()


def run() -> None:
    """Console-script entry point for `winvault-gui`."""
    sys.exit(main())
