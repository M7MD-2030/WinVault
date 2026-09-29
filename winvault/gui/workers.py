"""Run slow work (snapshots, event queries) off the UI thread."""

from __future__ import annotations

import traceback

from PySide6.QtCore import QThread, Signal


class Worker(QThread):
    """Runs ``fn(progress=callback)`` in a background thread.

    Signals are delivered on the UI thread, so handlers may touch widgets.
    """

    progress = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D401 - Qt override
        try:
            self.done.emit(self._fn(progress=self.progress.emit))
        except Exception as exc:  # surface every failure in the UI, never crash silently
            detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
            self.failed.emit(detail)
