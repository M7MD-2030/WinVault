# Development & testing

## Architecture

```
capture ──► compare ──► analyze ──────────► correlate ──────► present
collectors/  compare.py  analysis/noise.py   correlation.py    cli.py
snapshot.py              analysis/rules.py   events/           gui/
                                                               report.py
```

| Module | Responsibility |
|---|---|
| `winvault/collectors/` | One module per artifact source. Each returns `{stable_key: attributes}`. Keys starting with `_` are evidence metadata (timestamps) and never count as a modification. |
| `winvault/snapshot.py` | Capture, store and verify. Snapshots are written atomically (fsync), their SHA-256 is recorded in `index.json` under a cross-process lock, and every load re-hashes the file. The store is restricted to Administrators and SYSTEM on creation. |
| `winvault/compare.py` | Pairs objects by key: added / removed / modified / unchanged. |
| `winvault/analysis/noise.py` | Tags expected Windows activity with a reason. Rules must be **narrow**: the same identity moving to an official location, nothing else changed. A loose noise rule is a hiding place. |
| `winvault/analysis/rules.py` | Points and reasons per finding, mapped to Low / Medium / High / Critical. |
| `winvault/events/` | Reads Event Log evidence for the baseline→now window (UTC XPath) and stores it inside the current snapshot. |
| `winvault/correlation.py` | Links changes to events **by target** (SID, service, task path), and to processes by whole-word command-line match. Never by time proximity alone. |
| `winvault/service.py` | The single pipeline used by the CLI and the app. |
| `winvault/presentation.py`, `report.py`, `gui/` | Rendering. `presentation.py` is Qt-free and shared by the app and the HTML report. |
| `winvault/auditing.py` | Status / enable of the Windows audit settings (language-independent subcategory GUIDs). |

### Extending

- **New collector:** subclass `Collector` in `winvault/collectors/`, return stable keys, and register it in `collectors/__init__.py`. Nothing else needs to change.
- **New scoring rule:** add a `@rule(...)` function in `analysis/rules.py` returning `(points, reason)` or `None`, plus a test in `tests/test_rules.py`.
- **New noise rule:** add it in `analysis/noise.py` **with an adversarial test**: a look-alike that must *not* be filtered (see `tests/test_noise.py`).
- **New evidence:** add the event ID to `events/reader.py:QUERIES`, a summary in `events/describe.py`, and a matcher in `correlation.py`.

## Tests

```powershell
pip install -e ".[dev,gui]"
$env:QT_QPA_PLATFORM = "offscreen"     # the app tests run headless
pytest -q
```

Most tests are platform-independent (they run on Linux too). CI runs:

| Job | What |
|---|---|
| `unit-tests` (Ubuntu, Python 3.10) | Core logic on the oldest supported Python |
| `unit-tests` (Windows, Python 3.12) | Everything, including the desktop app headless |
| `windows-smoke` | End to end on a real Windows runner: enable auditing → baseline → `scripts/Test-WinVaultChanges.ps1` → compare → asserts that each test change is detected, scored, not filtered, and tied to its audit event, and that the HTML report is written |
| `release.yml` | On a published release: builds `winvault.exe` (CLI) and `WinVault-GUI.exe` (app) with PyInstaller, smoke-tests the CLI and `winvault install`, and attaches both with `SHA256SUMS.txt` |

## Test changes & the lab VM

`scripts/Test-WinVaultChanges.ps1` makes one harmless, clearly labelled change per area (everything is named `WinVaultTest*` and points at `notepad.exe`; nothing is executed), and `-Cleanup` removes them. **Run it only on a disposable machine**, such as the lab VM in [VM_SETUP.md](VM_SETUP.md) or the CI runner.

```powershell
winvault baseline --label clean
.\scripts\Test-WinVaultChanges.ps1
winvault compare --timeline --html report.html
.\scripts\Test-WinVaultChanges.ps1 -Cleanup     # always clean up before the next run
```

## Releasing

1. Bump `version` in `pyproject.toml` and `winvault/__init__.py`, and add a `CHANGELOG.md` entry.
2. Commit and push, then wait for CI to go green.
3. Run `gh release create vX.Y.Z --title "..." --notes "..."`. The release workflow builds and attaches the binaries.
