# Contributing to WinVault

Thanks for helping! Bug reports, new detection rules, noise rules, collectors and docs are all welcome.

## Getting started

```powershell
git clone https://github.com/M7MD-2030/WinVault.git
cd WinVault
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev,gui]"
$env:QT_QPA_PLATFORM = "offscreen"; pytest -q
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the architecture and where each kind of change goes.

## Ground rules

1. **Every change comes with tests.** Detection logic especially: add a case that must match and one that must not.
2. **Noise rules must be narrow.** A noise rule decides what analysts *don't* see. Match the exact benign transformation (same identity, official location, nothing else changed) and add an adversarial look-alike test that must stay visible.
3. **Never guess attribution.** Link evidence by the object it names (SID, service, task path), not by time proximity. If the evidence isn't there, the answer is *undetermined*.
4. **No real host data in the repo.** Snapshots and reports contain account names, SIDs and paths. Use synthetic fixtures in tests.
5. **Keep it dependency-light.** The core runs on the standard library, and PySide6 is only for the app.

## Pull requests

- One focused change per PR, with a short description of *why*.
- CI must be green: unit tests on Ubuntu (Python 3.10) and Windows (Python 3.12), plus the end-to-end Windows smoke test.
- Update `CHANGELOG.md` under an *Unreleased* heading.

## Reporting bugs

Use the issue templates. Include your Windows version, how you ran WinVault (exe, CLI or source), and the warnings it printed. Remove host-specific details you don't want to share.
