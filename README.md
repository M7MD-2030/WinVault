# WinVault — Digital Evidence & Forensic Analysis

> Security-focused change analysis for Windows. Capture a baseline, let the system run, capture again, and find out **what changed, whether it matters, and why**.

![CI](https://github.com/M7MD-2030/WinVault/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![License](https://img.shields.io/badge/license-MIT-green)

![WinVault detecting test changes](docs/images/compare.png)

Tools like Regshot show *every* difference between two points in time, and a normal Windows machine creates thousands of them in minutes. WinVault collects only **security-relevant** state (persistence locations, services, scheduled tasks, accounts, startup items), compares it, and (in upcoming phases) filters out the noise, scores what's left with explainable rules, and ties each finding back to Windows Event Log evidence.

```
Detect → Filter → Analyze → Correlate → Explain → Report
```

## Status

| Phase | Scope | Status |
|---|---|---|
| **1 — MVP** | Registry, Services, Scheduled Tasks, Users & Groups, Startup collectors · snapshot store · comparison engine · CLI | ✅ done |
| 2 | Noise filtering · rule-based risk scoring · explanations | ⏳ next |
| 3 | Event Log collection · correlation · timeline | planned |
| 4 | PySide6 GUI · dashboard · change details | planned |
| 5 | HTML/PDF/JSON reports · file hashing · packaging (PyInstaller) | planned |

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full design.

## What Phase 1 collects

| Collector | Source | Key fields |
|---|---|---|
| `registry` | Run / RunOnce / Policies\Explorer\Run (HKLM + every loaded user hive), Winlogon `Shell`/`Userinit`, `AppInit_DLLs`, `BootExecute`, LSA packages, `UserInitMprLogonScript` | value, type, owning SID, key last-write time |
| `services` | `HKLM\SYSTEM\CurrentControlSet\Services` | image path, ServiceDll, start type, account |
| `tasks` | `%SystemRoot%\System32\Tasks` XML | actions, triggers, run-as principal, run level, hidden flag, SHA-256 |
| `users` | Local users & groups | enabled, groups, admin membership, password metadata |
| `startup` | All-users + per-profile Startup folders | SHA-256, size, timestamps |

## Evidence handling

Every snapshot is written once as JSON and its SHA-256 is recorded in `index.json`. Every load re-hashes the file and refuses to use it if it has changed, and `winvault verify` checks the whole store. Volatile fields such as timestamps are kept as evidence but never count as a "modification".

## Quick start

Run these on Windows from an **elevated** terminal:

```powershell
git clone https://github.com/M7MD-2030/WinVault.git
cd WinVault
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

winvault baseline --label "clean install"
# ... use the machine, install something, etc ...
winvault compare --json report.json
```

Other commands:

```powershell
winvault list                      # stored snapshots
winvault verify                    # re-hash every snapshot (tamper check)
winvault diff <idA> <idB>          # compare two stored snapshots
winvault diff a.json b.json        # compare snapshot files — works on Linux too
winvault compare --only registry,tasks
```

The snapshot store defaults to `%ProgramData%\WinVault`. Override it with `--store DIR` or `WINVAULT_STORE`.

### Verify detection

`scripts/Test-WinVaultChanges.ps1` makes one harmless, clearly labelled change per collector. Each change points at `notepad.exe` and nothing is ever executed. Run it only in your test VM:

```powershell
winvault baseline --label clean
.\scripts\Test-WinVaultChanges.ps1
winvault compare
.\scripts\Test-WinVaultChanges.ps1 -Cleanup
```

CI runs this exact loop on a GitHub Windows runner on every push.

## Lab setup

See [`docs/VM_SETUP.md`](docs/VM_SETUP.md) for building the Windows development VM on KVM/libvirt.

## Architecture

```
winvault/
├── collectors/      # one module per artifact source → {stable_key: attributes}
├── snapshot.py      # Snapshot Manager: capture, store, hash-verify
├── compare.py       # Comparison Engine: added / removed / modified / unchanged
├── models.py        # Change, FieldChange, ComparisonResult
└── cli.py           # command line (GUI arrives in Phase 4)
```

To add a collector, subclass `Collector`, return `{key: {...}}` from `collect()`, and register it in `collectors/__init__.py`. The comparison engine needs no changes.

## Disclaimer

WinVault is a defensive forensics and education project. Run it only on systems you own or are authorised to examine. Snapshots contain host details such as usernames, SIDs and paths, so don't commit or share them.

## License

MIT, see [LICENSE](LICENSE).
