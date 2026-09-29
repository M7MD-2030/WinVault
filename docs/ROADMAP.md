# WinVault Roadmap

## Phase 1 — MVP ✅
- [x] Registry persistence collector
- [x] Services collector
- [x] Scheduled Tasks collector
- [x] Users / groups / privileges collector
- [x] Startup folder collector
- [x] Snapshot creation + hash-verified storage
- [x] Comparison engine (added / removed / modified / unchanged)
- [x] CLI + CI end-to-end detection test

## Phase 2 — Noise filtering & risk scoring ✅
- [x] `winvault/analysis/noise.py` — tight, auditable noise rules. Noise is tagged
      with a reason and hidden by default (`--show-noise` reveals it), never dropped.
      Rules: Defender platform move (same binary, ProgramFiles → versioned Platform dir),
      Setup transient accounts (`defaultuser0`), Microsoft `\Microsoft\Windows\` tasks
      whose only change is the file hash, per-user service instances (`Name_<hex>` on svchost).
      Every rule is deliberately narrow so a look-alike path can't hide in it.
- [x] `winvault/analysis/rules.py` — points + reason per rule; the reasons list *is*
      the justification, so no bare "CRITICAL" without an explanation.
      new autorun value +30 · new service +30 · new task +30 · new startup item +25
      · runs as SYSTEM +20 · uses interpreter (powershell/cmd/mshta/rundll32/…) +20
      · binary in user-writable path +20 · hidden task +15 · Winlogon Shell/Userinit +60
      · new local user +40 (direct into Administrators +90) · added to Administrators +50
      · security service disabled +60
- [x] Levels: 0–29 Low · 30–59 Medium · 60–79 High · 80+ Critical
- [x] `winvault compare` sorts by score, shows level + points + reasons, hides noise;
      full detail (incl. `analysis`) in `--json`. CI asserts the new admin user scores critical.
- [ ] Extra collectors: firewall, Defender prefs/exclusions, hosts file, installed software (Phase 2.1)

## Phase 3 — Event Log correlation & timeline ✅
- [x] `winvault/events/` — Get-WinEvent with a UTC XPath window (baseline → now); events are
      stored inside the current snapshot, so they share its SHA-256 integrity check and
      `winvault diff` can re-correlate offline
- [x] IDs: 4720/4722/4724/4725/4726/4738 accounts · 4732/4733 groups · 4697/7045/7040 services
      · 4698/4699/4702 + TaskScheduler 106/140/141 tasks · 4688 processes · 1102/104 log cleared
- [x] `winvault/correlation.py` — match on the target (SID, service, task path), process via
      whole-word command-line match, never on time proximity alone
- [x] Honest confidence (high / medium / low / none) with an explanation; "undetermined" instead of guessing
- [x] Alerts when an audit log was cleared inside the window
- [x] `--timeline` chronological view; coverage warnings when auditing is off
- [x] `scripts/Enable-WinVaultAuditing.ps1` (language-independent subcategory GUIDs)
- [ ] Later: PowerShell 4104 script blocks, Sysmon (1/12/13), registry SACL-based 4657

## Phase 4 — GUI (PySide6) ✅
- [x] `winvault/service.py` — one pipeline (capture → compare → analyze → correlate) shared by CLI and GUI
- [x] `winvault/presentation.py` — Qt-free rendering (colours, labels, finding details HTML) reused by the Phase 5 report
- [x] Toolbar: Create Baseline · Compare Now · Compare Snapshots · Export JSON · Snapshot Store
- [x] Dashboard tiles per risk level + noise; findings table (severity-sorted, filter, show-noise toggle)
- [x] Details pane: score breakdown, before/after, attribution, grouped evidence
- [x] Timeline tab; Snapshots tab with integrity verification and offline compare
- [x] Background worker thread (UI never freezes), elevation / alert / coverage banner
- [x] Headless smoke tests (Qt offscreen) run in CI on Windows

## Phase 5 — Reporting & packaging ✅
- [x] `winvault/report.py`: self-contained HTML report (no external assets, all values HTML-escaped),
      print CSS for PDF via the browser; `--html` in the CLI, *Export Report…* in the app
- [x] `files` collector: SHA-256 of critical config files (`drivers\etc\hosts` etc.) + scoring rule
- [x] `.github/workflows/release.yml`: on each published release, PyInstaller builds `WinVault.exe`
      (windowed) and `winvault-cli.exe` (console, Qt excluded), both with a UAC manifest,
      smoke-tests the CLI binary, and attaches them with `SHA256SUMS.txt`
- [ ] Later: code-signing the binaries, hashing more OS files, Sysmon / PowerShell 4104 evidence
