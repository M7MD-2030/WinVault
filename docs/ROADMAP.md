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

## Phase 2 — Noise filtering & risk scoring
- [ ] `winvault/filters/` — allow-list rules (YAML) for expected churn:
      per-session user services (`*_<hex>` suffix e.g. `CDPUserSvc_1a2b3`),
      Microsoft-signed tasks under `\Microsoft\Windows\`, Defender/Update churn
- [ ] `winvault/rules/` — one rule = match condition + points + reason, loaded from YAML
      so rules can be added without touching the engine
- [ ] Starter rules (20–30), e.g.
      new Run/RunOnce value (+30) · new service (+30) · new task (+30) · runs as SYSTEM (+20)
      · action is powershell/cmd/wscript/mshta/rundll32 (+20) · binary in user-writable path
      (`\Users\`, `\AppData\`, `\Temp\`, `\ProgramData\`) (+20) · hidden task (+15)
      · new local user (+40) · added to Administrators (+50) · Winlogon Shell/Userinit changed (+60)
- [ ] Levels: 0–29 Low · 30–59 Medium · 60–79 High · 80+ Critical, with every contributing reason listed
- [ ] Extra collectors: firewall, Defender prefs/exclusions, hosts file, installed software

## Phase 3 — Event Log correlation & timeline
- [ ] Read Security / System / TaskScheduler / PowerShell / Sysmon logs (pywin32 `win32evtlog` or `wevtutil`)
- [ ] Key IDs: 4688 process create, 4698/4702 task created/updated, 4697/7045 service installed,
      4720 user created, 4732 added to local group, 4657 registry value modified (needs SACL), 4104 script block
- [ ] Correlate by time window (baseline → current), target name, user SID and process
- [ ] Say "undetermined" when evidence is insufficient instead of guessing
- [ ] Chronological timeline per finding

## Phase 4 — GUI (PySide6)
- [ ] Baseline / Compare buttons, dashboard counts per risk level
- [ ] Change details pane: before/after, score breakdown, evidence, hashes
- [ ] Timeline view

## Phase 5 — Reporting & packaging
- [ ] HTML (Jinja2) + JSON report, PDF via HTML
- [ ] Critical file hashing (hosts, lsass/winlogon binaries, etc.)
- [ ] PyInstaller one-file `WinVault.exe` with UAC manifest (`--uac-admin`)
