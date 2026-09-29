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
