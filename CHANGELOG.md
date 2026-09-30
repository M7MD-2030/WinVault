# Changelog

All notable changes to WinVault. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.2] — 2026-10-01
### Added
- `winvault install` now **pins WinVault to the taskbar** on Windows 11 (from an Administrator terminal), next to File Explorer, with its icon. Your existing pins are kept. It uses Windows' own taskbar-layout setting for the current user, and restarts Explorer once so the pin shows up straight away. `--no-pin` skips it.
- `winvault uninstall` removes the taskbar pin and that setting again.

### Changed
- When it can't pin automatically (Windows 10, a non-admin install, or a taskbar layout your organization already manages), `install` says why and how to pin it by hand.

## [1.0.1] — 2026-09-30
### Added
- `winvault install` also adds a **WinVault** Start menu entry for the desktop app, so it can be searched and pinned to the taskbar. `uninstall` removes it.
- `scripts/Update-WinVault.ps1`: install or update to the latest release in one command, with SHA-256 verification against `SHA256SUMS.txt`.

### Fixed
- A pinned WinVault-GUI.exe and its running window no longer show up as two separate taskbar buttons.

## [1.0.0] — 2026-09-29

First stable release, ready for everyday use on Windows 10/11 without a lab setup.

### Added
- **`winvault.exe` works like any command-line tool**: `winvault install` puts it on PATH, so `winvault compare` works from any terminal.
- `winvault status` (store, elevation, auditing at a glance), `--fail-on LEVEL` exit codes for scripts, coloured output (`--no-color` / `NO_COLOR`), help with examples.
- `winvault audit [--enable]` and *Tools → Enable Auditing* in the app: check and turn on the audit settings WinVault uses, without any script.
- Warning when the Security or System log no longer reaches back to the baseline (evidence overwritten).
- App icon, menu bar, About dialog, and Windows version details on the `.exe` files.
- End-user README, development guide, contributing guide, security policy, and issue and PR templates.

### Changed
- Release binaries renamed: `winvault.exe` (command line, runs inside your terminal, no UAC popup) and `WinVault-GUI.exe` (desktop app).
- The snapshot store is created readable only by Administrators and SYSTEM.
- Index updates are protected by a cross-process lock (two runs at once no longer lose entries). Snapshot writes are fsync'd.

## [0.5.0] — 2026-09-29
### Added
- Self-contained HTML investigation report (`--html`, *Export Report…*) with print layout for PDF.
- `files` collector: SHA-256 of critical configuration files (`hosts`, etc.) and a scoring rule.
- Release workflow that builds `WinVault.exe` and `winvault-cli.exe` with `SHA256SUMS.txt`.

### Fixed
- Group membership changes show only the added/removed members in the app.
- `winvault gui` without PySide6 prints a helpful message instead of a traceback.

## [0.4.0] — 2026-09-29
### Added
- Desktop app (PySide6): severity dashboard, findings table with details, timeline, snapshot manager with integrity check, background workers.
- Shared `service` pipeline and Qt-free `presentation` layer.

## [0.3.0] — 2026-09-29
### Added
- Event Log correlation: who / when / which process, with honest confidence levels.
- Timeline view, alert on cleared audit logs, and coverage warnings when auditing is off.
- `scripts/Enable-WinVaultAuditing.ps1`.

## [0.2.0] — 2026-09-29
### Added
- Noise filtering of known Windows activity (tagged with a reason, never dropped).
- Explainable rule-based risk scoring (Low / Medium / High / Critical).

## [0.1.0] — 2026-09-28
### Added
- Collectors: autorun registry, services, scheduled tasks, users and groups, startup folders.
- SHA-256-verified snapshot store, comparison engine, and CLI.
