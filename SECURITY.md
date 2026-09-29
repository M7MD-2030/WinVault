# Security policy

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability reporting).

Include the version, steps to reproduce, and the impact. You'll get an acknowledgement within a few days. Please give reasonable time for a fix before public disclosure.

## In scope

- A snapshot or report being modified without WinVault's integrity check noticing
- Untrusted data from the machine (registry values, task definitions, event fields) causing code execution or script injection in the app or the HTML report
- A way for a change to be hidden by the noise filter when it shouldn't be
- Privilege or permission problems with the snapshot store

## Handling evidence

Snapshots and reports contain account names, SIDs, file paths and command lines from the examined machine. The default store (`%ProgramData%\WinVault`) is restricted to Administrators and SYSTEM. Treat exported reports as sensitive.
