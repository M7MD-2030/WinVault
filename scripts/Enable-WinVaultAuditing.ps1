<#
.SYNOPSIS
  Turns on the Windows audit settings WinVault uses as evidence (Phase 3).

.DESCRIPTION
  Out of the box Windows does not record which process created what, and it
  does not log scheduled-task creation. This script enables:

    Process Creation            4688  (+ full command lines)
    User Account Management     4720 4722 4724 4725 4726 4738
    Security Group Management   4732 4733
    Other Object Access Events  4698 4699 4702   (scheduled tasks)
    Security System Extension   4697             (service installs)
    Task Scheduler Operational log               (106 140 141)

  It also raises the Security log to 256 MB so evidence is not overwritten
  quickly. Settings persist across reboots. Run once in the dev VM, then
  commit it into the clean base (see docs/VM_SETUP.md).

.EXAMPLE
  .\scripts\Enable-WinVaultAuditing.ps1           # enable + show status
  .\scripts\Enable-WinVaultAuditing.ps1 -Status   # show status only
#>
[CmdletBinding()]
param([switch]$Status)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated (Administrator) PowerShell.'
}

# Subcategory GUIDs are language-independent (names differ on non-English Windows).
$subcategories = [ordered]@{
    'Process Creation (4688)'                    = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'User Account Management (4720..4738)'       = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management (4732/4733)'      = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events (4698/4702)'     = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Security System Extension (4697)'           = '{0CCE9211-69AE-11D9-BED3-505054503030}'
}
$auditKey  = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$taskLog   = 'Microsoft-Windows-TaskScheduler/Operational'

if (-not $Status) {
    foreach ($guid in $subcategories.Values) {
        auditpol.exe /set "/subcategory:$guid" /success:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $guid" }
    }
    # Make subcategory settings win over legacy category policy.
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord
    # Include the full command line in 4688 events.
    New-Item -Path $auditKey -Force | Out-Null
    Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    wevtutil.exe sl $taskLog /e:true
    wevtutil.exe sl Security /ms:268435456
    Write-Host 'WinVault auditing enabled.' -ForegroundColor Green
}

Write-Host ''
foreach ($name in $subcategories.Keys) {
    $row = auditpol.exe /get "/subcategory:$($subcategories[$name])" /r | ConvertFrom-Csv
    '{0,-42} {1}' -f $name, $row.'Inclusion Setting'
}
$cmd = (Get-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
'{0,-42} {1}' -f 'Command line in 4688', $(if ($cmd -eq 1) { 'Enabled' } else { 'Disabled' })
'{0,-42} {1}' -f 'Task Scheduler Operational log', $(if ((Get-WinEvent -ListLog $taskLog).IsEnabled) { 'Enabled' } else { 'Disabled' })
