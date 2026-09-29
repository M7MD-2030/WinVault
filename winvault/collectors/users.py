"""Local users, groups and group membership (incl. Administrators)."""

from __future__ import annotations

from .base import Collector, CollectorError, as_list, is_windows, run_powershell_json

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function D($d) { if ($d) { $d.ToUniversalTime().ToString('o') } else { $null } }
$users = @(Get-LocalUser | ForEach-Object {
  [pscustomobject]@{
    Name = $_.Name; SID = $_.SID.Value; Enabled = $_.Enabled
    Description = $_.Description; PasswordRequired = $_.PasswordRequired
    PasswordExpires = (D $_.PasswordExpires); PasswordLastSet = (D $_.PasswordLastSet)
    AccountExpires = (D $_.AccountExpires); LastLogon = (D $_.LastLogon)
  }
})
$groups = @(Get-LocalGroup | ForEach-Object {
  $g = $_
  $members = @()
  try {
    $members = @(Get-LocalGroupMember -SID $g.SID -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{ Name = $_.Name; SID = $_.SID.Value; Source = "$($_.PrincipalSource)" }
    })
  } catch {
    # Known bug: orphaned SIDs break Get-LocalGroupMember. Fall back to ADSI.
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$($g.Name),group"
    $members = @($adsi.psbase.Invoke('Members') | ForEach-Object {
      $p = $_.GetType().InvokeMember('ADsPath','GetProperty',$null,$_,$null)
      [pscustomobject]@{ Name = ($p -replace '^WinNT://',''); SID = $null; Source = 'ADSI' }
    })
  }
  [pscustomobject]@{ Name = $g.Name; SID = $g.SID.Value; Members = $members }
})
[pscustomobject]@{ users = $users; groups = $groups } | ConvertTo-Json -Depth 5 -Compress
"""


def build_items(data: dict) -> dict[str, dict]:
    """Turn the PowerShell output into snapshot items (split out for testing)."""
    items: dict[str, dict] = {}
    groups = as_list(data.get("groups"))
    member_of: dict[str, list[str]] = {}

    for g in groups:
        members = as_list(g.get("Members"))
        names = sorted(m.get("Name") or "" for m in members)
        items[f"group:{g['SID']}"] = {
            "kind": "group",
            "name": g["Name"],
            "sid": g["SID"],
            "members": names,
        }
        for m in members:
            ident = m.get("SID") or m.get("Name")
            member_of.setdefault(ident, []).append(g["Name"])
            # also index by short name so ADSI fallback entries still match
            short = (m.get("Name") or "").split("\\")[-1].split("/")[-1]
            if short and short != ident:
                member_of.setdefault(short, []).append(g["Name"])

    for u in as_list(data.get("users")):
        groups_of_user = sorted(set(member_of.get(u["SID"], []) + member_of.get(u["Name"], [])))
        items[f"user:{u['SID']}"] = {
            "kind": "user",
            "name": u["Name"],
            "sid": u["SID"],
            "enabled": u.get("Enabled"),
            "description": u.get("Description"),
            "password_required": u.get("PasswordRequired"),
            "password_expires": u.get("PasswordExpires"),
            "password_last_set": u.get("PasswordLastSet"),
            "account_expires": u.get("AccountExpires"),
            "groups": groups_of_user,
            "is_admin": "Administrators" in groups_of_user
            or any(g.get("SID") == "S-1-5-32-544" and _in_group(u, g) for g in groups),
            "_last_logon": u.get("LastLogon"),
        }
    return items


def _in_group(user: dict, group: dict) -> bool:
    for m in as_list(group.get("Members")):
        if m.get("SID") == user["SID"]:
            return True
        name = (m.get("Name") or "").replace("/", "\\").split("\\")[-1]
        if name.lower() == user["Name"].lower():
            return True
    return False


class UsersCollector(Collector):
    name = "users"
    description = "Local user accounts, groups and memberships"

    def collect(self) -> dict[str, dict]:
        if not is_windows():
            raise CollectorError("users collector requires Windows")
        return build_items(run_powershell_json(PS_SCRIPT))
