<#
.SYNOPSIS
    Collects evidence about local administrator membership and local accounts on a Windows host.
.DESCRIPTION
    Read-only. Records the members of the built-in Administrators group (by SID, so it works on localised
    systems), every local account with its enabled state, password flags and last logon, the local
    password policy (net accounts) and writes a hashed JSON envelope.
    No password hashes or secrets are read.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+, Microsoft.PowerShell.LocalAccounts (built in).
                  Standard user is enough; some fields need a local administrator.
    Impact      : Read-only
    Controls    : ISO27001:A.5.15, ISO27001:A.5.18, ISO27001:A.8.2 | CIS8:4.7, CIS8:5.2, CIS8:5.4
    License     : MIT
.EXAMPLE
    .\Get-LocalAdminEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence")
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

$data = [ordered]@{}

# Members of BUILTIN\Administrators (S-1-5-32-544). Get-LocalGroupMember fails with error 1789 on some
# Entra-joined or domain-less hosts when a member SID cannot be resolved; fall back to "net localgroup".
$data.administrators_group = Invoke-EvidenceStep -Name "Administrators group" -Step {
    try {
        $members = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | ForEach-Object {
            [ordered]@{
                name             = $_.Name
                object_class     = $_.ObjectClass
                principal_source = [string]$_.PrincipalSource
                sid              = $_.SID.Value
            }
        })
        $source = "Get-LocalGroupMember"
    } catch {
        $groupName = (Get-LocalGroup -SID "S-1-5-32-544").Name
        $raw = & net.exe localgroup $groupName 2>&1 | ForEach-Object { [string]$_ }
        $start = [array]::IndexOf($raw, ($raw | Where-Object { $_ -match "^-{10,}" } | Select-Object -First 1)) + 1
        $members = @($raw[$start..($raw.Count - 1)] |
            Where-Object { $_ -and $_ -notmatch "^(The command completed|La commande s)" -and $_ -notmatch "^\s*$" } |
            ForEach-Object {
                $n = $_.Trim()
                [ordered]@{
                    name             = $n
                    object_class     = $null
                    principal_source = if ($n -match "^(S-1-12-1-|S-1-5-21-)") { "Unresolved" } elseif ($n -match "\\") { "Domain" } else { "Local" }
                    sid              = if ($n -match "^S-1-") { $n } else { $null }
                }
            })
        $source = "net localgroup (fallback after: $($_.Exception.Message))"
    }
    [ordered]@{
        source       = $source
        member_count = $members.Count
        members      = $members
    }
}

# Local accounts
$data.local_users = Invoke-EvidenceStep -Name "Local users" -Step {
    @(Get-LocalUser | ForEach-Object {
        [ordered]@{
            name                 = $_.Name
            enabled              = [bool]$_.Enabled
            is_builtin_admin     = ($_.SID.Value -like "*-500")
            is_builtin_guest     = ($_.SID.Value -like "*-501")
            password_required    = [bool]$_.PasswordRequired
            password_expires     = if ($_.PasswordExpires) { $_.PasswordExpires.ToUniversalTime().ToString("o") } else { $null }
            password_last_set    = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToUniversalTime().ToString("o") } else { $null }
            last_logon           = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString("o") } else { $null }
            user_may_change_pwd  = [bool]$_.UserMayChangePassword
            description          = $_.Description
        }
    })
}

# Local password / lockout policy as reported by "net accounts"
$data.password_policy = Invoke-EvidenceStep -Name "net accounts" -Step {
    $lines = & net.exe accounts 2>&1 | Where-Object { $_ -match ":" }
    $policy = [ordered]@{}
    foreach ($line in $lines) {
        $parts = $line -split ":\s*", 2
        if ($parts.Count -eq 2) { $policy[($parts[0].Trim() -replace "\s+", "_").ToLowerInvariant()] = $parts[1].Trim() }
    }
    $policy
}

# Summary that an auditor can read without scrolling
$data.summary = Invoke-EvidenceStep -Name "Summary" -Step {
    $users = @($data.local_users | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains("name") })
    $admins = if ($data.administrators_group -is [System.Collections.IDictionary] -and $data.administrators_group.Contains("members")) { @($data.administrators_group.members) } else { @() }
    [ordered]@{
        administrators_count      = $admins.Count
        local_admin_members       = @($admins | Where-Object { $_.principal_source -eq "Local" } | ForEach-Object { $_.name })
        domain_or_entra_members   = @($admins | Where-Object { $_.principal_source -ne "Local" } | ForEach-Object { $_.name })
        local_users_total         = $users.Count
        local_users_enabled       = @($users | Where-Object { $_.enabled }).Count
        builtin_admin_enabled     = [bool]($users | Where-Object { $_.is_builtin_admin -and $_.enabled })
        builtin_guest_enabled     = [bool]($users | Where-Object { $_.is_builtin_guest -and $_.enabled })
        enabled_without_password  = @($users | Where-Object { $_.enabled -and -not $_.password_required } | ForEach-Object { $_.name })
    }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.5.15", "ISO27001:A.5.18", "ISO27001:A.8.2", "CIS8:4.7", "CIS8:5.2", "CIS8:5.4") `
    -Collector "windows/Get-LocalAdminEvidence.ps1" `
    -Data $data

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
