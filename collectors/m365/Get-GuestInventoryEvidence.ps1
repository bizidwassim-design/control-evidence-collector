<#
.SYNOPSIS
    Collects guest (external) account inventory evidence from a Microsoft Entra ID tenant (read-only).
.DESCRIPTION
    Signs in interactively (no stored credentials), lists every guest user and summarises: total,
    enabled, invitation state, accounts created in the last 30 days, accounts with no sign-in for
    90+ days, accounts that never signed in, and the number of guests per home domain. The external
    collaboration settings (who may invite, guest permissions) are recorded when the scope allows.
    Per-guest rows are included only with -IncludeUsers.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns.
                  Delegated scopes: User.Read.All, AuditLog.Read.All (sign-in activity, needs Entra ID P1/P2),
                  Policy.Read.All (collaboration settings). All read-only.
    Impact      : Read-only. Interactive sign-in.
    Controls    : ISO27001:A.5.16, ISO27001:A.5.18, ISO27001:A.5.19 | CIS8:5.1, CIS8:5.3, CIS8:6.1
    License     : MIT
.EXAMPLE
    .\Get-GuestInventoryEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4 -InactiveDays 90
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [int]$InactiveDays = 90,
    [switch]$IncludeUsers,
    [string]$TenantId
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

foreach ($m in "Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Identity.SignIns") {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is not installed. Run: Install-Module $m -Scope CurrentUser" }
}
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.SignIns

$connectParams = @{ Scopes = @("User.Read.All", "AuditLog.Read.All", "Policy.Read.All"); NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph." }

$now = [datetime]::UtcNow
$properties = "id,userPrincipalName,displayName,mail,createdDateTime,accountEnabled,externalUserState,externalUserStateChangeDateTime,creationType,signInActivity"

$data = [ordered]@{
    tenant_id     = $ctx.TenantId
    scopes_used   = @($ctx.Scopes)
    inactive_days = $InactiveDays
}

$data.guests = Invoke-EvidenceStep -Name "Guest users" -Step {
    try {
        $guests = @(Get-MgUser -Filter "userType eq 'Guest'" -All -Property $properties -ConsistencyLevel eventual -CountVariable guestCount)
        $signInAvailable = $true
    } catch {
        # signInActivity needs AuditLog.Read.All and a P1/P2 licence; retry without it
        $guests = @(Get-MgUser -Filter "userType eq 'Guest'" -All -Property ($properties -replace ",signInActivity", ""))
        $signInAvailable = $false
    }

    $rows = @($guests | ForEach-Object {
        $last = $null
        if ($signInAvailable -and $_.SignInActivity) {
            $candidates = @($_.SignInActivity.LastSignInDateTime, $_.SignInActivity.LastNonInteractiveSignInDateTime) | Where-Object { $_ }
            if ($candidates) { $last = ($candidates | Sort-Object -Descending | Select-Object -First 1) }
        }
        $domain = if ($_.Mail) { ($_.Mail -split "@")[-1].ToLowerInvariant() } elseif ($_.UserPrincipalName -match "#EXT#") { (($_.UserPrincipalName -split "#EXT#")[0] -split "_")[-1].ToLowerInvariant() } else { "unknown" }
        [ordered]@{
            user_principal_name   = $_.UserPrincipalName
            display_name          = $_.DisplayName
            home_domain           = $domain
            account_enabled       = [bool]$_.AccountEnabled
            external_user_state   = $_.ExternalUserState
            creation_type         = $_.CreationType
            created_utc           = if ($_.CreatedDateTime) { $_.CreatedDateTime.ToUniversalTime().ToString("o") } else { $null }
            last_sign_in_utc      = if ($last) { $last.ToUniversalTime().ToString("o") } else { $null }
            days_since_sign_in    = if ($last) { [int]($now - $last.ToUniversalTime()).TotalDays } else { $null }
            days_since_created    = if ($_.CreatedDateTime) { [int]($now - $_.CreatedDateTime.ToUniversalTime()).TotalDays } else { $null }
        }
    })

    $domainCounts = [ordered]@{}
    foreach ($r in ($rows | Sort-Object home_domain)) {
        if ($domainCounts.Contains($r.home_domain)) { $domainCounts[$r.home_domain] = $domainCounts[$r.home_domain] + 1 } else { $domainCounts[$r.home_domain] = 1 }
    }

    $result = [ordered]@{
        sign_in_activity_available = $signInAvailable
        total                      = $rows.Count
        enabled                    = @($rows | Where-Object { $_.account_enabled }).Count
        disabled                   = @($rows | Where-Object { -not $_.account_enabled }).Count
        pending_acceptance         = @($rows | Where-Object { $_.external_user_state -eq "PendingAcceptance" }).Count
        created_last_30_days       = @($rows | Where-Object { $null -ne $_.days_since_created -and $_.days_since_created -le 30 }).Count
        inactive_over_threshold    = if ($signInAvailable) { @($rows | Where-Object { $_.account_enabled -and $null -ne $_.days_since_sign_in -and $_.days_since_sign_in -ge $InactiveDays }).Count } else { $null }
        never_signed_in            = if ($signInAvailable) { @($rows | Where-Object { $_.account_enabled -and $null -eq $_.days_since_sign_in }).Count } else { $null }
        home_domains               = $domainCounts.Count
        guests_per_home_domain     = $domainCounts
    }
    if ($IncludeUsers) { $result.users = $rows }
    $result
}

$data.external_collaboration = Invoke-EvidenceStep -Name "Authorization policy" -Step {
    $p = Get-MgPolicyAuthorizationPolicy
    [ordered]@{
        allow_invites_from                 = [string]$p.AllowInvitesFrom
        guest_user_role_id                 = $p.GuestUserRoleId
        allow_email_verified_users_to_join = [bool]$p.AllowEmailVerifiedUsersToJoinOrganization
        block_msol_powershell              = [bool]$p.BlockMsolPowerShell
    }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.5.16", "ISO27001:A.5.18", "ISO27001:A.5.19", "CIS8:5.1", "CIS8:5.3", "CIS8:6.1") `
    -Collector "m365/Get-GuestInventoryEvidence.ps1" `
    -Data $data `
    -HostName ("entra-tenant:" + $ctx.TenantId) `
    -CollectedBy $ctx.Account

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Disconnect-MgGraph | Out-Null
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
