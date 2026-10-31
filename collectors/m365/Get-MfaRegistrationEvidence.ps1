<#
.SYNOPSIS
    Collects MFA registration evidence for a Microsoft Entra ID tenant through Microsoft Graph (read-only).
.DESCRIPTION
    Signs in interactively (no stored credentials, no app secrets), reads the authentication-methods
    user registration report and summarises it: users registered and capable for MFA, passwordless
    capability, SSPR registration, admins without MFA and the distribution of registered methods.
    Per-user rows are included only with -IncludeUsers; by default the evidence stays aggregate so it
    can be shared with an auditor without exposing a user list.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Microsoft.Graph.Authentication and Microsoft.Graph.Reports (Install-Module Microsoft.Graph.Reports).
                  Delegated scopes: UserAuthenticationMethod.Read.All, AuditLog.Read.All (read-only).
                  A role such as Global Reader or Reports Reader is sufficient.
    Impact      : Read-only. Interactive sign-in; nothing is cached by this script.
    Controls    : ISO27001:A.5.17, ISO27001:A.8.5 | CIS8:6.3, CIS8:6.5
    License     : MIT
.EXAMPLE
    .\Get-MfaRegistrationEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
.EXAMPLE
    .\Get-MfaRegistrationEvidence.ps1 -IncludeUsers    # adds the list of users and admins without MFA
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [switch]$IncludeUsers,
    [string]$TenantId
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

foreach ($m in "Microsoft.Graph.Authentication", "Microsoft.Graph.Reports") {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is not installed. Run: Install-Module $m -Scope CurrentUser" }
}
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Reports

$scopes = @("UserAuthenticationMethod.Read.All", "AuditLog.Read.All")
$connectParams = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph." }

$data = [ordered]@{
    tenant_id     = $ctx.TenantId
    scopes_used   = @($ctx.Scopes)
    auth_type     = [string]$ctx.AuthType
}

$data.registration = Invoke-EvidenceStep -Name "User registration details" -Step {
    $rows = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All)
    $members = @($rows | Where-Object { $_.UserType -eq "member" })
    $admins  = @($rows | Where-Object { $_.IsAdmin })

    $methodCounts = [ordered]@{}
    foreach ($r in $rows) {
        foreach ($m in @($r.MethodsRegistered)) {
            if (-not $m) { continue }
            if ($methodCounts.Contains($m)) { $methodCounts[$m] = $methodCounts[$m] + 1 } else { $methodCounts[$m] = 1 }
        }
    }
    $defaultCounts = [ordered]@{}
    foreach ($r in $rows) {
        $d = if ($r.DefaultMfaMethod) { [string]$r.DefaultMfaMethod } else { "none" }
        if ($defaultCounts.Contains($d)) { $defaultCounts[$d] = $defaultCounts[$d] + 1 } else { $defaultCounts[$d] = 1 }
    }

    $result = [ordered]@{
        users_total                 = $rows.Count
        members_total               = $members.Count
        guests_total                = @($rows | Where-Object { $_.UserType -eq "guest" }).Count
        mfa_registered              = @($rows | Where-Object { $_.IsMfaRegistered }).Count
        mfa_capable                 = @($rows | Where-Object { $_.IsMfaCapable }).Count
        members_mfa_registered      = @($members | Where-Object { $_.IsMfaRegistered }).Count
        members_mfa_registered_pct  = if ($members.Count) { [math]::Round(100 * @($members | Where-Object { $_.IsMfaRegistered }).Count / $members.Count, 1) } else { $null }
        passwordless_capable        = @($rows | Where-Object { $_.IsPasswordlessCapable }).Count
        sspr_registered             = @($rows | Where-Object { $_.IsSsprRegistered }).Count
        sspr_capable                = @($rows | Where-Object { $_.IsSsprCapable }).Count
        system_preferred_enabled    = @($rows | Where-Object { $_.IsSystemPreferredAuthenticationMethodEnabled }).Count
        admins_total                = $admins.Count
        admins_mfa_registered       = @($admins | Where-Object { $_.IsMfaRegistered }).Count
        admins_without_mfa          = @($admins | Where-Object { -not $_.IsMfaRegistered }).Count
        methods_registered_counts   = $methodCounts
        default_mfa_method_counts   = $defaultCounts
    }
    if ($IncludeUsers) {
        $result.admins_without_mfa_list = @($admins | Where-Object { -not $_.IsMfaRegistered } | ForEach-Object { $_.UserPrincipalName })
        $result.users = @($rows | ForEach-Object {
            [ordered]@{
                user_principal_name   = $_.UserPrincipalName
                user_type             = $_.UserType
                is_admin              = [bool]$_.IsAdmin
                mfa_registered        = [bool]$_.IsMfaRegistered
                mfa_capable           = [bool]$_.IsMfaCapable
                passwordless_capable  = [bool]$_.IsPasswordlessCapable
                sspr_registered       = [bool]$_.IsSsprRegistered
                default_mfa_method    = [string]$_.DefaultMfaMethod
                methods_registered    = @($_.MethodsRegistered)
                last_updated_utc      = if ($_.LastUpdatedDateTime) { $_.LastUpdatedDateTime.ToUniversalTime().ToString("o") } else { $null }
            }
        })
    }
    $result
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.5.17", "ISO27001:A.8.5", "CIS8:6.3", "CIS8:6.5") `
    -Collector "m365/Get-MfaRegistrationEvidence.ps1" `
    -Data $data `
    -HostName ("entra-tenant:" + $ctx.TenantId) `
    -CollectedBy $ctx.Account

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Disconnect-MgGraph | Out-Null
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
