<#
.SYNOPSIS
    Collects Conditional Access policy evidence from a Microsoft Entra ID tenant through Microsoft Graph (read-only).
.DESCRIPTION
    Signs in interactively (no stored credentials), reads every Conditional Access policy and records its
    state, assignments (as counts and "All" flags, not object ids), conditions, grant and session controls,
    plus named locations. Derives the checks an auditor asks for: is MFA required for all users, for
    admin roles, is legacy authentication blocked, are risk-based policies present, how many policies
    are in report-only or disabled state.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Microsoft.Graph.Authentication and Microsoft.Graph.Identity.SignIns.
                  Delegated scope: Policy.Read.All (read-only). Global Reader or Security Reader is sufficient.
    Impact      : Read-only. Interactive sign-in.
    Controls    : ISO27001:A.5.15, ISO27001:A.8.3, ISO27001:A.8.5 | CIS8:6.3, CIS8:6.4, CIS8:6.5
    License     : MIT
.EXAMPLE
    .\Get-ConditionalAccessEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [string]$TenantId
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

foreach ($m in "Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns") {
    if (-not (Get-Module -ListAvailable -Name $m)) { throw "Module $m is not installed. Run: Install-Module $m -Scope CurrentUser" }
}
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Identity.SignIns

$connectParams = @{ Scopes = @("Policy.Read.All"); NoWelcome = $true }
if ($TenantId) { $connectParams.TenantId = $TenantId }
Connect-MgGraph @connectParams
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph." }

function ConvertTo-PolicyRecord {
    param($p)
    $u = $p.Conditions.Users
    $a = $p.Conditions.Applications
    $grant = $p.GrantControls
    $sess = $p.SessionControls
    [ordered]@{
        id                    = $p.Id
        display_name          = $p.DisplayName
        state                 = [string]$p.State
        created_utc           = if ($p.CreatedDateTime) { $p.CreatedDateTime.ToUniversalTime().ToString("o") } else { $null }
        modified_utc          = if ($p.ModifiedDateTime) { $p.ModifiedDateTime.ToUniversalTime().ToString("o") } else { $null }
        users = [ordered]@{
            include_all          = (@($u.IncludeUsers) -contains "All")
            include_users_count  = @($u.IncludeUsers | Where-Object { $_ -ne "All" -and $_ -ne "None" }).Count
            include_groups_count = @($u.IncludeGroups).Count
            include_roles_count  = @($u.IncludeRoles).Count
            include_guests       = [bool]($u.IncludeGuestsOrExternalUsers -and $u.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes)
            exclude_users_count  = @($u.ExcludeUsers).Count
            exclude_groups_count = @($u.ExcludeGroups).Count
            exclude_roles_count  = @($u.ExcludeRoles).Count
        }
        applications = [ordered]@{
            include_all          = (@($a.IncludeApplications) -contains "All")
            include_count        = @($a.IncludeApplications).Count
            exclude_count        = @($a.ExcludeApplications).Count
            user_actions         = @($a.IncludeUserActions)
        }
        client_app_types      = @($p.Conditions.ClientAppTypes | ForEach-Object { [string]$_ })
        platforms_included    = @($p.Conditions.Platforms.IncludePlatforms | ForEach-Object { [string]$_ })
        locations_included    = @($p.Conditions.Locations.IncludeLocations)
        locations_excluded    = @($p.Conditions.Locations.ExcludeLocations)
        sign_in_risk_levels   = @($p.Conditions.SignInRiskLevels | ForEach-Object { [string]$_ })
        user_risk_levels      = @($p.Conditions.UserRiskLevels | ForEach-Object { [string]$_ })
        device_filter         = if ($p.Conditions.Devices -and $p.Conditions.Devices.DeviceFilter) { [ordered]@{ mode = [string]$p.Conditions.Devices.DeviceFilter.Mode; rule = $p.Conditions.Devices.DeviceFilter.Rule } } else { $null }
        grant = [ordered]@{
            operator                 = if ($grant) { [string]$grant.Operator } else { $null }
            built_in_controls        = @($grant.BuiltInControls | ForEach-Object { [string]$_ })
            authentication_strength  = if ($grant -and $grant.AuthenticationStrength) { $grant.AuthenticationStrength.DisplayName } else { $null }
            terms_of_use_count       = @($grant.TermsOfUse).Count
        }
        session = [ordered]@{
            sign_in_frequency        = if ($sess -and $sess.SignInFrequency -and $sess.SignInFrequency.IsEnabled) { "$($sess.SignInFrequency.Value) $($sess.SignInFrequency.Type)" } else { $null }
            persistent_browser       = if ($sess -and $sess.PersistentBrowser -and $sess.PersistentBrowser.IsEnabled) { [string]$sess.PersistentBrowser.Mode } else { $null }
            app_enforced_restrictions = [bool]($sess -and $sess.ApplicationEnforcedRestrictions -and $sess.ApplicationEnforcedRestrictions.IsEnabled)
            cloud_app_security       = if ($sess -and $sess.CloudAppSecurity -and $sess.CloudAppSecurity.IsEnabled) { [string]$sess.CloudAppSecurity.CloudAppSecurityType } else { $null }
        }
    }
}

$data = [ordered]@{
    tenant_id   = $ctx.TenantId
    scopes_used = @($ctx.Scopes)
}

$data.policies = Invoke-EvidenceStep -Name "Conditional Access policies" -Step {
    @(Get-MgIdentityConditionalAccessPolicy -All | Sort-Object DisplayName | ForEach-Object { ConvertTo-PolicyRecord $_ })
}

$data.named_locations = Invoke-EvidenceStep -Name "Named locations" -Step {
    @(Get-MgIdentityConditionalAccessNamedLocation -All | ForEach-Object {
        $ap = $_.AdditionalProperties
        [ordered]@{
            display_name = $_.DisplayName
            type         = ([string]$ap["@odata.type"]) -replace "^#microsoft\.graph\.", ""
            is_trusted   = if ($ap.ContainsKey("isTrusted")) { [bool]$ap["isTrusted"] } else { $null }
            ip_ranges    = if ($ap.ContainsKey("ipRanges")) { @($ap["ipRanges"]).Count } else { $null }
            countries    = if ($ap.ContainsKey("countriesAndRegions")) { @($ap["countriesAndRegions"]).Count } else { $null }
        }
    })
}

$data.checks = Invoke-EvidenceStep -Name "Derived checks" -Step {
    $pol = @($data.policies | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains("state") })
    $enabled = @($pol | Where-Object { $_.state -eq "enabled" })
    $requiresMfa = { param($x) ($x.grant.built_in_controls -contains "mfa") -or $x.grant.authentication_strength }
    [ordered]@{
        policies_total                   = $pol.Count
        policies_enabled                 = $enabled.Count
        policies_report_only             = @($pol | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
        policies_disabled                = @($pol | Where-Object { $_.state -eq "disabled" }).Count
        mfa_for_all_users                = [bool]($enabled | Where-Object { $_.users.include_all -and $_.applications.include_all -and (& $requiresMfa $_) })
        mfa_for_admin_roles              = [bool]($enabled | Where-Object { $_.users.include_roles_count -gt 0 -and (& $requiresMfa $_) })
        legacy_auth_blocked              = [bool]($enabled | Where-Object { ($_.client_app_types -contains "exchangeActiveSync" -or $_.client_app_types -contains "other") -and $_.grant.built_in_controls -contains "block" })
        sign_in_risk_policy              = [bool]($enabled | Where-Object { $_.sign_in_risk_levels.Count -gt 0 })
        user_risk_policy                 = [bool]($enabled | Where-Object { $_.user_risk_levels.Count -gt 0 })
        device_compliance_required       = [bool]($enabled | Where-Object { $_.grant.built_in_controls -contains "compliantDevice" -or $_.grant.built_in_controls -contains "domainJoinedDevice" })
        guest_specific_policy            = [bool]($enabled | Where-Object { $_.users.include_guests })
        policies_with_exclusions         = @($enabled | Where-Object { $_.users.exclude_users_count -gt 0 -or $_.users.exclude_groups_count -gt 0 }).Count
        enabled_policy_names             = @($enabled | ForEach-Object { $_.display_name })
    }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.5.15", "ISO27001:A.8.3", "ISO27001:A.8.5", "CIS8:6.3", "CIS8:6.4", "CIS8:6.5") `
    -Collector "m365/Get-ConditionalAccessEvidence.ps1" `
    -Data $data `
    -HostName ("entra-tenant:" + $ctx.TenantId) `
    -CollectedBy $ctx.Account

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Disconnect-MgGraph | Out-Null
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
