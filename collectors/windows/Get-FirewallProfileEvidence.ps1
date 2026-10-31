<#
.SYNOPSIS
    Collects host-firewall evidence from a Windows host: profile state, default actions, logging, rule counts.
.DESCRIPTION
    Read-only. Records the three Windows Defender Firewall profiles (Domain, Private, Public) with their
    enabled state, default inbound/outbound actions and logging settings, a count of rules by direction,
    action and state, the enabled inbound allow rules and the firewall service state, then writes a
    hashed JSON envelope.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+ with the NetSecurity module. Standard user is enough.
    Impact      : Read-only
    Controls    : ISO27001:A.8.20, ISO27001:A.8.22 | CIS8:4.4, CIS8:4.5
    License     : MIT
.EXAMPLE
    .\Get-FirewallProfileEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4 -RuleLimit 300
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [int]$RuleLimit = 200
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

$data = [ordered]@{}

$data.profiles = Invoke-EvidenceStep -Name "Firewall profiles" -Step {
    @(Get-NetFirewallProfile | ForEach-Object {
        [ordered]@{
            name                     = $_.Name
            enabled                  = [string]$_.Enabled
            default_inbound_action   = [string]$_.DefaultInboundAction
            default_outbound_action  = [string]$_.DefaultOutboundAction
            allow_inbound_rules      = [string]$_.AllowInboundRules
            allow_local_firewall_rules = [string]$_.AllowLocalFirewallRules
            notify_on_listen         = [string]$_.NotifyOnListen
            log_allowed              = [string]$_.LogAllowed
            log_blocked              = [string]$_.LogBlocked
            log_file_name            = $_.LogFileName
            log_max_size_kb          = $_.LogMaxSizeKilobytes
        }
    })
}

$data.rule_summary = Invoke-EvidenceStep -Name "Rule summary" -Step {
    $rules = @(Get-NetFirewallRule)
    $groups = $rules | Group-Object -Property { "{0}|{1}|{2}" -f $_.Direction, $_.Action, $_.Enabled }
    [ordered]@{
        total_rules = $rules.Count
        by_direction_action_enabled = @($groups | Sort-Object Name | ForEach-Object {
            $parts = $_.Name -split "\|"
            [ordered]@{ direction = $parts[0]; action = $parts[1]; enabled = $parts[2]; count = $_.Count }
        })
    }
}

$data.enabled_inbound_allow_rules = Invoke-EvidenceStep -Name "Enabled inbound allow rules" -Step {
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Sort-Object DisplayName)
    [ordered]@{
        count     = $rules.Count
        truncated = $rules.Count -gt $RuleLimit
        rules     = @($rules | Select-Object -First $RuleLimit | ForEach-Object {
            $port = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $addr = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            [ordered]@{
                display_name   = $_.DisplayName
                profile        = [string]$_.Profile
                protocol       = if ($port) { [string]$port.Protocol } else { $null }
                local_port     = if ($port) { [string]$port.LocalPort } else { $null }
                remote_address = if ($addr) { [string]$addr.RemoteAddress } else { $null }
                policy_store   = $_.PolicyStoreSourceType.ToString()
            }
        })
    }
}

$data.service = Invoke-EvidenceStep -Name "mpssvc" -Step {
    $svc = Get-Service -Name mpssvc
    [ordered]@{ status = [string]$svc.Status; start_type = [string]$svc.StartType }
}

$data.summary = Invoke-EvidenceStep -Name "Summary" -Step {
    $profiles = @($data.profiles | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains("name") })
    [ordered]@{
        all_profiles_enabled          = ($profiles.Count -eq 3) -and -not ($profiles | Where-Object { $_.enabled -ne "True" })
        profiles_disabled             = @($profiles | Where-Object { $_.enabled -ne "True" } | ForEach-Object { $_.name })
        profiles_inbound_not_blocked  = @($profiles | Where-Object { $_.default_inbound_action -eq "Allow" } | ForEach-Object { $_.name })
        profiles_without_block_logging = @($profiles | Where-Object { $_.log_blocked -ne "True" } | ForEach-Object { $_.name })
    }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.8.20", "ISO27001:A.8.22", "CIS8:4.4", "CIS8:4.5") `
    -Collector "windows/Get-FirewallProfileEvidence.ps1" `
    -Data $data

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
