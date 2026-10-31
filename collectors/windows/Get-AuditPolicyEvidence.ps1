<#
.SYNOPSIS
    Collects audit-policy and event-log configuration evidence from a Windows host.
.DESCRIPTION
    Read-only. Records the effective advanced audit policy (auditpol, every subcategory), the size,
    retention mode and record count of the key event logs, PowerShell logging policies and the
    Sysmon service state, then writes a hashed JSON envelope.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+. auditpol needs a local administrator;
                  without it the audit_policy section records the error and the rest is still collected.
    Impact      : Read-only
    Controls    : ISO27001:A.8.15 | CIS8:8.2, CIS8:8.3, CIS8:8.5
    License     : MIT
.EXAMPLE
    .\Get-AuditPolicyEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [string[]]$LogNames = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational",
                            "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-TaskScheduler/Operational",
                            "Microsoft-Windows-Windows Defender/Operational")
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

$data = [ordered]@{}

$data.audit_policy = Invoke-EvidenceStep -Name "auditpol" -Step {
    $raw = & auditpol.exe /get /category:* /r 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE (run as administrator): $($raw -join ' ')" }
    $rows = @($raw | Where-Object { $_ -and $_ -notmatch "^\s*$" } | ConvertFrom-Csv)
    $settings = @($rows | ForEach-Object {
        [ordered]@{
            subcategory = $_.Subcategory
            guid        = $_."Subcategory GUID"
            setting     = $_."Inclusion Setting"
        }
    })
    [ordered]@{
        subcategory_count = $settings.Count
        no_auditing_count = @($settings | Where-Object { $_.setting -eq "No Auditing" }).Count
        settings          = $settings
    }
}

$data.event_logs = Invoke-EvidenceStep -Name "Event logs" -Step {
    @($LogNames | ForEach-Object {
        $name = $_
        try {
            $log = Get-WinEvent -ListLog $name -ErrorAction Stop
            [ordered]@{
                log_name          = $name
                enabled           = [bool]$log.IsEnabled
                max_size_mb       = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
                log_mode          = [string]$log.LogMode
                record_count      = $log.RecordCount
                oldest_record_utc = $null
                file_size_mb      = [math]::Round($log.FileSize / 1MB, 1)
            }
        } catch {
            [ordered]@{ log_name = $name; error = $_.Exception.Message }
        }
    })
}

# Age of the oldest Security event tells an auditor how far back the local log reaches
$data.security_log_span = Invoke-EvidenceStep -Name "Security log span" -Step {
    $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
    [ordered]@{
        oldest_event_utc = $oldest.TimeCreated.ToUniversalTime().ToString("o")
        days_covered     = [math]::Round(((Get-Date) - $oldest.TimeCreated).TotalDays, 1)
    }
}

$data.powershell_logging = Invoke-EvidenceStep -Name "PowerShell logging policy" -Step {
    $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    [ordered]@{
        script_block_logging   = Get-RegistryValueSafe -Path "$base\ScriptBlockLogging" -Name "EnableScriptBlockLogging"
        module_logging         = Get-RegistryValueSafe -Path "$base\ModuleLogging" -Name "EnableModuleLogging"
        transcription          = Get-RegistryValueSafe -Path "$base\Transcription" -Name "EnableTranscripting"
        transcription_dir_set  = $null -ne (Get-RegistryValueSafe -Path "$base\Transcription" -Name "OutputDirectory")
    }
}

$data.command_line_auditing = Invoke-EvidenceStep -Name "Process command line auditing" -Step {
    [ordered]@{
        include_command_line_in_4688 = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"
    }
}

$data.sysmon = Invoke-EvidenceStep -Name "Sysmon" -Step {
    $svc = Get-Service | Where-Object { $_.Name -match "^Sysmon(64)?$" } | Select-Object -First 1
    if ($svc) { [ordered]@{ installed = $true; name = $svc.Name; status = [string]$svc.Status } }
    else      { [ordered]@{ installed = $false } }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.8.15", "CIS8:8.2", "CIS8:8.3", "CIS8:8.5") `
    -Collector "windows/Get-AuditPolicyEvidence.ps1" `
    -Data $data

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
