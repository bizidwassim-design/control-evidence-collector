<#
.SYNOPSIS
    Collects patch-status evidence for a Windows host: OS build, installed updates, pending reboot, update policy.
.DESCRIPTION
    Read-only. Records the operating system version and build, last boot time, the installed hotfixes
    (newest first, with the age of the newest one), pending-reboot indicators from the registry and the
    effective Windows Update policy settings, then writes a hashed JSON envelope.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+. Standard user is enough.
    Impact      : Read-only
    Controls    : ISO27001:A.8.8 | CIS8:7.3, CIS8:7.4
    License     : MIT
.EXAMPLE
    .\Get-PatchStatusEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
    [int]$HotfixLimit = 100
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

$data = [ordered]@{}

$data.operating_system = Invoke-EvidenceStep -Name "Operating system" -Step {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    [ordered]@{
        caption          = $os.Caption
        version          = $os.Version
        build_number     = $os.BuildNumber
        ubr              = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "UBR"
        display_version  = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DisplayVersion"
        architecture     = $os.OSArchitecture
        install_date     = if ($os.InstallDate) { $os.InstallDate.ToUniversalTime().ToString("o") } else { $null }
        last_boot_utc    = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString("o") } else { $null }
        uptime_days      = if ($os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1) } else { $null }
    }
}

$data.hotfixes = Invoke-EvidenceStep -Name "Hotfixes" -Step {
    $all = @(Get-HotFix | Sort-Object -Property InstalledOn -Descending)
    $newest = $all | Where-Object { $_.InstalledOn } | Select-Object -First 1
    [ordered]@{
        total_installed       = $all.Count
        newest_installed_on   = if ($newest) { $newest.InstalledOn.ToUniversalTime().ToString("yyyy-MM-dd") } else { $null }
        days_since_newest     = if ($newest) { [int]((Get-Date) - $newest.InstalledOn).TotalDays } else { $null }
        items                 = @($all | Select-Object -First $HotfixLimit | ForEach-Object {
            [ordered]@{
                hotfix_id    = $_.HotFixID
                description  = $_.Description
                installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToUniversalTime().ToString("yyyy-MM-dd") } else { $null }
            }
        })
    }
}

$data.pending_reboot = Invoke-EvidenceStep -Name "Pending reboot" -Step {
    $cbs = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $wu  = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $pfr = $null -ne (Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations")
    [ordered]@{
        component_based_servicing = $cbs
        windows_update            = $wu
        pending_file_rename       = $pfr
        any                       = ($cbs -or $wu -or $pfr)
    }
}

$data.update_policy = Invoke-EvidenceStep -Name "Windows Update policy" -Step {
    $au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $wu = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    [ordered]@{
        policy_present             = (Test-Path $au) -or (Test-Path $wu)
        no_auto_update             = Get-RegistryValueSafe -Path $au -Name "NoAutoUpdate"
        au_options                 = Get-RegistryValueSafe -Path $au -Name "AUOptions"
        scheduled_install_day      = Get-RegistryValueSafe -Path $au -Name "ScheduledInstallDay"
        use_wsus_server            = Get-RegistryValueSafe -Path $au -Name "UseWUServer"
        wsus_server                = Get-RegistryValueSafe -Path $wu -Name "WUServer"
        deferral_quality_days      = Get-RegistryValueSafe -Path $wu -Name "DeferQualityUpdatesPeriodInDays"
        deferral_feature_days      = Get-RegistryValueSafe -Path $wu -Name "DeferFeatureUpdatesPeriodInDays"
        last_install_success_utc   = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -Name "LastSuccessTime"
        last_detect_success_utc    = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -Name "LastSuccessTime"
    }
}

$data.windows_update_service = Invoke-EvidenceStep -Name "wuauserv" -Step {
    $svc = Get-Service -Name wuauserv
    [ordered]@{ status = [string]$svc.Status; start_type = [string]$svc.StartType }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.8.8", "CIS8:7.3", "CIS8:7.4") `
    -Collector "windows/Get-PatchStatusEvidence.ps1" `
    -Data $data

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
