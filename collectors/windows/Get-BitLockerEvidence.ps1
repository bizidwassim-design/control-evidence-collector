<#
.SYNOPSIS
    Collects disk-encryption evidence (BitLocker volumes, protectors, TPM state) from a Windows host.
.DESCRIPTION
    Read-only. Records every BitLocker volume with its protection status, encryption method and
    percentage, the TYPES of key protectors (never the recovery passwords or key material), the TPM
    state and the device-encryption policy, then writes a hashed JSON envelope.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+ with the BitLocker module; local administrator
                  for Get-BitLockerVolume and Get-Tpm. Falls back to "manage-bde -status" output.
    Impact      : Read-only. Recovery passwords are deliberately excluded from the output.
    Controls    : ISO27001:A.8.1, ISO27001:A.8.24 | CIS8:3.6, CIS8:3.11
    License     : MIT
.EXAMPLE
    .\Get-BitLockerEvidence.ps1 -OutputDirectory C:\Evidence\2026-Q4
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) "evidence")
)

$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\..\lib\Evidence.psm1") -Force

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

$data = [ordered]@{}

$data.volumes = Invoke-EvidenceStep -Name "BitLocker volumes" -Step {
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { throw "BitLocker module not available on this edition" }
    @(Get-BitLockerVolume | ForEach-Object {
        [ordered]@{
            mount_point            = $_.MountPoint
            volume_type            = [string]$_.VolumeType
            capacity_gb            = [math]::Round($_.CapacityGB, 1)
            protection_status      = [string]$_.ProtectionStatus
            volume_status          = [string]$_.VolumeStatus
            encryption_method      = [string]$_.EncryptionMethod
            encryption_percentage  = $_.EncryptionPercentage
            lock_status            = [string]$_.LockStatus
            auto_unlock_enabled    = [bool]$_.AutoUnlockEnabled
            key_protector_types    = @($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })   # types only, never the secrets
            recovery_protectors    = @($_.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq "RecoveryPassword" }).Count
        }
    })
}

$data.manage_bde_status = Invoke-EvidenceStep -Name "manage-bde -status" -Step {
    $raw = & manage-bde.exe -status 2>&1
    # keep only the status lines; recovery material is never printed by -status, but strip anything that looks like a key anyway
    @($raw | ForEach-Object { [string]$_ } | Where-Object { $_ -match "\S" -and $_ -notmatch "\b\d{6}-\d{6}-\d{6}" })
}

$data.tpm = Invoke-EvidenceStep -Name "TPM" -Step {
    if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) { throw "Get-Tpm not available" }
    $tpm = Get-Tpm
    [ordered]@{
        present   = [bool]$tpm.TpmPresent
        ready     = [bool]$tpm.TpmReady
        enabled   = [bool]$tpm.TpmEnabled
        activated = [bool]$tpm.TpmActivated
        owned     = [bool]$tpm.TpmOwned
    }
}

$data.policy = Invoke-EvidenceStep -Name "BitLocker policy" -Step {
    $fve = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    [ordered]@{
        policy_present                 = Test-Path $fve
        os_drive_encryption_method     = Get-RegistryValueSafe -Path $fve -Name "EncryptionMethodWithXtsOs"
        fixed_drive_encryption_method  = Get-RegistryValueSafe -Path $fve -Name "EncryptionMethodWithXtsFdv"
        os_require_tpm                 = Get-RegistryValueSafe -Path $fve -Name "UseTPM"
        os_recovery_backup_to_ad       = Get-RegistryValueSafe -Path $fve -Name "OSActiveDirectoryBackup"
        os_recovery_required_before_enc = Get-RegistryValueSafe -Path $fve -Name "OSRequireActiveDirectoryBackup"
        deny_write_unprotected_removable = Get-RegistryValueSafe -Path $fve -Name "RDVDenyWriteAccess"
    }
}

$data.summary = Invoke-EvidenceStep -Name "Summary" -Step {
    $vols = @($data.volumes | Where-Object { $_ -is [System.Collections.IDictionary] -and $_.Contains("mount_point") })
    $os = $vols | Where-Object { $_.volume_type -eq "OperatingSystem" } | Select-Object -First 1
    [ordered]@{
        volumes_total             = $vols.Count
        volumes_protected         = @($vols | Where-Object { $_.protection_status -eq "On" }).Count
        volumes_unprotected       = @($vols | Where-Object { $_.protection_status -ne "On" } | ForEach-Object { $_.mount_point })
        os_drive_protected        = if ($os) { $os.protection_status -eq "On" } else { $null }
        os_drive_method           = if ($os) { $os.encryption_method } else { $null }
        os_drive_has_recovery_key = if ($os) { $os.recovery_protectors -gt 0 } else { $null }
    }
}

$envelope = New-EvidenceEnvelope `
    -ControlIds @("ISO27001:A.8.1", "ISO27001:A.8.24", "CIS8:3.6", "CIS8:3.11") `
    -Collector "windows/Get-BitLockerEvidence.ps1" `
    -Data $data

$path = Write-Evidence -Envelope $envelope -OutputDirectory $OutputDirectory
Write-Host "Evidence written: $path"
Write-Host "SHA-256        : $($envelope.sha256)"
