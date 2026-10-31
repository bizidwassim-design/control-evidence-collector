<#
.SYNOPSIS
    Shared helper for the evidence collectors: builds the common JSON envelope, hashes it and writes it.
.DESCRIPTION
    Every collector in this repository produces the same envelope:

        { control_ids, collector, host, collected_at_utc, collected_by, data, sha256 }

    Hash scheme (identical in lib/evidence.sh and lib/evidence.py):
      1. Serialise the envelope with "sha256" set to a placeholder of 64 zeros.
      2. SHA-256 the exact UTF-8 bytes (LF line endings, no BOM, trailing newline).
      3. Write the same bytes with the placeholder replaced by the hex digest.
    A verifier reads the file, replaces the digest with the placeholder and recomputes the hash, so
    verification works on raw bytes and does not depend on any JSON canonicalisation.
.NOTES
    Author      : Wassim Bizid
    Repository  : https://github.com/bizidwassim-design/control-evidence-collector
    Requires    : Windows PowerShell 5.1 or PowerShell 7+
    Impact      : Read-only (writes only the evidence file)
    License     : MIT
#>

Set-StrictMode -Version 2.0

$script:Placeholder = "0" * 64
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-EvidenceSha256 {
    <#
    .SYNOPSIS
        Returns the lowercase hex SHA-256 of a byte array.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $sha.Dispose()
    }
}

function New-EvidenceEnvelope {
    <#
    .SYNOPSIS
        Builds the standard envelope around collected data.
    .PARAMETER ControlIds
        Control identifiers in the form "ISO27001:A.8.8" or "CIS8:7.3".
    .PARAMETER Collector
        Collector name, e.g. "windows/Get-PatchStatusEvidence.ps1".
    .PARAMETER Data
        The collected evidence (ordered hashtable, PSCustomObject, array...).
    .PARAMETER HostName
        Overrides the host name (default: the local computer name). Cloud and tenant collectors pass
        "entra-tenant:<id>" or similar.
    .PARAMETER CollectedBy
        Overrides the identity (default: DOMAIN\user of the running session).
    .PARAMETER CollectedAtUtc
        Overrides the timestamp (used to produce reproducible examples).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ControlIds,
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][AllowNull()]$Data,
        [string]$HostName = $env:COMPUTERNAME,
        [string]$CollectedBy,
        [datetime]$CollectedAtUtc = [datetime]::UtcNow
    )
    if (-not $CollectedBy) {
        $CollectedBy = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { "$env:USERNAME" }
    }
    if (-not $HostName) { $HostName = [System.Net.Dns]::GetHostName() }
    return [ordered]@{
        control_ids      = @($ControlIds)
        collector        = $Collector
        host             = $HostName
        collected_at_utc = $CollectedAtUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        collected_by     = $CollectedBy
        data             = $Data
        sha256           = $script:Placeholder
    }
}

function Write-Evidence {
    <#
    .SYNOPSIS
        Serialises, hashes and writes an envelope. Returns the full path of the file written.
    .PARAMETER Envelope
        The ordered hashtable returned by New-EvidenceEnvelope.
    .PARAMETER OutputDirectory
        Created if missing. Default: .\evidence
    .PARAMETER FileName
        Default: <collector-basename>_<host>_<timestamp>.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Envelope,
        [string]$OutputDirectory = (Join-Path (Get-Location) "evidence"),
        [string]$FileName
    )
    foreach ($key in "control_ids", "collector", "host", "collected_at_utc", "collected_by", "data") {
        if (-not $Envelope.Contains($key)) { throw "Envelope is missing the '$key' field." }
    }
    $Envelope["sha256"] = $script:Placeholder

    $json = ($Envelope | ConvertTo-Json -Depth 32) -replace "`r`n", "`n"
    if (-not $json.EndsWith("`n")) { $json += "`n" }

    $bytes = $script:Utf8NoBom.GetBytes($json)
    $hash = Get-EvidenceSha256 -Bytes $bytes
    $final = $json.Replace($script:Placeholder, $hash)
    $Envelope["sha256"] = $hash

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    if (-not $FileName) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension(($Envelope["collector"] -split "[\\/]")[-1])
        $safeHost = ($Envelope["host"] -replace "[^A-Za-z0-9._-]", "-")
        $stamp = $Envelope["collected_at_utc"] -replace "[-:]", ""
        $FileName = "{0}_{1}_{2}.json" -f $base, $safeHost, $stamp
    }
    $path = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path $FileName
    [System.IO.File]::WriteAllBytes($path, $script:Utf8NoBom.GetBytes($final))
    return $path
}

function Test-Evidence {
    <#
    .SYNOPSIS
        Verifies the SHA-256 of one evidence file. Returns an object with Path, Valid, Expected, Actual.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Path)
    process {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = $script:Utf8NoBom.GetString($bytes)
        $doc = $text | ConvertFrom-Json
        $expected = [string]$doc.sha256
        if ($expected -notmatch '^[0-9a-f]{64}$') {
            return [pscustomobject]@{ Path = $Path; Valid = $false; Expected = $expected; Actual = $null; Collector = $doc.collector }
        }
        $actual = Get-EvidenceSha256 -Bytes ($script:Utf8NoBom.GetBytes($text.Replace($expected, $script:Placeholder)))
        return [pscustomobject]@{
            Path      = $Path
            Valid     = ($actual -eq $expected)
            Expected  = $expected
            Actual    = $actual
            Collector = $doc.collector
        }
    }
}

function Invoke-EvidenceStep {
    <#
    .SYNOPSIS
        Runs a script block and returns its result, or an error record ({ error = "..." }) instead of
        aborting the whole collection. Collectors use it so that one missing privilege does not lose
        the rest of the evidence.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Step, [string]$Name = "step")
    try {
        return (& $Step)
    } catch {
        Write-Warning ("{0}: {1}" -f $Name, $_.Exception.Message)
        return [ordered]@{ error = $_.Exception.Message }
    }
}

Export-ModuleMember -Function New-EvidenceEnvelope, Write-Evidence, Test-Evidence, Get-EvidenceSha256, Invoke-EvidenceStep
