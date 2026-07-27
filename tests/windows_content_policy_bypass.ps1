param([int]$TimeoutSeconds = 45)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this regression test from an elevated PowerShell."
}

$service = Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
if ($null -eq $service -or $service.State -ne "Running") { throw "AIShieldBroker is not running." }
$broker = ([regex]::Match($service.PathName, '^"?([^\"]+?\.exe)"?(?:\s|$)')).Groups[1].Value
if (-not (Test-Path -LiteralPath $broker -PathType Leaf)) { throw "AIShieldBroker executable is missing." }

$original = (& $broker content-policy-status | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw "Could not read the content policy." }
$archiveBit = 2
$withoutArchives = [int]$original.enabled_categories -band (-bnot $archiveBit)
$withArchives = [int]$original.enabled_categories -bor $archiveBit
$downloads = Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads"
$run = [Guid]::NewGuid().ToString("N")
$disabledPartial = Join-Path $downloads "ai-shield-disabled-$run.crdownload"
$disabledFinal = Join-Path $downloads "ai-shield-disabled-$run.zip"
$enabledPartial = Join-Path $downloads "ai-shield-enabled-$run.crdownload"
$enabledFinal = Join-Path $downloads "ai-shield-enabled-$run.zip"
$journal = Join-Path $env:ProgramData "AIShield\quarantine\journal.jsonl"
$cleanupDestination = Join-Path $env:TEMP "ai-shield-enabled-$run.zip"
$quarantineId = $null

function Set-TestPolicy([int]$Mask) {
    & $broker content-policy-set $Mask 1 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not update the content policy." }
}

function New-MinimalZipBytes {
    $memory = [IO.MemoryStream]::new()
    $archive = [IO.Compression.ZipArchive]::new($memory, [IO.Compression.ZipArchiveMode]::Create, $true)
    $entry = $archive.CreateEntry("readme.txt")
    $writer = [IO.StreamWriter]::new($entry.Open(), [Text.UTF8Encoding]::new($false))
    $writer.Write("AI Shield content-policy bypass regression")
    $writer.Dispose()
    $archive.Dispose()
    $bytes = $memory.ToArray()
    $memory.Dispose()
    return $bytes
}

function Wait-PathState([string]$Path, [bool]$Expected) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        if ((Test-Path -LiteralPath $Path) -eq $Expected) { return }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for path state expected=$Expected path=$Path"
}

try {
    Add-Type -AssemblyName System.IO.Compression
    $zipBytes = New-MinimalZipBytes

    Set-TestPolicy $withoutArchives
    [IO.File]::WriteAllBytes($disabledPartial, $zipBytes)
    Start-Sleep -Seconds 2
    if (-not (Test-Path -LiteralPath $disabledPartial)) { throw "Transient Chromium download was quarantined." }
    Move-Item -LiteralPath $disabledPartial -Destination $disabledFinal
    Start-Sleep -Seconds 4
    if (-not (Test-Path -LiteralPath $disabledFinal)) { throw "Disabled archive category was still inspected or quarantined." }

    Set-TestPolicy $withArchives
    [IO.File]::WriteAllBytes($enabledPartial, $zipBytes)
    Start-Sleep -Seconds 2
    if (-not (Test-Path -LiteralPath $enabledPartial)) { throw "Transient download was quarantined before final rename." }
    Move-Item -LiteralPath $enabledPartial -Destination $enabledFinal
    Wait-PathState -Path $enabledFinal -Expected $false
    $record = Get-Content -LiteralPath $journal -ErrorAction SilentlyContinue |
        Where-Object { $_ -like "*ai-shield-enabled-$run.zip*committed*" } |
        Select-Object -Last 1
    if (-not $record) { throw "Final archive rename did not receive a fresh enforced verdict." }
    $quarantineId = ($record | ConvertFrom-Json).id

    Write-Output "transient_browser_download_allowed=true"
    Write-Output "disabled_archive_category_bypassed=true"
    Write-Output "final_rename_reclassified=true"
} finally {
    & $broker content-policy-set ([int]$original.enabled_categories) `
        ([int][bool]$original.fail_closed) ([int][bool]$original.release_required) | Out-Null
    Remove-Item -LiteralPath $disabledPartial,$disabledFinal,$enabledPartial,$enabledFinal -Force -ErrorAction SilentlyContinue
    if (-not $quarantineId -and (Test-Path -LiteralPath $journal)) {
        $cleanupRecord = Get-Content -LiteralPath $journal -ErrorAction SilentlyContinue |
            Where-Object { $_ -like "*ai-shield-enabled-$run.zip*committed*" } | Select-Object -Last 1
        if ($cleanupRecord) { $quarantineId = ($cleanupRecord | ConvertFrom-Json).id }
    }
    if ($quarantineId) {
        & $broker quarantine-restore $quarantineId $cleanupDestination `
            "Automated content-policy bypass regression cleanup" | Out-Null
        Remove-Item -LiteralPath $cleanupDestination -Force -ErrorAction SilentlyContinue
    }
}
