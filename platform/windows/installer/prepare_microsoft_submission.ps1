param(
    [ValidateSet("Release")]
    [string]$Configuration = "Release",
    [string]$OutputDirectory = "",
    [string]$PackageDirectory = "",
    [string]$Inf2CatOs = "10_X64,Server10_X64",
    [string]$EvCertificateThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$package = if ([string]::IsNullOrWhiteSpace($PackageDirectory)) {
    Join-Path $repo "driver_package\$Configuration"
} else {
    if ([IO.Path]::IsPathRooted($PackageDirectory)) { [IO.Path]::GetFullPath($PackageDirectory) }
    else { [IO.Path]::GetFullPath((Join-Path $repo $PackageDirectory)) }
}
if (-not (Test-Path -LiteralPath $package -PathType Container)) {
    throw "Driver package directory is missing: $package"
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo "submission\microsoft" }
$staging = Join-Path $OutputDirectory "packages"
$manifestFile = Join-Path $OutputDirectory "SHA256SUMS.json"
$abiValidator = Join-Path $repo "platform\windows\verification\validate_abi_freeze.ps1"
$kitsBin = "C:\Program Files (x86)\Windows Kits\10\bin"
$inf2cat = Get-ChildItem $kitsBin -Recurse -Filter Inf2Cat.exe -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
$signtool = Get-ChildItem $kitsBin -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -match "\\x64\\" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $inf2cat -or -not $signtool) { throw "Inf2Cat and x64 SignTool from the Windows Driver Kit are required." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $abiValidator
if($LASTEXITCODE -ne 0){throw "Frozen ABI validation failed."}

$drivers = @(
    [ordered]@{name="wfp";sys="AIShieldWfp.sys";inf="ai_shield_wfp.inf";pdb="platform\windows\wfp\driver\x64\Release\AIShieldWfp.pdb"},
    [ordered]@{name="minifilter";sys="AIShieldMiniFilter.sys";inf="ai_shield_minifilter.inf";pdb="platform\windows\minifilter\driver\x64\Release\AIShieldMiniFilter.pdb"},
    [ordered]@{name="process_guard";sys="AIShieldProcessGuard.sys";inf="ai_shield_process_guard.inf";pdb="platform\windows\process_guard\driver\x64\Release\AIShieldProcessGuard.pdb"}
)

if (Test-Path $OutputDirectory) { Remove-Item $OutputDirectory -Recurse -Force }
New-Item -ItemType Directory -Force -Path $staging | Out-Null

foreach ($driver in $drivers) {
    $directory=Join-Path $staging $driver.name
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    foreach ($file in @($driver.sys,$driver.inf)) {
        $source=Join-Path $package $file
        if (-not (Test-Path $source)) { throw "Submission input is missing: $source" }
        Copy-Item $source $directory
    }
    $pdbSource=Join-Path $repo $driver.pdb
    if (-not (Test-Path $pdbSource)) { throw "Submission symbols are missing: $pdbSource" }
    Copy-Item $pdbSource $directory
    & $inf2cat.FullName "/driver:$directory" "/os:$Inf2CatOs" /verbose
    if ($LASTEXITCODE -ne 0) { throw "Inf2Cat validation failed for $($driver.name)." }
}

$files=Get-ChildItem $staging -Recurse -File | Sort-Object FullName
$hashes=@($files|ForEach-Object{[ordered]@{path=$_.FullName.Substring($staging.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash;size=$_.Length}})
$manifest=[ordered]@{schema=1;created_utc=[DateTime]::UtcNow.ToString("o");configuration=$Configuration;
    inf2cat_os=$Inf2CatOs;files=$hashes}
[IO.File]::WriteAllText($manifestFile,($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $repo "runtime\verification\ABI_MANIFEST.json") (Join-Path $OutputDirectory "ABI_MANIFEST.json") -Force

$cabFile=Join-Path $OutputDirectory "AIShieldDrivers-x64.cab"
$ddfFile=Join-Path $OutputDirectory "AIShieldDrivers.ddf"
$ddf=@(
    ".OPTION EXPLICIT",
    ".Set CabinetNameTemplate=AIShieldDrivers-x64.cab",
    ".Set DiskDirectoryTemplate=$OutputDirectory",
    ".Set CompressionType=MSZIP",
    ".Set Cabinet=on",
    ".Set Compress=on"
)
foreach($driver in $drivers){
    $ddf += ".Set DestinationDir=$($driver.name)"
    Get-ChildItem (Join-Path $staging $driver.name) -File | Sort-Object Name | ForEach-Object { $ddf += ('"' + $_.FullName + '"') }
}
[IO.File]::WriteAllLines($ddfFile,$ddf,[Text.UTF8Encoding]::new($false))
& makecab.exe /F $ddfFile | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cabFile)) { throw "CAB creation failed." }
if ($EvCertificateThumbprint) {
    if ($EvCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw "EV certificate thumbprint is malformed." }
    & $signtool.FullName sign /sha1 $EvCertificateThumbprint /fd sha256 /tr $TimestampUrl /td sha256 /v $cabFile
    if ($LASTEXITCODE -ne 0) { throw "EV signing of the submission CAB failed." }
    & $signtool.FullName verify /pa /all /v $cabFile
    if ($LASTEXITCODE -ne 0) { throw "EV signature verification of the submission CAB failed." }
}

$readme=@"
# AI Shield Microsoft driver submission staging

This directory is generated input for Microsoft signing qualification. It is not a Microsoft-signed release.

Required external gates:

1. Register the organization in the Windows Hardware Developer Program.
2. Use the current Partner Center certificate and identity requirements.
3. Run the applicable Windows HLK playlists on every declared Windows target.
4. Create and sign the HLK submission package required by Partner Center.
5. Upload through the Hardware Dashboard and download the Microsoft-signed return package.
6. Verify every returned catalog with SignTool and repeat install, reboot, HVCI and Driver Verifier qualification.

Generated locally:

- isolated INF/SYS/CAT folders for all three drivers
- matching PDB symbols and AIShieldDrivers-x64.cab
- Inf2Cat validation for: $Inf2CatOs
- SHA-256 manifest: SHA256SUMS.json
- frozen ABI manifest: ABI_MANIFEST.json
- EV signed CAB: $(if ($EvCertificateThumbprint) { "yes" } else { "no; signing remains an external release gate" })

Do not enable Secure Boot for this local test-signed build. Only the returned Microsoft-trusted package may pass the production signing gate.
"@
[IO.File]::WriteAllText((Join-Path $OutputDirectory "SUBMISSION_README.md"),$readme,[Text.UTF8Encoding]::new($false))
Write-Output "submission staging: $OutputDirectory"
Write-Output "inf2cat: $($inf2cat.FullName)"
Write-Output "signtool: $($signtool.FullName)"
Write-Output "submission cab: $cabFile"
Write-Output "ev_signed: $([bool]$EvCertificateThumbprint)"
