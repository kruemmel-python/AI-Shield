param([Parameter(Mandatory=$true)][string]$PackageDirectory)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Binary update requires an elevated PowerShell."
}
$package = Resolve-Path $PackageDirectory
$manifestPath = Join-Path $package "manifest.json"
$signaturePath = Join-Path $package "manifest.p7s"
if (-not (Test-Path $manifestPath) -or -not (Test-Path $signaturePath)) {
    throw "The package requires manifest.json and detached manifest.p7s."
}
$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
$content = [Security.Cryptography.Pkcs.ContentInfo]::new($manifestBytes)
$cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
$cms.Decode($signatureBytes)
$cms.CheckSignature($true)
if ($cms.SignerInfos.Count -ne 1) { throw "Exactly one update signer is required." }
$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
if ($manifest.format -ne "AIShieldUpdate/2" -or [uint64]$manifest.security_version -eq 0 -or
    [string]::IsNullOrWhiteSpace($manifest.publisher_thumbprint)) { throw "Update manifest is invalid." }
$signer = $cms.SignerInfos[0].Certificate.Thumbprint
if ($signer -ne $manifest.publisher_thumbprint) { throw "Manifest signer does not match publisher pin." }

$root = Join-Path $env:ProgramFiles "AIShield"
$statePath = Join-Path $env:ProgramData "AIShield\update-state.json"
$transactionPath = Join-Path $env:ProgramData "AIShield\update-transaction.json"
$state = if (Test-Path $statePath) { Get-Content $statePath -Raw | ConvertFrom-Json } else {
    [pscustomobject]@{ security_version = [uint64]0; active_slot = "base" }
}
if ([uint64]$manifest.security_version -le [uint64]$state.security_version) {
    throw "Update downgrade or replay rejected."
}
$inactive = if ($state.active_slot -eq "a") { "b" } else { "a" }
$stage = Join-Path $root ("slots\" + $inactive)
if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
foreach ($file in $manifest.files) {
    $relative = [string]$file.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "Manifest path escapes package: $relative"
    }
    $source = [IO.Path]::GetFullPath((Join-Path $package $relative))
    $packagePrefix = [IO.Path]::GetFullPath($package).TrimEnd('\') + '\'
    if (-not $source.StartsWith($packagePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest path escapes package: $relative"
    }
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($hash -ne [string]$file.sha256) { throw "Hash mismatch: $relative" }
    if ([IO.Path]::GetExtension($source) -in @(".exe", ".dll", ".sys", ".ps1")) {
        $authenticode = Get-AuthenticodeSignature -LiteralPath $source
        if ($authenticode.Status -ne "Valid" -or $authenticode.SignerCertificate.Thumbprint -ne $manifest.publisher_thumbprint) {
            throw "Publisher verification failed: $relative"
        }
    }
    $destination = Join-Path $stage $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination
}
$brokerService = Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'" -ErrorAction Stop
$coreService = Get-CimInstance Win32_Service -Filter "Name='AIShieldCore'" -ErrorAction Stop
$previousBrokerPath = ([string]$brokerService.PathName).Trim('"')
$previousCorePath = ([string]$coreService.PathName).Trim('"')
$rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
foreach ($activePath in @($previousBrokerPath,$previousCorePath)) {
    $resolvedActivePath = [IO.Path]::GetFullPath($activePath)
    if (-not $resolvedActivePath.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $resolvedActivePath)) {
        throw "Active service binary is outside the protected installation root: $activePath"
    }
}
$transaction = [ordered]@{ format = "AIShieldUpdateTransaction/2"; state = "activating";
    previous_slot = $state.active_slot; staged_slot = $inactive; security_version = [uint64]$manifest.security_version;
    previous_broker_path = $previousBrokerPath; previous_core_path = $previousCorePath }
$transaction | ConvertTo-Json -Compress | Set-Content -LiteralPath $transactionPath -Encoding UTF8
$activated = $false
try {
    Stop-Service AIShieldCore, AIShieldBroker -Force -ErrorAction SilentlyContinue
    $broker = Join-Path $stage "bin\ai_shield_broker.exe"
    $core = Join-Path $stage "bin\ai_shield_service.exe"
    if (-not (Test-Path $broker) -or -not (Test-Path $core)) { throw "Package omits required service binaries." }
    & sc.exe config AIShieldBroker binPath= ('"' + $broker + '"') | Out-Null
    & sc.exe config AIShieldCore binPath= ('"' + $core + '"') | Out-Null
    $driverDirectory = Join-Path $stage "drivers"
    if (Test-Path $driverDirectory) {
        Get-ChildItem $driverDirectory -Filter *.inf | ForEach-Object {
            & pnputil.exe /add-driver $_.FullName /install
            if ($LASTEXITCODE -ne 0) { throw "Driver package activation failed: $($_.Name)" }
        }
    }
    Start-Service AIShieldBroker
    Start-Service AIShieldCore
    Start-Sleep -Seconds 2
    if ((Get-Service AIShieldBroker).Status -ne "Running" -or (Get-Service AIShieldCore).Status -ne "Running") {
        throw "Updated services failed their activation health check."
    }
    [ordered]@{ security_version = [uint64]$manifest.security_version; active_slot = $inactive;
        publisher_thumbprint = $manifest.publisher_thumbprint; updated_utc = [DateTime]::UtcNow.ToString("o") } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $statePath -Encoding UTF8
    $activated = $true
} finally {
    if (-not $activated) {
        if (Test-Path $previousBrokerPath) { & sc.exe config AIShieldBroker binPath= ('"' + $previousBrokerPath + '"') | Out-Null }
        if (Test-Path $previousCorePath) { & sc.exe config AIShieldCore binPath= ('"' + $previousCorePath + '"') | Out-Null }
        Start-Service AIShieldBroker -ErrorAction SilentlyContinue
        Start-Service AIShieldCore -ErrorAction SilentlyContinue
    }
    if ($activated) { Remove-Item -LiteralPath $transactionPath -Force }
}
Write-Output "AI Shield update active security_version=$($manifest.security_version) slot=$inactive"
