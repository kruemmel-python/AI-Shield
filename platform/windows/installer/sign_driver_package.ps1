param(
    [string]$PackageDir = "driver_package\Release",
    [string]$Subject = "CN=AI Shield Prototype Test Signing",
    [switch]$ForceNewCertificate
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script from an elevated PowerShell so the certificate can be trusted for driver loading."
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
if ([System.IO.Path]::IsPathRooted($PackageDir)) {
    $resolvedPackage = Resolve-Path $PackageDir
} else {
    $resolvedPackage = Resolve-Path (Join-Path $repo $PackageDir)
}
$certificateName = $Subject
$certStore = "Cert:\LocalMachine\My"
$rootStore = "Cert:\LocalMachine\Root"
$publisherStore = "Cert:\LocalMachine\TrustedPublisher"

$existing = Get-ChildItem $certStore |
    Where-Object { $_.Subject -eq $certificateName -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($ForceNewCertificate -and $existing) {
    Remove-Item -LiteralPath $existing.PSPath -Force
    $existing = $null
}

if (-not $existing) {
    $existing = New-SelfSignedCertificate `
        -Subject $certificateName `
        -Type CodeSigningCert `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation $certStore `
        -NotAfter (Get-Date).AddYears(5)
}

$cerPath = Join-Path $resolvedPackage "ai_shield_testsigning.cer"
Export-Certificate -Cert $existing -FilePath $cerPath -Force | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation $rootStore | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation $publisherStore | Out-Null

$signtoolCandidates = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe"
)
$signtool = $signtoolCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $signtool) {
    throw "signtool.exe not found. Install the Windows SDK signing tools."
}

$drivers = Get-ChildItem -Path $resolvedPackage -Filter *.sys
if ($drivers.Count -eq 0) {
    throw "No .sys files found in $resolvedPackage."
}

foreach ($driver in $drivers) {
    & $signtool sign /fd SHA256 /sha1 $existing.Thumbprint /s My /sm $driver.FullName
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    & $signtool verify /pa /v $driver.FullName
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Write-Output "signed package: $resolvedPackage"
Write-Output "certificate thumbprint: $($existing.Thumbprint)"
