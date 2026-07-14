param([string]$Subject="CN=AI Shield Prototype Test Signing")

$ErrorActionPreference="Stop"
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Elevated execution is required to access the machine code-signing key."
}
$repo=Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$hostPath=Join-Path $repo "build_vs\Release\ai_shield_browser_host.exe"
if(-not(Test-Path $hostPath)){throw "Build the Release browser host first."}
$certificate=Get-ChildItem Cert:\LocalMachine\My|Where-Object {$_.Subject-eq$Subject-and$_.HasPrivateKey}|
    Sort-Object NotAfter -Descending|Select-Object -First 1
if($null-eq$certificate){throw "Code-signing certificate not found: $Subject"}
$signtool=@(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\signtool.exe")|
    Where-Object {Test-Path $_}|Select-Object -First 1
if(-not$signtool){throw "signtool.exe was not found."}
& $signtool sign /fd SHA256 /sha1 $certificate.Thumbprint /s My /sm $hostPath
if($LASTEXITCODE-ne0){exit $LASTEXITCODE}
& $signtool verify /pa /v $hostPath
if($LASTEXITCODE-ne0){exit $LASTEXITCODE}
Write-Output "signed browser host publisher=$($certificate.Thumbprint)"
