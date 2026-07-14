param(
    [Parameter(Mandatory=$true)][ValidateSet("UNINSTALL-AI-SHIELD")][string]$Confirmation,
    [string]$AuditExportDirectory,
    [switch]$PurgeSecurityData
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uninstall requires an elevated PowerShell."
}
if ($AuditExportDirectory) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\admin\ai_shield_admin.ps1") `
        -Action audit-export -OutputDirectory $AuditExportDirectory
    if ($LASTEXITCODE -ne 0) { throw "Mandatory audit export failed; uninstall stopped." }
}
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
if (Test-Path $kernelctl) { & $kernelctl audit }
Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_core_service.ps1") -Action uninstall
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_broker.ps1") -Action uninstall
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AIShield"))
$expectedInstallRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\AIShield'
if ($installRoot -ne $expectedInstallRoot) { throw "Installation path validation failed." }
if (Test-Path -LiteralPath $installRoot) { Remove-Item -LiteralPath $installRoot -Recurse -Force }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")
if ($LASTEXITCODE -ne 0) { throw "Driver removal failed; security data was preserved." }
if ($PurgeSecurityData) {
    $data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "AIShield"))
    $expected = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\AIShield'
    if ($data -ne $expected) { throw "Security data path validation failed." }
    Remove-Item -LiteralPath $data -Recurse -Force
}
Write-Output "AI Shield uninstalled. Security data preserved=$(-not $PurgeSecurityData)"
