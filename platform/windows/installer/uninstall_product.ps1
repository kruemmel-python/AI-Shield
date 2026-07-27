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
$driverServices = @("AIShieldWfp", "AIShieldMiniFilter", "AIShieldProcessGuard")
$allDriversInstalled = @($driverServices | Where-Object {
    $null -ne (Get-Service -Name $_ -ErrorAction SilentlyContinue)
}).Count -eq $driverServices.Count
if ((Test-Path $kernelctl) -and $allDriversInstalled) { & $kernelctl audit }
Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_core_service.ps1") -Action uninstall
if ($LASTEXITCODE -ne 0) { throw "Core service removal failed." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_broker.ps1") -Action uninstall
if ($LASTEXITCODE -ne 0) { throw "Broker service removal failed." }
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    $remainingUserServices = @("AIShieldCore", "AIShieldBroker") | Where-Object {
        (& sc.exe query $_ 2>$null | Out-String) -match 'SERVICE_NAME'
    }
    if ($remainingUserServices.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
if ($remainingUserServices.Count -ne 0) {
    throw "User-mode services remain installed: $($remainingUserServices -join ', ')"
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")
if ($LASTEXITCODE -ne 0) { throw "Driver removal failed; security data was preserved." }
$deadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    $remainingDrivers = $driverServices | Where-Object {
        (& sc.exe query $_ 2>$null | Out-String) -match 'SERVICE_NAME'
    }
    if ($remainingDrivers.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
if ($remainingDrivers.Count -ne 0) {
    throw "Kernel drivers remain installed: $($remainingDrivers -join ', ')"
}
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AIShield"))
$expectedInstallRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\AIShield'
if ($installRoot -ne $expectedInstallRoot) { throw "Installation path validation failed." }
if (Test-Path -LiteralPath $installRoot) { Remove-Item -LiteralPath $installRoot -Recurse -Force }
if ($PurgeSecurityData) {
    $data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "AIShield"))
    $expected = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\AIShield'
    if ($data -ne $expected) { throw "Security data path validation failed." }
    Remove-Item -LiteralPath $data -Recurse -Force
}
Write-Output "AI Shield uninstalled. Security data preserved=$(-not $PurgeSecurityData)"
