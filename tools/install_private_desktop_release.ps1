param(
    [Parameter(Mandatory=$true)]
    [string]$MsiPath,
    [string]$LogPath = "runtime\msi-private-desktop-install.log"
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this release installation from an elevated PowerShell."
}
$msi = if ([IO.Path]::IsPathRooted($MsiPath)) { [IO.Path]::GetFullPath($MsiPath) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $MsiPath))
}
$log = if ([IO.Path]::IsPathRooted($LogPath)) { [IO.Path]::GetFullPath($LogPath) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $LogPath))
}
if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw "MSI not found: $msi" }
New-Item -ItemType Directory -Force -Path (Split-Path $log -Parent) | Out-Null

$signature = Get-AuthenticodeSignature -LiteralPath $msi
if ($signature.Status -ne "Valid") { throw "MSI signature is not valid: $($signature.Status)" }

function Get-MsiProductCode([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        $database = $installer.GetType().InvokeMember(
            "OpenDatabase", "InvokeMethod", $null, $installer, @($Path, 0))
        $view = $database.GetType().InvokeMember(
            "OpenView", "InvokeMethod", $null, $database,
            @('SELECT `Value` FROM `Property` WHERE `Property`=''ProductCode'''))
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        if ($null -eq $record) { throw "MSI does not contain a ProductCode." }
        return [string]$record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
    } finally {
        foreach ($object in @($view, $database, $installer)) {
            if ($null -ne $object -and [Runtime.InteropServices.Marshal]::IsComObject($object)) {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($object)
            }
        }
    }
}

function Invoke-Msi([string[]]$Arguments, [string]$Operation) {
    $process = Start-Process msiexec.exe -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -notin @(0, 3010)) {
        throw "$Operation failed with exit code $($process.ExitCode). Log: $log"
    }
    return $process.ExitCode -eq 3010
}

Set-Location $repo
Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
$productCode = Get-MsiProductCode $msi
$installed = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$productCode"
if (-not $installed) {
    $installed = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$productCode"
}
$restartRequired = $false
if ($installed) {
    $uninstallLog = [IO.Path]::ChangeExtension($log, ".uninstall.log")
    $restartRequired = Invoke-Msi -Arguments @(
        "/x", $productCode, "/qn", "/norestart", "/l*v", ('"' + $uninstallLog + '"')) `
        -Operation "Existing MSI removal"
}
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
if (Test-Path -LiteralPath $driverctl -PathType Leaf) {
    & $driverctl stop
    if ($LASTEXITCODE -ne 0) { throw "Existing drivers could not be stopped." }
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")
if ($LASTEXITCODE -ne 0) { throw "Existing drivers could not be uninstalled." }

$restartRequired = (Invoke-Msi -Arguments @(
    "/i", ('"' + $msi + '"'), "/qn", "/norestart", "/l*v", ('"' + $log + '"')) `
    -Operation "MSI installation") -or $restartRequired

Write-Output "installed=$msi"
Write-Output "log=$log"
Write-Output "restart_required=$restartRequired"
exit 0
