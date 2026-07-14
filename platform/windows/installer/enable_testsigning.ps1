param(
    [ValidateSet("on", "off")]
    [string]$State = "on"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script from an elevated PowerShell."
}

$secureBoot = $null
$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if (-not $?) {
    $secureBoot = $null
}

if ($State -eq "on" -and $secureBoot -eq $true) {
    Write-Output "Secure Boot is enabled. Windows will reject local test-signed kernel drivers."
    Write-Output "Disable Secure Boot in UEFI firmware or use Microsoft-signed drivers, then run this script again."
}

if ($State -eq "on") {
    & bcdedit.exe /set testsigning on
} else {
    & bcdedit.exe /set testsigning off
}
if ($LASTEXITCODE -ne 0) {
    if ($State -eq "on" -and $secureBoot -eq $true) {
        Write-Output "TESTSIGNING could not be changed because Secure Boot protects the boot policy."
    }
    exit $LASTEXITCODE
}

Write-Output "testsigning=$State"
Write-Output "Restart Windows before loading kernel drivers if the state changed."
