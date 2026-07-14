param(
    [Parameter(Mandatory=$true)][string]$PackageDir
)

$ErrorActionPreference = "Stop"
$driverctl = Join-Path $PSScriptRoot "..\..\..\build_vs\Release\ai_shield_driverctl.exe"
$wfp = Join-Path $PackageDir "AIShieldWfp.sys"
$mini = Join-Path $PackageDir "AIShieldMiniFilter.sys"
$proc = Join-Path $PackageDir "AIShieldProcessGuard.sys"

$secureBoot = $null
try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
} catch {
    Write-Warning "Secure Boot status could not be queried in this installer context; treating it as unknown."
}
$systemStartOptions = Get-ItemPropertyValue -LiteralPath `
    "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SystemStartOptions" -ErrorAction SilentlyContinue
$testSigning = [string]$systemStartOptions -match '(?i)(^|\s)TESTSIGNING(\s|$)'
if (-not $testSigning) {
    $testSigning = ((& bcdedit.exe /enum "{current}" 2>$null) -join "`n") -match `
        '(?im)^testsigning\s+(Yes|Ja)\s*$'
}
if ($secureBoot -eq $true -or -not $testSigning) {
    Write-Output "Driver load preflight failed:"
    Write-Output "  SecureBoot=$secureBoot"
    Write-Output "  TestSigning=$testSigning"
    Write-Output "Local test-signed kernel drivers require TESTSIGNING=Yes and Secure Boot disabled."
}

& $driverctl install --wfp $wfp --minifilter $mini --process $proc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $driverctl start
