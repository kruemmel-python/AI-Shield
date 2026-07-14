param([switch]$PurgeSecurityData)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($PurgeSecurityData) { $forward += "-PurgeSecurityData" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}
$root = Get-AIShieldPrivateRoot
Unregister-ScheduledTask -TaskName "AIShieldPrivateUIResume" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AI Shield") `
    -Recurse -Force -ErrorAction SilentlyContinue
$markerPath = Join-Path $env:ProgramData "AIShield\private-desktop\install.json"
$marker = if (Test-Path -LiteralPath $markerPath) {
    Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
} else { $null }
if ($null -ne $marker -and $marker.schema -ne "AIShieldPrivateDesktopInstall/1") {
    throw "Private desktop installation state is invalid; automatic baseline rollback was stopped."
}
$firewallState = Join-Path $env:ProgramData "AIShield\firewall\state.json"
if ($null -ne $marker -and $marker.firewall_transaction_owned -eq $true -and
    (Test-Path -LiteralPath $firewallState)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\firewall\firewall_baseline.ps1") `
        -Action rollback -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Windows Firewall rollback failed; uninstall stopped." }
}
$defenderState = Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json"
if ($null -ne $marker -and $marker.defender_transaction_owned -eq $true -and
    (Test-Path -LiteralPath $defenderState)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\security\defender_audit_baseline.ps1") `
        -Action rollback -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender rollback failed; uninstall stopped." }
}
$browserScript = Join-Path $root "platform\windows\browser_extension\install_browser_sensor.ps1"
if (Test-Path -LiteralPath $browserScript -PathType Leaf) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $browserScript `
        -Action uninstall -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Browser sensor rollback failed; uninstall stopped." }
}
$arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
    (Join-Path $root "platform\windows\installer\uninstall_product.ps1"),
    "-Confirmation", "UNINSTALL-AI-SHIELD")
if ($PurgeSecurityData) { $arguments += "-PurgeSecurityData" }
& powershell.exe @arguments
if ($LASTEXITCODE -ne 0) { throw "AI Shield product uninstall failed." }
if ($null -ne $marker -and [string]$marker.certificate_thumbprint -match '^[A-Fa-f0-9]{40}$') {
    if ($marker.publisher_certificate_owned -eq $true) {
        Remove-Item -LiteralPath `
            "Cert:\LocalMachine\TrustedPublisher\$($marker.certificate_thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
    if ($marker.root_certificate_owned -eq $true) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($marker.certificate_thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
}
if (-not $PurgeSecurityData) {
    Remove-Item -LiteralPath (Split-Path $markerPath -Parent) -Recurse -Force -ErrorAction SilentlyContinue
}
$msiInstallRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AI_Shield_Private_Desktop"))
$currentPackageRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if ($currentPackageRoot -eq $msiInstallRoot) {
    Remove-Item -LiteralPath (Join-Path $currentPackageRoot "runtime") -Recurse -Force `
        -ErrorAction SilentlyContinue
}
Write-Output "AI Shield Private Desktop was removed."
