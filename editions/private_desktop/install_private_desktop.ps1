param(
    [switch]$SkipWindowsBaseline,
    [switch]$SuppressUiLaunch,
    [switch]$RefreshInstalledComponents
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($SkipWindowsBaseline) { $forward += "-SkipWindowsBaseline" }
    if ($SuppressUiLaunch) { $forward += "-SuppressUiLaunch" }
    if ($RefreshInstalledComponents) { $forward += "-RefreshInstalledComponents" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}

$root = Get-AIShieldPrivateRoot
$driverctl = Join-Path $root "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $root "build_vs\Release\ai_shield_kernelctl.exe"
$package = Join-Path $root "driver_package\Release"
$certificate = Join-Path $package "ai_shield_testsigning.cer"
$installDrivers = Join-Path $root "platform\windows\installer\install_drivers.ps1"
$installBroker = Join-Path $root "platform\windows\installer\install_broker.ps1"
$installCore = Join-Path $root "platform\windows\installer\install_core_service.ps1"
$policyScript = Join-Path $root "platform\windows\policy\ai_shield_policy.ps1"
$browserScript = Join-Path $root "platform\windows\browser_extension\install_browser_sensor.ps1"
$recoveryScript = Join-Path $root "platform\windows\ransomware\ransomware_recovery.ps1"
$markerRoot = Join-Path $env:ProgramData "AIShield\private-desktop"
$markerPath = Join-Path $markerRoot "install.json"
$uiLauncher = Join-Path $PSScriptRoot "AI_Shield_UI.cmd"
$trayManager = Join-Path $PSScriptRoot "tray\manage_tray_agent.ps1"

function Install-AIShieldPrivateUiShortcut {
    Assert-AIShieldFile $uiLauncher "Private desktop UI launcher"
    $shortcutDirectory = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AI Shield"
    New-Item -ItemType Directory -Force -Path $shortcutDirectory | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $shortcutDirectory "AI Shield Private Desktop.lnk"))
    $shortcut.TargetPath = $uiLauncher
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = "AI Shield Private Desktop öffnen"
    $shortcut.Save()
}
function Install-AIShieldPrivateTray {
    Assert-AIShieldFile $trayManager "Private desktop tray manager"
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $trayManager, "-Action", "install")
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { $arguments += "-NoImmediateStart" }
    & powershell.exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "Tray autostart installation failed." }
}
function Install-AIShieldBrowserSensor {
    $browserCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $browserScript -Action install `
        -PublisherThumbprint $browserCertificate.Thumbprint -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Browser sensor installation failed." }
}
function Initialize-AIShieldRecoveryBaseline {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        $pending = Join-Path $env:ProgramData "AIShield\recovery-baseline.pending"
        [IO.File]::WriteAllText($pending, [DateTime]::UtcNow.ToString('o'), [Text.UTF8Encoding]::new($false))
        Write-Output "Recovery baseline deferred to the first interactive UI start."
        return
    }
    $status = & powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $recoveryScript -Action status | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "Recovery-Vault status failed." }
    if ([string]::IsNullOrWhiteSpace([string]$status.latest_snapshot)) {
        $snapshot = & powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $recoveryScript -Action initialize | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $snapshot.snapshot_id) { throw "Initial recovery baseline failed." }
        Write-Output "Recovery baseline created: $($snapshot.snapshot_id), records=$(@($snapshot.records).Count), skipped=$($snapshot.skipped)"
    }
}

if (Test-Path -LiteralPath $markerPath) {
    $existingMarker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($existingMarker.schema -ne "AIShieldPrivateDesktopInstall/1" -or
        $existingMarker.installation_complete -ne $true) {
        throw "An incomplete or invalid private desktop installation exists. Run Deinstallieren.cmd before retrying."
    }
    Write-Output "AI Shield Private Desktop is already installed; activating protection."
    if ($RefreshInstalledComponents) {
        Write-Output "Refreshing installed user-mode services and reloading kernel drivers in place."
        Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
        & $driverctl stop
        if ($LASTEXITCODE -ne 0) { throw "Installed drivers could not be stopped for the update." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installDrivers -PackageDir $package
        if ($LASTEXITCODE -ne 0) { throw "Driver refresh failed with exit code $LASTEXITCODE." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installBroker
        if ($LASTEXITCODE -ne 0) { throw "Broker refresh failed with exit code $LASTEXITCODE." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installCore
        if ($LASTEXITCODE -ne 0) { throw "Core service refresh failed with exit code $LASTEXITCODE." }
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start_private_desktop.ps1") `
        -HardenDownloads
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Install-AIShieldBrowserSensor
    Initialize-AIShieldRecoveryBaseline
    Install-AIShieldPrivateUiShortcut
    Install-AIShieldPrivateTray
    if (-not $SuppressUiLaunch) { Start-Process -FilePath $uiLauncher }
    exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) { throw "AI Shield Private Desktop requires 64-bit Windows." }
foreach ($required in @($driverctl, $kernelctl, $certificate, $installDrivers, $installBroker, $installCore,
        $policyScript, $browserScript, $recoveryScript, (Join-Path $root "build_vs\Release\ai_shield_browser_host.exe"),
        $uiLauncher, (Join-Path $PSScriptRoot "ui\start_private_ui.ps1"),
        (Join-Path $PSScriptRoot "ui\AIShield.PrivateDesktop.UI.xaml"),
        $trayManager, (Join-Path $PSScriptRoot "tray\start_tray_agent.ps1"),
        (Join-Path $package "AIShieldWfp.sys"),
        (Join-Path $package "AIShieldMiniFilter.sys"), (Join-Path $package "AIShieldProcessGuard.sys"))) {
    Assert-AIShieldFile $required "Required package file"
}

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
    $bootConfiguration = (& bcdedit.exe /enum "{current}" 2>$null) -join "`n"
    $testSigning = $bootConfiguration -match '(?im)^testsigning\s+(Yes|Ja)\s*$'
}
if ($secureBoot -eq $true -or -not $testSigning) {
    throw ("The prototype drivers cannot be installed in the current boot configuration. " +
        "Secure Boot must be disabled and TESTSIGNING must be enabled for this local prototype. " +
        "Do not change either setting on a production PC. SecureBoot=$secureBoot TestSigning=$testSigning")
}

Write-Output "Installing AI Shield Private Desktop"
$certificateInfo = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
$certificateThumbprint = $certificateInfo.Thumbprint
$rootCertificatePath = "Cert:\LocalMachine\Root\$certificateThumbprint"
$publisherCertificatePath = "Cert:\LocalMachine\TrustedPublisher\$certificateThumbprint"
$rootCertificateOwned = -not (Test-Path -LiteralPath $rootCertificatePath)
$publisherCertificateOwned = -not (Test-Path -LiteralPath $publisherCertificatePath)
if ($rootCertificateOwned) {
    Import-Certificate -FilePath $certificate -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
}
if ($publisherCertificateOwned) {
    Import-Certificate -FilePath $certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}

New-Item -ItemType Directory -Force -Path $markerRoot | Out-Null
& icacls.exe $markerRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect the private edition state directory." }
$initialMarker = [ordered]@{
    schema = "AIShieldPrivateDesktopInstall/1"
    installed_utc = [DateTime]::UtcNow.ToString("o")
    installation_complete = $false
    certificate_thumbprint = $certificateThumbprint
    root_certificate_owned = $rootCertificateOwned
    publisher_certificate_owned = $publisherCertificateOwned
    firewall_transaction_owned = $false
    defender_transaction_owned = $false
    browser_sensor_owned = $false
    recovery_baseline_owned = $false
    enterprise_connectors = $false
}
[IO.File]::WriteAllText($markerPath, ($initialMarker | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installDrivers -PackageDir $package
if ($LASTEXITCODE -ne 0) { throw "Driver installation failed with exit code $LASTEXITCODE." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installBroker
if ($LASTEXITCODE -ne 0) { throw "Broker installation failed with exit code $LASTEXITCODE." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installCore
if ($LASTEXITCODE -ne 0) { throw "Core service installation failed with exit code $LASTEXITCODE." }
Install-AIShieldBrowserSensor
Initialize-AIShieldRecoveryBaseline

$pin = Join-Path $env:ProgramData "AIShield\policy\signer.thumbprint"
if (-not (Test-Path -LiteralPath $pin)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action initialize
    if ($LASTEXITCODE -ne 0) { throw "Local policy trust initialization failed." }
}

$firewallApplied = $false
$defenderApplied = $false
if (-not $SkipWindowsBaseline) {
    $firewallScript = Join-Path $root "platform\windows\firewall\firewall_baseline.ps1"
    $firewallState = Join-Path $env:ProgramData "AIShield\firewall\state.json"
    if (-not (Test-Path -LiteralPath $firewallState)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $firewallScript `
            -Action apply -ConfirmSystemChange
        if ($LASTEXITCODE -ne 0) { throw "Windows Firewall baseline failed." }
        $firewallApplied = $true
    }
    $defenderScript = Join-Path $root "platform\windows\security\defender_audit_baseline.ps1"
    $defenderState = Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json"
    if (-not (Test-Path -LiteralPath $defenderState)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $defenderScript `
            -Action apply-audit -ConfirmSystemChange
        if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender audit baseline failed." }
        $defenderApplied = $true
    }
}

$marker = [ordered]@{
    schema = "AIShieldPrivateDesktopInstall/1"
    installed_utc = [DateTime]::UtcNow.ToString("o")
    installation_complete = $true
    certificate_thumbprint = $certificateThumbprint
    root_certificate_owned = $rootCertificateOwned
    publisher_certificate_owned = $publisherCertificateOwned
    firewall_transaction_owned = $firewallApplied
    defender_transaction_owned = $defenderApplied
    browser_sensor_owned = $true
    recovery_baseline_owned = $true
    enterprise_connectors = $false
}
[IO.File]::WriteAllText($markerPath, ($marker | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

Install-AIShieldPrivateUiShortcut
Install-AIShieldPrivateTray

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start_private_desktop.ps1") `
    -HardenDownloads
if ($LASTEXITCODE -ne 0) { throw "Private desktop protection could not be started." }
Write-Output "AI Shield Private Desktop is installed and active."
if (-not $SuppressUiLaunch) { Start-Process -FilePath $uiLauncher }
