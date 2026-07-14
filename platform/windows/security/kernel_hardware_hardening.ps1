param(
    [ValidateSet("status","apply","rollback")][string]$Action = "status",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$stateRoot = Join-Path $env:ProgramData "AIShield\hardening"
$statePath = Join-Path $stateRoot "kernel-hardware-before.json"
$deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$hvciPath = Join-Path $deviceGuardPath "Scenarios\HypervisorEnforcedCodeIntegrity"
$systemGuardPath = Join-Path $deviceGuardPath "Scenarios\SystemGuard"
$ciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
$integrations = Join-Path $repo "build_vs\Release\ai_shield_integrations.exe"

function Read-Value([string]$Path,[string]$Name) {
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}
function Write-Value([string]$Path,[string]$Name,[int]$Value) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}
function Restore-Value([string]$Path,[string]$Name,$Value) {
    if ($null -eq $Value) { Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue }
    else { Write-Value $Path $Name ([int]$Value) }
}
function Get-TpmAnchorStatus {
    if (-not (Test-Path -LiteralPath $integrations -PathType Leaf)) { return "unavailable" }
    $output = (& $integrations tpm-status 2>$null) -join ";"
    if ($LASTEXITCODE -ne 0) { return "unavailable" }
    return $output
}
function Test-TransactionState {
    try { $present = Test-Path -LiteralPath $statePath -ErrorAction Stop; return [bool]$present }
    catch { return $false }
}
function Get-Status {
    $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
        -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $available = @($(if($null-ne$deviceGuard){$deviceGuard.AvailableSecurityProperties}else{@()}))
    $running = @($(if($null-ne$deviceGuard){$deviceGuard.SecurityServicesRunning}else{@()}))
    $configured = @($(if($null-ne$deviceGuard){$deviceGuard.SecurityServicesConfigured}else{@()}))
    $secureBootValue = Read-Value "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled"
    $secureBoot = $secureBootValue -eq 1
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $tpmReady = $null-ne$tpm-and$tpm.TpmPresent-and$tpm.TpmReady-and$tpm.TpmEnabled
    $anchor = Get-TpmAnchorStatus
    if (-not $tpmReady -and $anchor -match "provider=1" -and $anchor -match "hardware=1") { $tpmReady = $true }
    $bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object VolumeType -eq OperatingSystem | Select-Object -First 1)
    $hvciConfigured = (Read-Value $hvciPath "Enabled") -eq 1
    $secureLaunchConfigured = (Read-Value $systemGuardPath "Enabled") -eq 1
    [ordered]@{
        schema="AIShieldKernelHardwareStatus/1"; transaction=(Test-TransactionState);
        secure_boot=$secureBoot; test_signing=([string](Read-Value "HKLM:\SYSTEM\CurrentControlSet\Control" "SystemStartOptions") -match "(?i)TESTSIGNING");
        tpm_ready=$tpmReady; tpm_anchor=($anchor -match "key=1"); tpm_observed=$anchor;
        vbs_configured=((Read-Value $deviceGuardPath "EnableVirtualizationBasedSecurity") -eq 1);
        hvci_configured=$hvciConfigured; hvci_running=($running -contains 2);
        vulnerable_driver_blocklist=((Read-Value $ciPath "VulnerableDriverBlocklistEnable") -eq 1);
        dma_protection_available=($available -contains 3); dma_required=((Read-Value $deviceGuardPath "RequirePlatformSecurityFeatures") -eq 3);
        secure_launch_configured=$secureLaunchConfigured; secure_launch_running=($running -contains 3);
        smm_firmware_measurement_running=($running -contains 4);
        kernel_stack_protection_running=($running -contains 5 -or $running -contains 6);
        bitlocker_active=($bitlocker.Count -gt 0 -and [string]$bitlocker[0].ProtectionStatus -eq "On");
        hardware_rooted_chain=($secureBoot -and $tpmReady -and ($running -contains 2));
        restart_required=(($hvciConfigured -and -not ($running -contains 2)) -or
            ($secureLaunchConfigured -and -not ($running -contains 3)));
        available_security_properties=$available; configured_security_services=$configured; running_security_services=$running;
        limitation="Mitigates kernel and firmware attack classes; cannot guarantee detection of unknown silicon, firmware or supply-chain compromise."
    }
}

if ($Action -eq "status") { Get-Status | ConvertTo-Json -Depth 6 -Compress; exit 0 }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not $ConfirmSystemChange) { throw "Elevated execution and -ConfirmSystemChange are required." }

if ($Action -eq "rollback") {
    if (-not (Test-Path -LiteralPath $statePath)) { throw "No AI Shield kernel/hardware transaction exists." }
    $before = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Restore-Value $deviceGuardPath "EnableVirtualizationBasedSecurity" $before.enable_vbs
    Restore-Value $deviceGuardPath "RequirePlatformSecurityFeatures" $before.require_platform
    Restore-Value $hvciPath "Enabled" $before.hvci_enabled
    Restore-Value $hvciPath "Locked" $before.hvci_locked
    Restore-Value $systemGuardPath "Enabled" $before.system_guard_enabled
    Restore-Value $ciPath "VulnerableDriverBlocklistEnable" $before.driver_blocklist
    Remove-Item -LiteralPath $statePath -Force
    Get-Status | ConvertTo-Json -Depth 6 -Compress
    exit 0
}

if (Test-Path -LiteralPath $statePath) { Get-Status | ConvertTo-Json -Depth 6 -Compress; exit 0 }
New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
& icacls.exe $stateRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect kernel/hardware rollback state." }
$before = [ordered]@{schema="AIShieldKernelHardwareBackup/1";created_utc=[DateTime]::UtcNow.ToString("o");
    enable_vbs=Read-Value $deviceGuardPath "EnableVirtualizationBasedSecurity";
    require_platform=Read-Value $deviceGuardPath "RequirePlatformSecurityFeatures";
    hvci_enabled=Read-Value $hvciPath "Enabled";hvci_locked=Read-Value $hvciPath "Locked";
    system_guard_enabled=Read-Value $systemGuardPath "Enabled";
    driver_blocklist=Read-Value $ciPath "VulnerableDriverBlocklistEnable"}
[IO.File]::WriteAllText($statePath, ($before|ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))

$preflight = Get-Status
Write-Value $deviceGuardPath "EnableVirtualizationBasedSecurity" 1
Write-Value $hvciPath "Enabled" 1
Write-Value $hvciPath "Locked" 0
Write-Value $ciPath "VulnerableDriverBlocklistEnable" 1
if ($preflight.secure_boot -and $preflight.dma_protection_available) {
    Write-Value $deviceGuardPath "RequirePlatformSecurityFeatures" 3
}
if ($preflight.secure_boot -and $preflight.tpm_ready) {
    Write-Value $systemGuardPath "Enabled" 1
}
if ($preflight.tpm_ready -and -not $preflight.tpm_anchor -and (Test-Path $integrations)) {
    & $integrations tpm-provision | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TPM trust-anchor provisioning failed." }
}
Get-Status | ConvertTo-Json -Depth 6 -Compress
