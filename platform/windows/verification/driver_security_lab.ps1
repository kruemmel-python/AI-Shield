param(
    [ValidateSet("preflight", "arm-verifier", "reset-verifier", "arm-hvci", "status")]
    [string]$Action = "preflight",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference="Stop"
$drivers=@("AIShieldWfp.sys","AIShieldMiniFilter.sys","AIShieldProcessGuard.sys")
$resultDir=Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")) "runtime\verification"
New-Item -ItemType Directory -Force -Path $resultDir|Out-Null

function Confirm-Administrator {
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw "Run from an elevated PowerShell."}
}

function Get-SecurityState {
    $secureBoot=$null
    $secureBoot=Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    $deviceGuard=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $verifier=(& verifier.exe /querysettings 2>&1)-join "`n"
    return [ordered]@{
        timestamp_utc=[DateTime]::UtcNow.ToString("o")
        secure_boot=$secureBoot
        virtualization_based_security_status=$deviceGuard.VirtualizationBasedSecurityStatus
        security_services_configured=@($deviceGuard.SecurityServicesConfigured)
        security_services_running=@($deviceGuard.SecurityServicesRunning)
        code_integrity_policy_enforcement_status=$deviceGuard.CodeIntegrityPolicyEnforcementStatus
        verifier_output=$verifier
    }
}

Confirm-Administrator

if($Action -in @("preflight","status")){
    $state=Get-SecurityState
    $output=Join-Path $resultDir "security-state.json"
    [IO.File]::WriteAllText($output,($state|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    $state|ConvertTo-Json -Depth 5
    Write-Output "result=$output"
    exit 0
}

if(-not $ConfirmSystemChange){throw "$Action requires -ConfirmSystemChange."}

if($Action -eq "arm-verifier"){
    & verifier.exe /reset | Out-Null
    & verifier.exe /standard /driver $drivers
    if($LASTEXITCODE -ne 0){throw "Driver Verifier configuration failed."}
    Write-Output "Driver Verifier armed only for: $($drivers -join ', ')"
    Write-Output "Reboot manually on a disposable test system. Recovery: verifier.exe /reset"
    exit 0
}

if($Action -eq "reset-verifier"){
    & verifier.exe /reset
    if($LASTEXITCODE -ne 0){throw "Driver Verifier reset failed."}
    Write-Output "Driver Verifier reset; reboot manually if it was active."
    exit 0
}

if($Action -eq "arm-hvci"){
    $deviceGuardPath="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $hvciPath=Join-Path $deviceGuardPath "Scenarios\HypervisorEnforcedCodeIntegrity"
    New-Item -Path $hvciPath -Force|Out-Null
    New-ItemProperty -Path $deviceGuardPath -Name EnableVirtualizationBasedSecurity -PropertyType DWord -Value 1 -Force|Out-Null
    New-ItemProperty -Path $deviceGuardPath -Name RequirePlatformSecurityFeatures -PropertyType DWord -Value 1 -Force|Out-Null
    New-ItemProperty -Path $hvciPath -Name Enabled -PropertyType DWord -Value 1 -Force|Out-Null
    New-ItemProperty -Path $hvciPath -Name Locked -PropertyType DWord -Value 0 -Force|Out-Null
    Write-Output "HVCI requested with UEFI lock disabled for laboratory rollback."
    Write-Output "Reboot manually, then run -Action status and the reboot qualification suite."
    exit 0
}
