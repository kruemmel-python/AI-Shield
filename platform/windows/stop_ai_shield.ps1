param(
    [switch]$KeepDrivers
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$pidFile = Join-Path $repo "runtime\ai_shield_prototype.pid"
$servicePidFile = Join-Path $env:ProgramData "AIShield\gateway.pid"
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'))
    if ($KeepDrivers) {
        $arguments += "-KeepDrivers"
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}

if (Test-Path -LiteralPath $policyScript) {
    $stateFile = Join-Path $env:ProgramData "AIShield\policy\state.json"
    if (Test-Path -LiteralPath $stateFile) {
        $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        $version = [uint64]$state.security_version + 1
        $input = Join-Path $env:TEMP "ai-shield-stop-policy.json"
        $envelope = Join-Path $env:TEMP "ai-shield-stop-policy.aipolicy"
        [IO.File]::WriteAllText($input, (([ordered]@{ security_version=$version; mode="audit";
            block_inbound_port=0; redirect_outbound_port=0; proxy_port=0;
            block_quarantine_execution=$true; block_user_temp_execution=$true;
            block_download_execution=$false; block_risky_script_command=$true;
            block_office_child_process=$true; system_network_guard=$false;
            block_unsolicited_inbound=$false; block_browser_non_web=$false }) | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign -InputFile $input -OutputFile $envelope
        if ($LASTEXITCODE -eq 0) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $envelope
        }
        Remove-Item -LiteralPath $input, $envelope -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $pidFile) {
    $gatewayPid = [int](Get-Content -LiteralPath $pidFile -Raw)
    $gateway = Get-Process -Id $gatewayPid -ErrorAction SilentlyContinue
    if ($gateway) {
        Stop-Process -Id $gatewayPid
        Write-Output "stopped AI Shield gateway PID $gatewayPid"
    } else {
        Write-Output "AI Shield gateway was not running"
    }
    Remove-Item -LiteralPath $pidFile -Force
    Remove-Item -LiteralPath $servicePidFile -Force -ErrorAction SilentlyContinue
} else {
    Write-Output "AI Shield gateway state file not found"
}

if (-not $KeepDrivers) {
    Stop-Service -Name "AIShieldBroker" -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $driverctl)) {
        throw "Driver control executable not found: $driverctl"
    }
    & $driverctl stop
    if ($LASTEXITCODE -ne 0) {
        throw "One or more drivers could not be stopped."
    }
}

Write-Output "AI Shield prototype stopped"
