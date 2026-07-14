$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$logDirectory = Join-Path $repo "runtime"
$log = Join-Path $logDirectory "deploy-current-prototype.log"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
Start-Transcript -Path $log -Force | Out-Null
$completed = $false
try {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Deployment requires an elevated PowerShell."
    }
    Set-Location $repo
    $cmake = "C:\Program Files\CMake\bin\cmake.exe"
    $ctest = "C:\Program Files\CMake\bin\ctest.exe"
    $driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
    $kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
    $pidFile = Join-Path $repo "runtime\ai_shield_prototype.pid"

    Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
    if (Test-Path $pidFile) {
        $gatewayPid = [uint32](Get-Content $pidFile -Raw)
        Stop-Process -Id $gatewayPid -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
    Get-Process ai_shield_prototype -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path $kernelctl) { & $kernelctl audit }
    if (Test-Path $driverctl) { & $driverctl stop }

    & $cmake -S . -B build_vs -G "Visual Studio 17 2022" -A x64 -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
    if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
    & $cmake --build build_vs --config Release --parallel
    if ($LASTEXITCODE -ne 0) { throw "Release build failed." }
    & $ctest --test-dir build_vs -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "Release tests failed." }
    $integrations = Join-Path $repo "build_vs\Release\ai_shield_integrations.exe"
    & $integrations tpm-status
    if ($LASTEXITCODE -eq 0) {
        & $integrations tpm-provision
        if ($LASTEXITCODE -ne 0) { throw "TPM trust-anchor provisioning failed." }
        & $integrations tpm-status
    } else {
        Write-Output "TPM platform provider unavailable; DPAPI runtime protection remains active."
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\security\kernel_hardware_hardening.ps1") `
        -Action apply -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Kernel and hardware mitigation baseline failed." }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\build_drivers.ps1") `
        -Configuration Release
    if ($LASTEXITCODE -ne 0) { throw "WDK driver build failed." }
    $package = Join-Path $repo "driver_package\Release"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\sign_driver_package.ps1") `
        -PackageDir $package
    if ($LASTEXITCODE -ne 0) { throw "Driver signing failed." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_drivers.ps1") `
        -PackageDir $package
    if ($LASTEXITCODE -ne 0) { throw "Driver installation failed." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_broker.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Broker installation failed." }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_core_service.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Core service installation failed." }

    $policyState = Join-Path $env:ProgramData "AIShield\policy\state.json"
    if (Test-Path $policyState) {
        $state = Get-Content $policyState -Raw | ConvertFrom-Json
        $policyInput = Join-Path $repo "runtime\deployment-audit-policy.json"
        $policyEnvelope = Join-Path $repo "runtime\deployment-audit-policy.aipolicy"
        [ordered]@{ security_version = [uint64]$state.security_version + 1; mode = "audit";
            block_inbound_port = 0; redirect_outbound_port = 0; proxy_port = 0;
            block_quarantine_execution = $true; block_user_temp_execution = $true;
            block_download_execution = $false; block_risky_script_command = $true;
            block_office_child_process = $true; system_network_guard = $true;
            block_unsolicited_inbound = $false; block_browser_non_web = $false } | ConvertTo-Json -Compress |
            Set-Content -LiteralPath $policyInput -Encoding UTF8
        $policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign `
            -InputFile $policyInput -OutputFile $policyEnvelope
        if ($LASTEXITCODE -ne 0) { throw "Deployment audit policy signing failed." }
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $policyEnvelope
        Remove-Item $policyInput,$policyEnvelope -Force -ErrorAction SilentlyContinue
        if ($LASTEXITCODE -ne 0) { throw "Deployment audit policy activation failed." }
    }
    & (Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe") status
    & (Join-Path $repo "build_vs\Release\ai_shield_broker.exe") runtime-status
    Get-Service AIShieldCore,AIShieldBroker,AIShieldWfp,AIShieldMiniFilter,AIShieldProcessGuard |
        Select-Object Name,Status,StartType
    $completed = $true
} finally {
    Stop-Transcript | Out-Null
    if (-not $completed) { Write-Output "Deployment failed. Log: $log" }
}
Write-Output "Deployment completed. Log: $log"
