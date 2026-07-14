param(
    [ValidateSet("Backend", "Demo")]
    [string]$Mode = "Backend",
    [ValidateRange(1, 65535)]
    [int]$ListenPort = 18080,
    [ValidateRange(1, 65535)]
    [int]$BackendPort = 18081,
    [string]$BackendHost = "127.0.0.1",
    [switch]$EnableEnforcement
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$prototype = Join-Path $repo "build_vs\Release\ai_shield_prototype.exe"
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$brokerInstallScript = Join-Path $repo "platform\windows\installer\install_broker.ps1"
$coreInstallScript = Join-Path $repo "platform\windows\installer\install_core_service.ps1"
$updateRecoveryScript = Join-Path $repo "platform\windows\installer\recover_pending_update.ps1"
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$package = Join-Path $repo "driver_package\Release"
$installScript = Join-Path $repo "platform\windows\installer\install_drivers.ps1"
$runtime = Join-Path $repo "runtime"
$quarantine = Join-Path $repo "AI_Shield_Quarantine"
$pidFile = Join-Path $runtime "ai_shield_prototype.pid"
$servicePidFile = Join-Path $env:ProgramData "AIShield\gateway.pid"
$stdoutLog = Join-Path $runtime "ai_shield_prototype.out.log"
$stderrLog = Join-Path $runtime "ai_shield_prototype.err.log"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"'),
        "-Mode", $Mode,
        "-ListenPort", $ListenPort,
        "-BackendPort", $BackendPort,
        "-BackendHost", $BackendHost
    )
    if ($EnableEnforcement) {
        $arguments += "-EnableEnforcement"
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}

Write-Output "AI Shield prototype startup"
Write-Output "repository: $repo"

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $updateRecoveryScript
if ($LASTEXITCODE -ne 0) { throw "Pending binary update recovery failed." }

if (-not (Test-Path -LiteralPath $prototype)) {
    throw "Prototype executable not found: $prototype. Build the Release configuration first."
}
if (-not (Test-Path -LiteralPath $driverctl)) {
    throw "Driver control executable not found: $driverctl. Build the Release configuration first."
}
if (-not (Test-Path -LiteralPath $kernelctl)) {
    throw "Kernel control executable not found: $kernelctl. Build the Release configuration first."
}
if (-not (Test-Path -LiteralPath $broker)) {
    throw "Telemetry broker not found: $broker. Build the Release configuration first."
}

if ($Mode -eq "Backend") {
    $backendListener = Get-NetTCPConnection -State Listen -LocalPort $BackendPort -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq $BackendHost -or $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" } |
        Select-Object -First 1
    if (-not $backendListener) {
        throw "No local backend is listening on ${BackendHost}:${BackendPort}. Start the backend or use -Mode Demo."
    }
    Write-Output "backend ready: ${BackendHost}:${BackendPort}"
}

$existingListener = Get-NetTCPConnection -State Listen -LocalPort $ListenPort -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($existingListener) {
    $owner = Get-Process -Id $existingListener.OwningProcess -ErrorAction SilentlyContinue
    $ownerName = if ($owner) { $owner.ProcessName } else { "unknown" }
    throw "Listener port $ListenPort is already used by PID $($existingListener.OwningProcess) ($ownerName)."
}

$driverStatus = (& $driverctl status 2>&1) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "Driver status query failed.`n$driverStatus"
}
if ($driverStatus -match "not installed") {
    $requiredDrivers = @(
        (Join-Path $package "AIShieldWfp.sys"),
        (Join-Path $package "AIShieldMiniFilter.sys"),
        (Join-Path $package "AIShieldProcessGuard.sys")
    )
    foreach ($driver in $requiredDrivers) {
        if (-not (Test-Path -LiteralPath $driver)) {
            throw "Driver package is incomplete: $driver"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $driver
        if ($signature.Status -ne "Valid") {
            throw "Driver signature is not valid: $driver ($($signature.Status))"
        }
    }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript -PackageDir $package
    if ($LASTEXITCODE -ne 0) {
        throw "Driver installation failed with exit code $LASTEXITCODE."
    }
} else {
    & $driverctl start
    if ($LASTEXITCODE -ne 0) {
        throw "One or more drivers could not be started. Run ai_shield_driverctl.exe status for details."
    }
}

$driverStatus = (& $driverctl status 2>&1) -join "`n"
Write-Output $driverStatus
$runningCount = ([regex]::Matches($driverStatus, "state=4 win32_exit=0")).Count
if ($runningCount -ne 3) {
    throw "Driver health check failed: expected three running drivers, found $runningCount."
}

& $kernelctl audit
if ($LASTEXITCODE -ne 0) {
    throw "Kernel sensors did not accept the audit policy. Install the current driver package."
}

$policyPin = Join-Path $env:ProgramData "AIShield\policy\signer.thumbprint"
if (-not (Test-Path -LiteralPath $policyPin)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action initialize
    if ($LASTEXITCODE -ne 0) { throw "Policy trust initialization failed." }
}

$brokerService = Get-Service -Name "AIShieldBroker" -ErrorAction SilentlyContinue
if (-not $brokerService) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $brokerInstallScript -Action install
    if ($LASTEXITCODE -ne 0) { throw "Telemetry broker installation failed." }
} elseif ($brokerService.Status -ne "Running") {
    Start-Service -Name "AIShieldBroker"
}
$brokerService = Get-Service -Name "AIShieldBroker"
if ($brokerService.Status -ne "Running") { throw "Telemetry broker health check failed." }

$coreService = Get-Service -Name "AIShieldCore" -ErrorAction SilentlyContinue
if (-not $coreService) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $coreInstallScript -Action install
    if ($LASTEXITCODE -ne 0) { throw "Core orchestrator installation failed." }
} elseif ($coreService.Status -ne "Running") {
    Start-Service -Name "AIShieldCore"
}

New-Item -ItemType Directory -Force -Path $runtime | Out-Null
New-Item -ItemType Directory -Force -Path $quarantine | Out-Null
Remove-Item -LiteralPath $stdoutLog -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $stderrLog -Force -ErrorAction SilentlyContinue

$prototypeArguments = @("--listen", "localhost:$ListenPort")
if ($Mode -eq "Demo") {
    $prototypeArguments += "--demo"
} else {
    $prototypeArguments += @("--backend", "${BackendHost}:${BackendPort}")
}

$process = Start-Process -FilePath $prototype `
    -ArgumentList $prototypeArguments `
    -WorkingDirectory $repo `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Milliseconds 500
$started = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
if (-not $started) {
    $errorText = Get-Content -LiteralPath $stderrLog -Raw -ErrorAction SilentlyContinue
    throw "AI Shield gateway terminated during startup. $errorText"
}

Set-Content -LiteralPath $pidFile -Value $process.Id
Set-Content -LiteralPath $servicePidFile -Value $process.Id
if ($EnableEnforcement -and $Mode -ne "Backend") {
    Stop-Process -Id $process.Id
    throw "Transparent enforcement requires Backend mode."
}
$policyStateFile = Join-Path $env:ProgramData "AIShield\policy\state.json"
$policyState = Get-Content -LiteralPath $policyStateFile -Raw | ConvertFrom-Json
$policyVersion = [uint64]$policyState.security_version + 1
$policyInput = Join-Path $runtime "startup-policy.json"
$policyEnvelope = Join-Path $runtime "startup-policy.aipolicy"
$startupPolicy = [ordered]@{
    security_version = $policyVersion
    mode = $(if ($EnableEnforcement) { "enforce" } else { "audit" })
    block_inbound_port = 0
    redirect_outbound_port = $(if ($EnableEnforcement) { $BackendPort } else { 0 })
    proxy_port = $(if ($EnableEnforcement) { $ListenPort } else { 0 })
    block_quarantine_execution = $true
    block_user_temp_execution = $true
    block_download_execution = $false
    block_risky_script_command = $true
    block_office_child_process = $true
    system_network_guard = $true
    block_unsolicited_inbound = $false
    block_browser_non_web = $false
}
[IO.File]::WriteAllText($policyInput, ($startupPolicy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign -InputFile $policyInput -OutputFile $policyEnvelope
if ($LASTEXITCODE -eq 0) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $policyEnvelope
}
Remove-Item -LiteralPath $policyInput, $policyEnvelope -Force -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) {
    Stop-Process -Id $process.Id
    Remove-Item -LiteralPath $pidFile -Force
    throw "Signed policy activation failed; previous policy was restored and gateway stopped."
}
Write-Output "gateway running: PID $($process.Id)"
Write-Output "protected endpoints: http://127.0.0.1:$ListenPort/ and http://[::1]:$ListenPort/"
if ($Mode -eq "Backend") {
    Write-Output "forwarding to: http://${BackendHost}:${BackendPort}/"
} else {
    Write-Output "mode: integrated demonstration"
}
Write-Output "logs: $stdoutLog"
Write-Output "quarantine: $quarantine"
Write-Output "kernel mode: $(if ($EnableEnforcement) { 'enforce' } else { 'audit' })"
Write-Output "telemetry broker: running; audit: $env:ProgramData\AIShield\audit"
