param([switch]$StrictBrowser, [switch]$BlockUnsolicitedInbound, [switch]$HardenDownloads,
    [switch]$HardenKernelHardware)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = @("-NoProfile","-ExecutionPolicy","Bypass","-File",('"'+$PSCommandPath+'"'))
    if ($StrictBrowser) { $arguments += "-StrictBrowser" }
    if ($BlockUnsolicitedInbound) { $arguments += "-BlockUnsolicitedInbound" }
    if ($HardenDownloads) { $arguments += "-HardenDownloads" }
    if ($HardenKernelHardware) { $arguments += "-HardenKernelHardware" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$postureScript = Join-Path $repo "platform\windows\security\system_security_posture.ps1"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $postureScript
if ($LASTEXITCODE -ne 0) { throw "Windows security posture collection failed." }
if ($HardenKernelHardware) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\security\kernel_hardware_hardening.ps1") `
        -Action apply -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Kernel and hardware hardening failed." }
}
& $driverctl start
if ($LASTEXITCODE -ne 0) { throw "Kernel sensors failed to start." }
Start-Service AIShieldBroker -ErrorAction SilentlyContinue
Start-Service AIShieldCore -ErrorAction SilentlyContinue
$state = Get-Content (Join-Path $env:ProgramData "AIShield\policy\state.json") -Raw | ConvertFrom-Json
$input = Join-Path $repo "runtime\system-protection-policy.json"
$envelope = Join-Path $repo "runtime\system-protection-policy.aipolicy"
[ordered]@{ security_version = [uint64]$state.security_version + 1; mode = "enforce";
    block_inbound_port = 0; redirect_outbound_port = 0; proxy_port = 0;
    block_quarantine_execution = $true; block_user_temp_execution = $true;
    block_download_execution = [bool]$HardenDownloads; block_risky_script_command = $true;
    block_office_child_process = $true; system_network_guard = $true;
    block_unsolicited_inbound = [bool]$BlockUnsolicitedInbound;
    block_browser_non_web = [bool]$StrictBrowser } | ConvertTo-Json -Compress |
    Set-Content -LiteralPath $input -Encoding UTF8
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign -InputFile $input -OutputFile $envelope
if ($LASTEXITCODE -ne 0) { throw "System protection policy signing failed." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $envelope
Remove-Item $input,$envelope -Force -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) { throw "System protection policy activation failed." }
Write-Output "AI Shield system protection active"
Write-Output "dual-stack telemetry: all ALE connect/accept flows"
Write-Output "worm egress guard: active"
Write-Output "strict browser ports: $([bool]$StrictBrowser)"
Write-Output "block unsolicited inbound: $([bool]$BlockUnsolicitedInbound)"
Write-Output "block direct download execution: $([bool]$HardenDownloads)"
Write-Output "kernel and hardware mitigation baseline: $([bool]$HardenKernelHardware)"
