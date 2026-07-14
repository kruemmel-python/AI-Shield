param(
    [ValidateSet("inspect", "runtime-corruption", "policy-corruption", "partial-update", "service-account")]
    [string]$Action = "inspect",
    [switch]$ConfirmDisruptive
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$policy = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$reportDir = Join-Path $env:ProgramData "AIShield\qualification"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$report = [ordered]@{ action = $Action; started_utc = [DateTime]::UtcNow.ToString("o"); passed = $false; observations = @() }

if ($Action -ne "inspect" -and -not $ConfirmDisruptive) {
    throw "Disruptive recovery drills require -ConfirmDisruptive on an isolated test system."
}
if ($Action -eq "inspect") {
    $report.observations += (& $broker runtime-status 2>&1) -join "`n"
    $report.observations += (Get-Service AIShieldCore,AIShieldBroker,AIShieldWfp,AIShieldMiniFilter,AIShieldProcessGuard |
        Select-Object Name,Status,StartType | ConvertTo-Json -Compress)
    $report.passed = $true
}
if ($Action -eq "runtime-corruption") {
    $primary = Join-Path $env:ProgramData "AIShield\runtime-state.dpapi"
    $backup = "$primary.drill-backup"
    Copy-Item $primary $backup -Force
    try {
        [IO.File]::WriteAllText($primary, "corrupt")
        & $broker runtime-status
        $report.passed = $LASTEXITCODE -eq 0
    } finally {
        if (-not $report.passed) { Move-Item $backup $primary -Force } else { Remove-Item $backup -Force }
    }
}
if ($Action -eq "policy-corruption") {
    $current = Join-Path $env:ProgramData "AIShield\policy\current.aipolicy"
    $backup = "$current.drill-backup"
    Copy-Item $current $backup -Force
    try {
        [IO.File]::WriteAllText($current, "corrupt")
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policy -Action recover
        $report.passed = $LASTEXITCODE -eq 0
    } finally {
        if (-not $report.passed) { Move-Item $backup $current -Force } else { Remove-Item $backup -Force }
    }
}
if ($Action -eq "partial-update") {
    $transaction = Join-Path $env:ProgramData "AIShield\update-transaction.json"
    $brokerService = Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
    $coreService = Get-CimInstance Win32_Service -Filter "Name='AIShieldCore'"
    $brokerPath = ([string]$brokerService.PathName).Trim('"')
    $corePath = ([string]$coreService.PathName).Trim('"')
    [ordered]@{ format = "AIShieldUpdateTransaction/2"; state = "activating"; previous_slot = "base";
        staged_slot = "a"; security_version = [uint64]999999;
        previous_broker_path = $brokerPath; previous_core_path = $corePath } | ConvertTo-Json -Compress |
        Set-Content -LiteralPath $transaction -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\recover_pending_update.ps1")
    $recoveredBroker = Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
    $recoveredCore = Get-CimInstance Win32_Service -Filter "Name='AIShieldCore'"
    $report.passed = $LASTEXITCODE -eq 0 -and -not (Test-Path $transaction) -and
        $recoveredBroker.State -eq "Running" -and $recoveredCore.State -eq "Running" -and
        ([string]$recoveredBroker.PathName).Trim('"') -eq $brokerPath -and
        ([string]$recoveredCore.PathName).Trim('"') -eq $corePath
    $report.observations += "broker=$($recoveredBroker.PathName);core=$($recoveredCore.PathName)"
}
if ($Action -eq "service-account") {
    $services = Get-CimInstance Win32_Service | Where-Object Name -in @("AIShieldCore", "AIShieldBroker")
    $report.passed = @($services | Where-Object StartName -eq "LocalSystem").Count -eq 2
    $report.observations += ($services | Select-Object Name,StartName,State | ConvertTo-Json -Compress)
}
$report.completed_utc = [DateTime]::UtcNow.ToString("o")
$path = Join-Path $reportDir ("recovery-" + $Action + "-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ") + ".json")
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
if (-not $report.passed) { throw "Recovery drill failed. Report: $path" }
Write-Output "Recovery drill passed: $path"
