param(
    [ValidateSet("health", "runtime-status", "rotate-key", "safe-mode-reset", "quarantine-release",
                 "audit-export", "recover", "ransomware-status", "ransomware-snapshot",
                 "ransomware-detect", "ransomware-incidents", "ransomware-restore-plan",
                 "ransomware-restore", "ransomware-contain", "ransomware-release-containment")]
    [string]$Action,
    [string]$ObjectId,
    [string]$Destination,
    [string]$Reason,
    [string]$OutputDirectory,
    [string]$IncidentId,
    [uint32]$ProcessId = 0,
    [switch]$ConfirmRestore,
    [switch]$ConfirmContainment
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$policy = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$ransomware = Join-Path $repo "platform\windows\ransomware\ransomware_recovery.ps1"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Action -eq "health") {
    $health = Join-Path $env:ProgramData "AIShield\health.json"
    if (-not (Test-Path -LiteralPath $health)) { throw "Core health state is unavailable." }
    Get-Content -LiteralPath $health -Raw | ConvertFrom-Json | Format-List
    Get-Service AIShieldCore, AIShieldBroker, AIShieldWfp, AIShieldMiniFilter, AIShieldProcessGuard |
        Select-Object Name, Status, StartType
    exit 0
}
if (-not $isAdmin) { throw "This administrative action requires an elevated PowerShell." }
switch ($Action) {
    "runtime-status" { & $broker runtime-status; exit $LASTEXITCODE }
    "rotate-key" {
        & $broker runtime-rotate-key
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Restart-Service AIShieldBroker -Force
        exit 0
    }
    "safe-mode-reset" { & sc.exe control AIShieldCore 128; exit $LASTEXITCODE }
    "quarantine-release" {
        if ($ObjectId -notmatch '^[A-Fa-f0-9]{64}$' -or -not $Destination -or $Reason.Length -lt 3) {
            throw "ObjectId, Destination and a reason of at least three characters are required."
        }
        & $broker quarantine-restore $ObjectId $Destination $Reason
        exit $LASTEXITCODE
    }
    "audit-export" {
        if (-not $OutputDirectory) { throw "OutputDirectory is required." }
        $source = Join-Path $env:ProgramData "AIShield\audit"
        $target = Join-Path $OutputDirectory ("AIShield-Audit-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ"))
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Get-ChildItem -LiteralPath $source -File | Copy-Item -Destination $target
        Get-ChildItem -LiteralPath $target -File | ForEach-Object {
            $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            [pscustomobject]@{ file = $_.Name; sha256 = $hash.Hash }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target "manifest.json") -Encoding UTF8
        Write-Output $target
        exit 0
    }
    "ransomware-status" { & $ransomware -Action status; exit 0 }
    "ransomware-snapshot" { & $ransomware -Action snapshot; exit 0 }
    "ransomware-detect" { & $ransomware -Action detect -ProcessId $ProcessId -ConfirmContainment:$ConfirmContainment; exit 0 }
    "ransomware-incidents" { & $ransomware -Action incidents; exit 0 }
    "ransomware-restore-plan" {
        if (-not $IncidentId) { throw "IncidentId is required." }
        & $ransomware -Action restore-plan -IncidentId $IncidentId
        exit 0
    }
    "ransomware-restore" {
        if (-not $IncidentId -or -not $ConfirmRestore) { throw "IncidentId and -ConfirmRestore are required." }
        & $ransomware -Action restore -IncidentId $IncidentId -ConfirmRestore
        exit 0
    }
    "ransomware-contain" {
        if (-not $IncidentId -or $ProcessId -eq 0 -or -not $ConfirmContainment) { throw "IncidentId, ProcessId and -ConfirmContainment are required." }
        & $ransomware -Action contain -IncidentId $IncidentId -ProcessId $ProcessId -ConfirmContainment
        exit 0
    }
    "ransomware-release-containment" { & $ransomware -Action release-containment; exit 0 }
    "recover" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policy -Action recover
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Restart-Service AIShieldBroker -Force
        Restart-Service AIShieldCore -Force
        exit 0
    }
}
