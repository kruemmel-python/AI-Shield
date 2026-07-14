param(
    [ValidateSet("inspect", "apply-audit", "rollback")]
    [string]$Action = "inspect",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$stateRoot = Join-Path $env:ProgramData "AIShield\hardening"
$backupPath = Join-Path $stateRoot "defender-audit-backup.json"
$recommendedAsr = @(
    "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b"
)

function Get-DefenderSnapshot {
    $preference = Get-MpPreference -ErrorAction Stop
    $rules = [ordered]@{}
    $ids = @($preference.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
    $actions = @($preference.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    for ($i=0; $i -lt $ids.Count -and $i -lt $actions.Count; $i++) {
        $rules[[string]$ids[$i].ToLowerInvariant()] = [int]$actions[$i]
    }
    return [ordered]@{
        network_protection = [int]$preference.EnableNetworkProtection
        controlled_folder_access = [int]$preference.EnableControlledFolderAccess
        pua_protection = [int]$preference.PUAProtection
        cloud_block_level = [int]$preference.CloudBlockLevel
        sample_submission = [int]$preference.SubmitSamplesConsent
        asr_rules = $rules
    }
}

if ($Action -eq "inspect") {
    Get-DefenderSnapshot | ConvertTo-Json -Depth 5
    exit 0
}
if (-not $isAdmin) { throw "This action requires an elevated PowerShell." }
if (-not $ConfirmSystemChange) {
    throw "Use -ConfirmSystemChange after reviewing the audit-only changes and rollback procedure."
}

New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
& icacls.exe $stateRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure hardening state directory." }

if ($Action -eq "apply-audit") {
    if (Test-Path -LiteralPath $backupPath) {
        throw "An audit-baseline transaction already exists. Roll it back before applying another one."
    }
    $before = Get-DefenderSnapshot
    $added = @($recommendedAsr | Where-Object { -not $before.asr_rules.Contains($_) })
    [ordered]@{ schema="AIShieldDefenderAuditBackup/1"; created_utc=[DateTime]::UtcNow.ToString('o');
        before=$before; added_asr_rules=$added } | ConvertTo-Json -Depth 7 |
        Set-Content -LiteralPath $backupPath -Encoding UTF8
    foreach ($id in $added) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 2
    }
    if ([int]$before.network_protection -eq 0) { Set-MpPreference -EnableNetworkProtection 2 }
    if ([int]$before.controlled_folder_access -eq 0) { Set-MpPreference -EnableControlledFolderAccess 2 }
    if ([int]$before.pua_protection -eq 0) { Set-MpPreference -PUAProtection 2 }
    $after = Get-DefenderSnapshot
    [ordered]@{ action="audit-baseline-applied"; backup=$backupPath; state=$after } | ConvertTo-Json -Depth 6
    exit 0
}

if (-not (Test-Path -LiteralPath $backupPath)) { throw "No Defender audit-baseline backup exists." }
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
if ($backup.schema -ne "AIShieldDefenderAuditBackup/1") { throw "Defender backup schema is invalid." }
$addedRules = @($backup.added_asr_rules | Where-Object { $null -ne $_ })
if ($addedRules.Count -gt 0) {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids $addedRules
}
Set-MpPreference -EnableNetworkProtection ([int]$backup.before.network_protection)
Set-MpPreference -EnableControlledFolderAccess ([int]$backup.before.controlled_folder_access)
Set-MpPreference -PUAProtection ([int]$backup.before.pua_protection)
$rolledBack = Get-DefenderSnapshot
Remove-Item -LiteralPath $backupPath -Force
[ordered]@{ action="audit-baseline-rolled-back"; state=$rolledBack } | ConvertTo-Json -Depth 6
