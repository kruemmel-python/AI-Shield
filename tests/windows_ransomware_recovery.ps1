param([string]$RepositoryRoot = '')
$ErrorActionPreference = 'Stop'
$repo = if ($RepositoryRoot) { [IO.Path]::GetFullPath($RepositoryRoot) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
$run = Join-Path $repo ('runtime\ransomware-test-' + [guid]::NewGuid().ToString('N'))
$protected = Join-Path $run 'protected'
$vault = Join-Path $run 'vault'
New-Item -ItemType Directory -Force $protected | Out-Null
$file = Join-Path $protected 'important.txt'
[IO.File]::WriteAllText($file, 'known-good', [Text.UTF8Encoding]::new($false))
$brokenJunction = Join-Path $protected 'broken-junction'
& cmd.exe /d /c "mklink /J `"$brokenJunction`" `"$(Join-Path $run 'missing-target')`"" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Broken junction test fixture could not be created.' }
$script = Join-Path $repo 'platform\windows\ransomware\ransomware_recovery.ps1'
try {
    $snapshot = & $script -Action initialize -ProtectedRoot $protected -VaultRoot $vault -MaximumVaultBytes 10485760 | ConvertFrom-Json
    if (-not $snapshot.snapshot_id) { throw 'Snapshot was not created.' }
    [IO.File]::WriteAllText($file, ('encrypted-' + 'x' * 4096), [Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath (Join-Path $protected '.ai-shield-recovery-canary.dat') -Force
    $incident = & $script -Action detect -ProtectedRoot $protected -VaultRoot $vault -ChangeThreshold 1 -DestructiveThreshold 1 | ConvertFrom-Json
    if ($incident.state -ne 'confirmed' -or -not $incident.incident_id) {
        throw "Canary incident was not confirmed: snapshot=$($snapshot | ConvertTo-Json -Compress) incident=$($incident | ConvertTo-Json -Compress)"
    }
    $plan = & $script -Action restore-plan -ProtectedRoot $protected -VaultRoot $vault -IncidentId $incident.incident_id | ConvertFrom-Json
    if ($plan.items.Count -lt 1 -or -not $plan.requires_confirmation) { throw 'Restore plan is incomplete.' }
    & $script -Action restore -ProtectedRoot $protected -VaultRoot $vault -IncidentId $incident.incident_id -ConfirmRestore | Out-Null
    if ((Get-Content -LiteralPath $file -Raw) -ne 'known-good') { throw 'Restored content does not match baseline.' }
    $external = Join-Path $run 'external'
    New-Item -ItemType Directory -Force $external | Out-Null
    $backup = & $script -Action backup -ProtectedRoot $protected -VaultRoot $vault -BackupRoot $external | ConvertFrom-Json
    $verification = & $script -Action verify-backup -ProtectedRoot $protected -VaultRoot $vault -BackupRoot $backup.backup_root | ConvertFrom-Json
    if (-not $verification.valid -or $verification.checked -lt 1) { throw 'External recovery backup verification failed.' }
    Write-Output 'ransomware_recovery_snapshot=true'
    Write-Output 'ransomware_recovery_detection=true'
    Write-Output 'ransomware_recovery_restore=true'
    Write-Output 'ransomware_recovery_external_backup=true'
    Write-Output 'ransomware_recovery_reparse_guard=true'
} finally {
    $full = [IO.Path]::GetFullPath($run)
    $runtime = [IO.Path]::GetFullPath((Join-Path $repo 'runtime')).TrimEnd('\') + '\'
    if ($full.StartsWith($runtime, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $full)) {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}
