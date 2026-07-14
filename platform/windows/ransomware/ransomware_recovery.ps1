param(
    [ValidateSet('status','initialize','snapshot','detect','incidents','restore-plan','restore','backup','verify-backup','contain','release-containment')]
    [string]$Action = 'status',
    [string[]]$ProtectedRoot = @(),
    [string]$VaultRoot = '',
    [string]$SnapshotId = '',
    [string]$IncidentId = '',
    [string]$BackupRoot = '',
    [uint32]$ProcessId = 0,
    [uint64]$MaximumVaultBytes = 10737418240,
    [uint64]$MaximumFileBytes = 536870912,
    [uint32]$ChangeThreshold = 40,
    [uint32]$DestructiveThreshold = 10,
    [switch]$ConfirmRestore,
    [switch]$ConfirmContainment
)

$ErrorActionPreference = 'Stop'
$schema = 'AIShieldRansomwareRecovery/1'
if ([string]::IsNullOrWhiteSpace($VaultRoot)) { $VaultRoot = Join-Path $env:ProgramData 'AIShield\recovery-vault' }
$VaultRoot = [IO.Path]::GetFullPath($VaultRoot)

function Get-DefaultRoots {
    $result = @()
    foreach ($name in @('Desktop','Documents','Pictures','Music','Videos')) {
        $path = Join-Path $env:USERPROFILE $name
        if (Test-Path -LiteralPath $path -PathType Container) { $result += [IO.Path]::GetFullPath($path) }
    }
    return @($result | Select-Object -Unique)
}
if ($ProtectedRoot.Count -eq 0) { $ProtectedRoot = Get-DefaultRoots }
$ProtectedRoot = @($ProtectedRoot | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') } | Select-Object -Unique)

$objects = Join-Path $VaultRoot 'objects'
$snapshots = Join-Path $VaultRoot 'snapshots'
$incidents = Join-Path $VaultRoot 'incidents'
$staging = Join-Path $VaultRoot 'restore-staging'
$conflicts = Join-Path $VaultRoot 'conflicts'
$statePath = Join-Path $VaultRoot 'state.json'
$containmentPath = Join-Path $VaultRoot 'containment.json'

function Write-AtomicJson([string]$Path, $Value) {
    $parent = Split-Path $Path -Parent
    New-Item -ItemType Directory -Force $parent | Out-Null
    $temporary = "$Path.$PID.tmp"
    [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Initialize-Vault([bool]$CreateCanaries = $true) {
    foreach ($path in @($VaultRoot,$objects,$snapshots,$incidents,$staging,$conflicts)) {
        New-Item -ItemType Directory -Force $path | Out-Null
    }
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        & icacls.exe $VaultRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Recovery-Vault ACL could not be applied.' }
    }
    if ($CreateCanaries) {
        foreach ($root in $ProtectedRoot) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            $canary = Join-Path $root '.ai-shield-recovery-canary.dat'
            if (-not (Test-Path -LiteralPath $canary)) {
                [IO.File]::WriteAllText($canary, "AI Shield recovery canary. Do not modify.`r`n", [Text.UTF8Encoding]::new($false))
                (Get-Item -LiteralPath $canary).Attributes = [IO.FileAttributes]::Hidden
            }
        }
    }
    if (-not (Test-Path -LiteralPath $statePath)) {
        Write-AtomicJson $statePath ([ordered]@{schema=$schema;latest_snapshot='';last_incident='';protected_roots=$ProtectedRoot;mode='audit';created_utc=[DateTime]::UtcNow.ToString('o')})
    }
}

function Get-EntropyMilli([string]$Path) {
    $counts = [uint32[]]::new(256)
    $total = 0
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $buffer = [byte[]]::new(65536)
        $read = $stream.Read($buffer, 0, $buffer.Length)
        for ($i = 0; $i -lt $read; $i++) { $counts[$buffer[$i]]++ }
        $total = $read
    } finally { $stream.Dispose() }
    if ($total -eq 0) { return 0 }
    $entropy = 0.0
    foreach ($count in $counts) {
        if ($count) {
            $probability = [double]$count / $total
            $entropy -= $probability * [Math]::Log($probability, 2)
        }
    }
    return [uint32][Math]::Round($entropy * 1000)
}

function Get-ProtectedFiles {
    foreach ($root in $ProtectedRoot) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $pending = [Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($root)
        while ($pending.Count -gt 0) {
            $directory = $pending.Dequeue()
            try {
                $entries = @([IO.Directory]::EnumerateFileSystemEntries($directory))
            } catch {
                continue
            }
            foreach ($path in $entries) {
                try {
                    $attributes = [IO.File]::GetAttributes($path)
                    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    if ($attributes -band [IO.FileAttributes]::Directory) {
                        $pending.Enqueue($path)
                        continue
                    }
                    $file = [IO.FileInfo]::new($path)
                    if ($file.Exists -and $file.Length -le $MaximumFileBytes) { Write-Output $file }
                } catch {
                    # Files can disappear or become inaccessible while a live system is snapshotted.
                    continue
                }
            }
        }
    }
}

function Get-VaultUsage {
    $sum = (Get-ChildItem -LiteralPath $objects -File -ErrorAction SilentlyContinue |
        Measure-Object Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [uint64]$sum
}

function Save-Object($File, [string]$Hash) {
    $target = Join-Path $objects ($Hash + '.bin')
    if (Test-Path -LiteralPath $target) { return $target }
    if ($null -eq $script:snapshotVaultUsage) { $script:snapshotVaultUsage = [uint64](Get-VaultUsage) }
    if ($File.Length -gt $MaximumVaultBytes -or $script:snapshotVaultUsage -gt $MaximumVaultBytes-$File.Length) { throw 'Recovery-Vault quota exceeded.' }
    $temporary = Join-Path $objects ($Hash + '.' + $PID + '.tmp')
    Copy-Item -LiteralPath $File.FullName -Destination $temporary -Force
    if ((Get-Sha256 $temporary) -ne $Hash -or (Get-Sha256 $File.FullName) -ne $Hash) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        throw "File changed while snapshot was captured: $($File.FullName)"
    }
    Move-Item -LiteralPath $temporary -Destination $target -Force
    $script:snapshotVaultUsage += [uint64]$File.Length
    return $target
}

function New-Snapshot {
    Initialize-Vault
    $id = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $script:snapshotVaultUsage = [uint64](Get-VaultUsage)
    $records = [Collections.Generic.List[object]]::new()
    $skipped = 0
    $skipReasons = [Collections.Generic.List[object]]::new()
    foreach ($file in Get-ProtectedFiles) {
        try {
            $hash = Get-Sha256 $file.FullName
            Save-Object $file $hash | Out-Null
            $records.Add([ordered]@{
                path = $file.FullName
                hash = $hash
                bytes = [uint64]$file.Length
                last_write_utc = $file.LastWriteTimeUtc.ToString('o')
                entropy_milli = Get-EntropyMilli $file.FullName
                canary = $file.Name -eq '.ai-shield-recovery-canary.dat'
            })
        } catch {
            $skipped++
            $skipReasons.Add([ordered]@{path=$file.FullName;reason=$_.Exception.Message})
        }
    }
    $manifest = [ordered]@{schema=$schema;kind='snapshot';snapshot_id=$id;created_utc=[DateTime]::UtcNow.ToString('o');protected_roots=$ProtectedRoot;records=$records.ToArray();skipped=$skipped;skip_reasons=$skipReasons.ToArray()}
    Write-AtomicJson (Join-Path $snapshots "$id.json") $manifest
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $state.latest_snapshot = $id
    $state.protected_roots = $ProtectedRoot
    Write-AtomicJson $statePath $state
    return $manifest
}

function Get-Snapshot([string]$Id) {
    if ([string]::IsNullOrWhiteSpace($Id)) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $Id = [string]$state.latest_snapshot
    }
    if ($Id -notmatch '^[0-9TZ]+$') { throw 'Invalid snapshot identifier.' }
    $path = Join-Path $snapshots "$Id.json"
    if (-not (Test-Path -LiteralPath $path)) { throw 'Snapshot not found.' }
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Find-Changes {
    $snapshot = Get-Snapshot $SnapshotId
    $baseline = @{}
    foreach ($record in $snapshot.records) { $baseline[[string]$record.path] = $record }
    $current = @{}
    $changed = @()
    $new = @()
    foreach ($file in @(Get-ProtectedFiles)) {
        $current[$file.FullName] = $true
        if (-not $baseline.ContainsKey($file.FullName)) {
            $new += [ordered]@{path=$file.FullName;bytes=[uint64]$file.Length}
            continue
        }
        $old = $baseline[$file.FullName]
        if ([uint64]$old.bytes -ne [uint64]$file.Length -or
            [DateTime]$old.last_write_utc -ne $file.LastWriteTimeUtc) {
            $hash = Get-Sha256 $file.FullName
            if ($hash -ne [string]$old.hash) {
                $entropy = Get-EntropyMilli $file.FullName
                $changed += [ordered]@{path=$file.FullName;before_hash=$old.hash;after_hash=$hash;before_entropy=[uint32]$old.entropy_milli;after_entropy=$entropy;canary=[bool]$old.canary}
            }
        }
    }
    $deleted = @()
    foreach ($path in $baseline.Keys) {
        if (-not $current.ContainsKey($path)) {
            $old = $baseline[$path]
            $deleted += [ordered]@{path=$path;before_hash=$old.hash;canary=[bool]$old.canary}
        }
    }
    return [pscustomobject]@{snapshot=$snapshot;changed=$changed;deleted=$deleted;new=$new}
}

function New-Incident {
    if (-not (Test-Path -LiteralPath $statePath)) {
        throw 'Recovery-Vault is not initialized. Create a baseline snapshot first.'
    }
    $delta = Find-Changes
    $entropy = @($delta.changed | Where-Object { [int]$_.after_entropy - [int]$_.before_entropy -ge 1200 }).Count
    $canary = @(($delta.changed + $delta.deleted) | Where-Object { $_.canary }).Count
    $destructive = $delta.deleted.Count
    $score = 0
    $reasons = @()
    if ($delta.changed.Count -ge $ChangeThreshold) { $score += 35; $reasons += 'change_burst' }
    if ($destructive -ge $DestructiveThreshold) { $score += 35; $reasons += 'delete_burst' }
    if ($entropy -ge 5) { $score += 25; $reasons += 'entropy_increase' }
    if ($canary) { $score = 100; $reasons += 'canary_modified' }
    $score = [Math]::Min(100, $score)
    if ($score -lt 50) { return [ordered]@{schema=$schema;kind='scan';state='normal';score=$score;changed=$delta.changed.Count;deleted=$delta.deleted.Count;new=$delta.new.Count} }
    $id = 'incident-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
    $state = $(if ($score -ge 80) { 'confirmed' } else { 'suspicious' })
    $incident=[ordered]@{schema=$schema;kind='incident';incident_id=$id;created_utc=[DateTime]::UtcNow.ToString('o');state=$state;score=$score;reasons=$reasons;snapshot_id=$delta.snapshot.snapshot_id;changed=$delta.changed;deleted=$delta.deleted;new=$delta.new;process_id=$ProcessId;containment='not_requested';restore_state='not_started'}
    Write-AtomicJson (Join-Path $incidents "$id.json") $incident
    $runtime = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $runtime.last_incident = $id
    Write-AtomicJson $statePath $runtime
    if ($ProcessId -ne 0 -and $ConfirmContainment) {
        Invoke-Containment $id $ProcessId
        $incident = Get-Content -LiteralPath (Join-Path $incidents "$id.json") -Raw | ConvertFrom-Json
    }
    return $incident
}

function Get-Incident([string]$Id) {
    if ($Id -notmatch '^incident-[0-9TZ]+$') { throw 'Invalid incident identifier.' }
    $path = Join-Path $incidents "$Id.json"
    if (-not (Test-Path -LiteralPath $path)) { throw 'Incident not found.' }
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Get-RestorePlan([string]$Id) {
    $incident = Get-Incident $Id
    $snapshot = Get-Snapshot $incident.snapshot_id
    $map = @{}
    foreach ($record in $snapshot.records) { $map[[string]$record.path] = $record }
    $items = @()
    $missing = @()
    foreach ($entry in @($incident.changed) + @($incident.deleted)) {
        if ($map.ContainsKey([string]$entry.path)) {
            $record = $map[[string]$entry.path]
            $object = Join-Path $objects ($record.hash + '.bin')
            if (Test-Path -LiteralPath $object) {
                $items += [ordered]@{path=$record.path;hash=$record.hash;bytes=$record.bytes;object=$object}
            } else { $missing += $entry.path }
        }
    }
    return [ordered]@{schema=$schema;kind='restore-plan';incident_id=$Id;snapshot_id=$incident.snapshot_id;items=$items;missing=$missing;requires_confirmation=$true}
}

function Test-ProtectedDestination([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    foreach ($root in $ProtectedRoot) {
        if ($full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $full.Equals($root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Invoke-Restore([string]$Id) {
    $plan = Get-RestorePlan $Id
    if (-not $ConfirmRestore) { return $plan }
    $stageRoot = Join-Path $staging $Id
    New-Item -ItemType Directory -Force $stageRoot | Out-Null
    $restored = 0
    foreach ($item in $plan.items) {
        if (-not (Test-ProtectedDestination $item.path)) { throw "Restore path escaped protected roots: $($item.path)" }
        if ((Get-Sha256 $item.object) -ne $item.hash) { throw "Vault object integrity failed: $($item.hash)" }
        $parent = [IO.Path]::GetDirectoryName([string]$item.path)
        New-Item -ItemType Directory -Force $parent | Out-Null
        $temporary = Join-Path $parent ('.ai-shield-restore-' + [guid]::NewGuid().ToString('N') + '.tmp')
        Copy-Item -LiteralPath $item.object -Destination $temporary -Force
        if ((Get-Sha256 $temporary) -ne $item.hash) { throw 'Restore staging integrity failed.' }
        if (Test-Path -LiteralPath $item.path) {
            $conflict = Join-Path $conflicts ($Id + '-' + [guid]::NewGuid().ToString('N') + '.bin')
            Move-Item -LiteralPath $item.path -Destination $conflict -Force
        }
        Move-Item -LiteralPath $temporary -Destination $item.path -Force
        $restored++
    }
    $path = Join-Path $incidents "$Id.json"
    $incident = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $incident.restore_state = 'completed'
    $incident | Add-Member -NotePropertyName restored_files -NotePropertyValue $restored -Force
    $incident | Add-Member -NotePropertyName restored_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    Write-AtomicJson $path $incident
    return [ordered]@{schema=$schema;kind='restore-result';incident_id=$Id;restored=$restored;missing=$plan.missing.Count}
}

function New-ExternalBackup([string]$Destination) {
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'BackupRoot is required.' }
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'Recovery-Vault is not initialized.' }
    $destinationRoot = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    if ($destinationRoot.StartsWith($VaultRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $VaultRoot.StartsWith($destinationRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'External backup must not be placed inside or above the local Recovery-Vault.'
    }
    foreach ($root in $ProtectedRoot) {
        if ($destinationRoot.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'External backup must not be placed inside a protected user-data root.'
        }
    }
    $backupId = 'AIShield-Recovery-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $target = Join-Path $destinationRoot $backupId
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    foreach ($child in Get-ChildItem -LiteralPath $VaultRoot -Force) {
        Copy-Item -LiteralPath $child.FullName -Destination $target -Recurse -Force
    }
    $files = @(Get-ChildItem -LiteralPath $target -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($target.Length + 1).Replace('\', '/')
            bytes = [uint64]$_.Length
            sha256 = Get-Sha256 $_.FullName
        }
    })
    $manifest = [ordered]@{schema='AIShieldRecoveryBackup/1';created_utc=[DateTime]::UtcNow.ToString('o');source_vault=$VaultRoot;files=$files}
    Write-AtomicJson (Join-Path $target 'backup-manifest.json') $manifest
    [uint64]$backupBytes = 0
    foreach ($file in $files) { $backupBytes += [uint64]$file.bytes }
    return [ordered]@{schema=$schema;kind='backup';backup_root=$target;files=$files.Count;bytes=$backupBytes}
}

function Test-ExternalBackup([string]$Destination) {
    if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'BackupRoot is required.' }
    $target = [IO.Path]::GetFullPath($Destination)
    $manifestPath = Join-Path $target 'backup-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Backup manifest not found.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 'AIShieldRecoveryBackup/1') { throw 'Unknown backup manifest schema.' }
    $failed = @()
    foreach ($file in $manifest.files) {
        $candidate = [IO.Path]::GetFullPath((Join-Path $target ([string]$file.path).Replace('/', '\')))
        if (-not $candidate.StartsWith($target.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $candidate) -or
            (Get-Sha256 $candidate) -ne [string]$file.sha256) {
            $failed += [string]$file.path
        }
    }
    return [ordered]@{schema=$schema;kind='backup-verification';valid=$failed.Count -eq 0;checked=@($manifest.files).Count;failed=$failed}
}

function Add-NativeContainment {
    if(-not('AIShield.NativeContainment'-as[type])){Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace AIShield { public static class NativeContainment {
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr handle);
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr handle);
} }
'@}}

function Invoke-Containment([string]$Id,[uint32]$TargetPid) {
    if (-not $ConfirmContainment) { throw 'Containment requires -ConfirmContainment.' }
    if ($TargetPid -in @(0, 4, $PID)) { throw 'Refusing to contain a system or AI Shield control process.' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid"
    if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath)) { throw 'Process executable could not be resolved.' }
    $image = [IO.Path]::GetFullPath([string]$process.ExecutablePath)
    foreach ($blocked in @($env:windir, (Join-Path $env:ProgramFiles 'AI_Shield_Private_Desktop'), (Join-Path $env:ProgramFiles 'AIShield'))) {
        if ($blocked -and $image.StartsWith($blocked, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to suspend Windows or AI Shield binaries.' }
    }
    Add-NativeContainment
    $handle = [AIShield.NativeContainment]::OpenProcess(0x0800, $false, $TargetPid)
    if ($handle -eq [IntPtr]::Zero) { throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    try {
        $status = [AIShield.NativeContainment]::NtSuspendProcess($handle)
        if ($status -ne 0) { throw "NtSuspendProcess failed: $status" }
    } finally { [AIShield.NativeContainment]::CloseHandle($handle) | Out-Null }
    $rule = 'AIShield-Ransomware-' + $Id
    New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Program $image -Profile Any | Out-Null
    Write-AtomicJson $containmentPath ([ordered]@{schema=$schema;incident_id=$Id;process_id=$TargetPid;image=$image;rule=$rule;created_utc=[DateTime]::UtcNow.ToString('o')})
    $path = Join-Path $incidents "$Id.json"
    $incident = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $incident.containment = 'active'
    Write-AtomicJson $path $incident
}

function Release-Containment {
    if (-not (Test-Path -LiteralPath $containmentPath)) { return }
    $state = Get-Content -LiteralPath $containmentPath -Raw | ConvertFrom-Json
    Add-NativeContainment
    $handle = [AIShield.NativeContainment]::OpenProcess(0x0800, $false, [uint32]$state.process_id)
    if ($handle -ne [IntPtr]::Zero) {
        try { [AIShield.NativeContainment]::NtResumeProcess($handle) | Out-Null }
        finally { [AIShield.NativeContainment]::CloseHandle($handle) | Out-Null }
    }
    Remove-NetFirewallRule -DisplayName $state.rule -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $containmentPath -Force
}

switch ($Action) {
    'initialize' { Initialize-Vault; New-Snapshot | ConvertTo-Json -Depth 5 }
    'snapshot' { New-Snapshot | ConvertTo-Json -Depth 5 }
    'detect' { New-Incident | ConvertTo-Json -Depth 12 }
    'incidents' {
        Initialize-Vault $false
        @(Get-ChildItem -LiteralPath $incidents -Filter 'incident-*.json' -File |
            Sort-Object LastWriteTime -Descending |
            ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json }) | ConvertTo-Json -Depth 8
    }
    'restore-plan' { Get-RestorePlan $IncidentId | ConvertTo-Json -Depth 8 }
    'restore' { Invoke-Restore $IncidentId | ConvertTo-Json -Depth 8 }
    'backup' { New-ExternalBackup $BackupRoot | ConvertTo-Json -Depth 5 }
    'verify-backup' { Test-ExternalBackup $BackupRoot | ConvertTo-Json -Depth 5 }
    'contain' { Invoke-Containment $IncidentId $ProcessId; Get-Content -LiteralPath $containmentPath -Raw }
    'release-containment' { Release-Containment; '{"released":true}' }
    'status' {
        Initialize-Vault $false
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        [ordered]@{schema=$schema;mode=$state.mode;latest_snapshot=$state.latest_snapshot;last_incident=$state.last_incident;vault_bytes=Get-VaultUsage;maximum_vault_bytes=$MaximumVaultBytes;protected_roots=$state.protected_roots;containment_active=Test-Path -LiteralPath $containmentPath} | ConvertTo-Json -Depth 5
    }
}
