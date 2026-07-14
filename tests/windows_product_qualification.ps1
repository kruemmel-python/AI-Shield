param(
    [ValidateSet("quick", "soak", "recovery", "install", "reboot-resume")]
    [string]$Suite = "quick",
    [ValidateRange(1, 1440)]
    [int]$DurationMinutes = 1,
    [ValidateRange(1, 64)]
    [int]$Concurrency = 4,
    [switch]$ArmReboot,
    [switch]$ConfirmInstallCycle
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$resultsDir = Join-Path $repo "runtime\qualification"
$runId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $resultsDir $runId
$resultFile = Join-Path $runDir "result.json"
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$diag = Join-Path $repo "build_vs\Release\ai_shield_diag.exe"
$policy = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$installer = Join-Path $repo "platform\windows\installer\update_and_install_drivers.ps1"
$uninstaller = Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1"
$processRuleTest = Join-Path $repo "tests\windows_process_guard_rules.ps1"
$resumeState = Join-Path $env:ProgramData "AIShield\qualification-reboot.json"
$resumeTask = "AIShieldQualificationResume"
$checks = [Collections.Generic.List[object]]::new()

New-Item -ItemType Directory -Force -Path $runDir | Out-Null

function Add-Check([string]$Name, [bool]$Passed, [string]$Evidence) {
    $checks.Add([ordered]@{ name=$Name; passed=$Passed; evidence=$Evidence })
    Write-Output "[$(if ($Passed) { 'PASS' } else { 'FAIL' })] $Name - $Evidence"
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DriverHealth {
    $text = (& $driverctl status 2>&1) -join "`n"
    return [ordered]@{ passed=($LASTEXITCODE -eq 0 -and ([regex]::Matches($text,"state=4 win32_exit=0")).Count -eq 3); text=$text }
}

function Get-KernelHealth {
    $text = (& $kernelctl status 2>&1) -join "`n"
    $dropped = [regex]::Matches($text,"telemetry_dropped=(\d+)") | ForEach-Object { [uint64]$_.Groups[1].Value }
    return [ordered]@{ passed=($LASTEXITCODE -eq 0 -and $dropped.Count -eq 3); text=$text; dropped=[uint64](($dropped | Measure-Object -Sum).Sum) }
}

function Invoke-HttpCorpus([int]$Workers, [int]$Minutes) {
    $deadline = [DateTime]::UtcNow.AddMinutes($Minutes)
    $jobs = @()
    for ($worker = 0; $worker -lt $Workers; $worker++) {
        $jobs += Start-Job -ArgumentList $deadline,$worker -ScriptBlock {
            param($Deadline,$Worker)
            $allowed=0;$blocked=0;$failed=0
            $paths=@("/","/safe","/health","/%2e%2e/%2e%2e/secret","/..%2f..%2fsecret","/../../secret")
            while ([DateTime]::UtcNow -lt $Deadline) {
                foreach ($path in $paths) {
                    $body = & curl.exe -g -s --max-time 5 --path-as-is "http://127.0.0.1:18081$path"
                    if ($LASTEXITCODE -ne 0) { $failed++ }
                    elseif (($body -join "`n") -match "request_not_processed") { $blocked++ }
                    else { $allowed++ }
                }
            }
            [pscustomobject]@{worker=$Worker;allowed=$allowed;blocked=$blocked;failed=$failed}
        }
    }
    $rows = $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job -Force
    return [ordered]@{
        allowed=[uint64](($rows.allowed | Measure-Object -Sum).Sum)
        blocked=[uint64](($rows.blocked | Measure-Object -Sum).Sum)
        failed=[uint64](($rows.failed | Measure-Object -Sum).Sum)
    }
}

function Test-AuditSegments {
    $script = @"
`$bad=0;`$count=0
Get-ChildItem 'C:\ProgramData\AIShield\audit' -Filter *.bin | Sort-Object LastWriteTime | Select-Object -Last 20 | ForEach-Object {
  & '$diag' audit-verify `$_.FullName | Out-Null
  `$count++
  if (`$LASTEXITCODE -ne 0) { `$bad++ }
}
Write-Output "count=`$count bad=`$bad"
if (`$count -eq 0 -or `$bad -ne 0) { exit 2 }
"@
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $script 2>&1
    return [ordered]@{ passed=($LASTEXITCODE -eq 0); text=($output -join " ") }
}

function Invoke-RecoveryDrill {
    $before = Get-Service AIShieldBroker
    Stop-Service AIShieldBroker -Force
    Start-Service AIShieldBroker
    Start-Sleep -Seconds 2
    $after = Get-Service AIShieldBroker
    $policyText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policy -Action status 2>&1) -join "`n"
    $passed = $before.Status -eq "Running" -and $after.Status -eq "Running" -and
        $LASTEXITCODE -eq 0 -and $policyText -match "signature=valid" -and $policyText -match "recovery_required=False"
    Add-Check "broker-policy-recovery" $passed ($policyText -replace "`r?`n","; ")
}

function Invoke-ProvenanceDrill {
    $source=Join-Path $env:USERPROFILE "Downloads\ai-shield-$runId.cmd"
    $restored=Join-Path $runDir "restored-provenance-test.cmd"
    Set-Content -LiteralPath $source -Value "@echo provenance-test"
    Set-Content -LiteralPath ($source+":Zone.Identifier") -Value "[ZoneTransfer]`r`nZoneId=3"
    Start-Sleep -Seconds 7
    $moved=-not (Test-Path -LiteralPath $source)
    $record=Get-Content "C:\ProgramData\AIShield\quarantine\journal.jsonl" | ForEach-Object { $_|ConvertFrom-Json } |
        Where-Object { $_.source -eq $source -and $_.state -eq "committed" } | Select-Object -Last 1
    $restoredOk=$false
    if($record){
        & (Join-Path $repo "build_vs\Release\ai_shield_broker.exe") quarantine-restore $record.id $restored
        $restoredOk=$LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $restored)
    }
    Add-Check "automatic-provenance-quarantine" ($moved -and $restoredOk) "moved=$moved restored=$restoredOk id=$($record.id)"
}

function Complete-Run {
    $failed = @($checks | Where-Object { -not $_.passed }).Count
    $result = [ordered]@{ schema=1; run_id=$runId; suite=$Suite; started_utc=$runId;
        completed_utc=[DateTime]::UtcNow.ToString("o"); passed=($failed -eq 0); checks=$checks }
    [IO.File]::WriteAllText($resultFile,($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    Write-Output "result=$resultFile"
    if ($failed -ne 0) { exit 2 }
}

if (-not (Test-Administrator)) { throw "Run product qualification from an elevated PowerShell." }

if ($Suite -eq "install") {
    if (-not $ConfirmInstallCycle) { throw "Install qualification requires -ConfirmInstallCycle." }
    Stop-Service AIShieldBroker -Force -ErrorAction SilentlyContinue
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstaller
    Add-Check "driver-uninstall" ($LASTEXITCODE -eq 0) "uninstaller exit=$LASTEXITCODE"
    $removedText=(& $driverctl status 2>&1)-join "`n"
    Add-Check "services-removed" (([regex]::Matches($removedText,"not installed")).Count -eq 3) ($removedText -replace "`r?`n","; ")
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -Configuration Release
    Add-Check "driver-update-install" ($LASTEXITCODE -eq 0) "update installer exit=$LASTEXITCODE"
    $health=Get-DriverHealth;Add-Check "driver-services" $health.passed ($health.text -replace "`r?`n","; ")
    Add-Check "broker-service" ((Get-Service AIShieldBroker).Status -eq "Running") "service queried after install"
    Complete-Run
    exit 0
}

if ($Suite -eq "reboot-resume") {
    if (-not (Test-Path $resumeState)) { throw "Reboot qualification state is missing." }
    $state=Get-Content $resumeState -Raw|ConvertFrom-Json
    $health=Get-DriverHealth;Add-Check "drivers-after-reboot" $health.passed ($health.text -replace "`r?`n","; ")
    Add-Check "broker-after-reboot" ((Get-Service AIShieldBroker).Status -eq "Running") "boot_id=$($state.boot_id)"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policy -Action recover | Out-Null
    Add-Check "policy-recovery-after-reboot" ($LASTEXITCODE -eq 0) "recover exit=$LASTEXITCODE"
    Remove-Item $resumeState -Force
    Unregister-ScheduledTask -TaskName $resumeTask -Confirm:$false -ErrorAction SilentlyContinue
    Complete-Run
    exit 0
}

$driverHealth=Get-DriverHealth;Add-Check "driver-services" $driverHealth.passed ($driverHealth.text -replace "`r?`n","; ")
Add-Check "broker-service" ((Get-Service AIShieldBroker).Status -eq "Running") "LocalSystem broker running"
$kernelBefore=Get-KernelHealth
$load=Invoke-HttpCorpus $Concurrency $DurationMinutes
Add-Check "http-load" ($load.allowed -gt 0 -and $load.blocked -gt 0 -and $load.failed -eq 0) (($load|ConvertTo-Json -Compress))
$kernelHealth=Get-KernelHealth
Add-Check "kernel-health" $kernelHealth.passed ($kernelHealth.text -replace "`r?`n","; ")
$droppedDelta=$kernelHealth.dropped-$kernelBefore.dropped
Add-Check "telemetry-loss" ($droppedDelta -eq 0) "before=$($kernelBefore.dropped) after=$($kernelHealth.dropped) delta=$droppedDelta"
$audit=Test-AuditSegments;Add-Check "audit-integrity" $audit.passed $audit.text
$deviceGuard=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
Add-Check "hvci-runtime" (@($deviceGuard.SecurityServicesRunning) -contains 2) "services_running=$(@($deviceGuard.SecurityServicesRunning)-join ',')"

if ($Suite -in @("recovery","soak")) {
    Invoke-RecoveryDrill
    & powershell.exe -ExecutionPolicy Bypass -File $processRuleTest | Out-Null
    Add-Check "process-guard-rules" ($LASTEXITCODE -eq 0) "rule test exit=$LASTEXITCODE"
    Invoke-ProvenanceDrill
}

if ($ArmReboot) {
    $state=[ordered]@{schema=1;boot_id=$runId;armed_utc=[DateTime]::UtcNow.ToString("o")}
    [IO.File]::WriteAllText($resumeState,($state|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Suite reboot-resume"
    $trigger=New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $resumeTask -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
    Add-Check "reboot-resume-armed" $true "scheduled task=$resumeTask; reboot was not initiated"
}

Complete-Run
