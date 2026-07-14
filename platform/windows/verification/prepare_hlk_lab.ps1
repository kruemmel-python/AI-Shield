param(
    [string]$Controller = "",
    [string]$SubmissionDirectory = "",
    [switch]$RequireInstalledHlk
)

$ErrorActionPreference="Stop"
$repo=Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$resultDir=Join-Path $repo "runtime\verification"
$submission=if([string]::IsNullOrWhiteSpace($SubmissionDirectory)){Join-Path $repo "submission\microsoft"}
elseif([IO.Path]::IsPathRooted($SubmissionDirectory)){[IO.Path]::GetFullPath($SubmissionDirectory)}
else{[IO.Path]::GetFullPath((Join-Path $repo $SubmissionDirectory))}
$candidates=@(
    "C:\Program Files (x86)\Windows Kits\10\Hardware Lab Kit\Studio\HardwareLabConsole.exe",
    "C:\Program Files (x86)\Windows Kits\10\Hardware Lab Kit\Studio\HLKStudio.exe"
)
$studio=$candidates|Where-Object{Test-Path $_}|Select-Object -First 1
$deviceGuard=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
$required=@(
    "AIShieldDrivers-x64.cab",
    "ABI_MANIFEST.json",
    "SHA256SUMS.json",
    "packages\wfp\ai_shield_wfp.cat",
    "packages\minifilter\ai_shield_minifilter.cat",
    "packages\process_guard\ai_shield_process_guard.cat"
)
$missing=@($required|Where-Object{-not(Test-Path (Join-Path $submission $_))})
$blockers=[Collections.Generic.List[string]]::new()
if(-not $studio){$blockers.Add("Windows HLK Studio/Controller is not installed on this machine.")}
if($missing.Count){$blockers.Add("Submission artifacts missing: "+($missing-join ", "))}
if(-not(@($deviceGuard.SecurityServicesRunning)-contains 2)){$blockers.Add("HVCI/Memory Integrity is not running on the system under test.")}
if(-not $Controller){$blockers.Add("No HLK Controller endpoint was supplied.")}
$matrix=@(
    [ordered]@{package="wfp";driver="AIShieldWfp.sys";class="NetService";focus=@("applicable network filter tests","code integrity","driver verifier","reliability")},
    [ordered]@{package="minifilter";driver="AIShieldMiniFilter.sys";class="ActivityMonitor";focus=@("applicable file-system filter tests","code integrity","driver verifier","reliability")},
    [ordered]@{package="process_guard";driver="AIShieldProcessGuard.sys";class="System";focus=@("applicable kernel driver tests","code integrity","driver verifier","reliability")}
)
$result=[ordered]@{schema=1;created_utc=[DateTime]::UtcNow.ToString("o");controller=$Controller;
    hlk_studio=$studio;hvci_running=(@($deviceGuard.SecurityServicesRunning)-contains 2);
    submission_directory=$submission;missing_artifacts=$missing;driver_matrix=$matrix;
    ready=($blockers.Count-eq 0);blockers=@($blockers)}
$output=Join-Path $resultDir "HLK_READINESS.json"
New-Item -ItemType Directory -Force $resultDir|Out-Null
[IO.File]::WriteAllText($output,($result|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
$result|ConvertTo-Json -Depth 7
Write-Output "result=$output"
if($RequireInstalledHlk -and $blockers.Count){exit 3}
