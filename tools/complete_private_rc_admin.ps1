param(
    [ValidateRange(5,3600)][int]$QualificationSeconds = 60,
    [switch]$ConfirmInstallCycle
)

$ErrorActionPreference="Stop"
$repo=Resolve-Path (Join-Path $PSScriptRoot "..")
$root=Join-Path $repo "runtime\private-release"
$drivers=Join-Path $root "drivers-b"
$reportPath=Join-Path $root "RC_REPORT.json"
$release=(Get-Content -LiteralPath (Join-Path $repo "editions\private_desktop\RELEASE_CONTRACT.json") `
    -Raw|ConvertFrom-Json).release
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Run the RC completion from an elevated PowerShell."
}
foreach($name in @("AIShieldWfp.sys","AIShieldMiniFilter.sys","AIShieldProcessGuard.sys",
    "ai_shield_wfp.inf","ai_shield_minifilter.inf","ai_shield_process_guard.inf")){
    if(-not(Test-Path -LiteralPath (Join-Path $drivers $name))){throw "RC driver staging is incomplete: $name"}
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "platform\windows\installer\sign_driver_package.ps1") -PackageDir $drivers
if($LASTEXITCODE-ne0){throw "RC driver test signing failed."}

$zipA=Join-Path $root "signed-private-a.zip";$zipB=Join-Path $root "signed-private-b.zip"
foreach($zip in @($zipA,$zipB)){
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tools\package_private_desktop.ps1") -Output $zip -DriverPackageDirectory $drivers
    if($LASTEXITCODE-ne0){throw "Signed consumer package creation failed."}
}
$hashA=(Get-FileHash $zipA -Algorithm SHA256).Hash;$hashB=(Get-FileHash $zipB -Algorithm SHA256).Hash
if($hashA-ne$hashB){throw "Signed consumer package is not reproducible: $hashA != $hashB"}
$releaseLabel=([string]$release-replace'[^A-Za-z0-9._-]','_')
$final=Join-Path $repo "AI_Shield_Private_Desktop_$releaseLabel.zip"
Copy-Item -LiteralPath $zipB -Destination $final -Force

if(-not$ConfirmInstallCycle){
    Write-Output "signed package created but runtime qualification is pending"
    Write-Output "rerun with -ConfirmInstallCycle to replace the three installed prototype drivers and test this RC"
    Write-Output "signed consumer RC: $final"
    Write-Output "sha256=$hashB"
    exit 3
}

$fallback=Join-Path $repo "driver_package\Release"
$driverctl=Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
try{
    Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
    & $driverctl stop|Out-Null
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")|Out-Null
    if($LASTEXITCODE-ne0){throw "RC driver uninstall phase failed."}
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\install_drivers.ps1") -PackageDir $drivers|Out-Null
    if($LASTEXITCODE-ne0){throw "RC driver installation phase failed."}
    Start-Service AIShieldBroker
    Start-Service AIShieldCore
    $status=(& $driverctl status 2>&1)-join"`n"
    if(([regex]::Matches($status,"state=4 win32_exit=0")).Count-ne3){throw "RC driver health check failed: $status"}
}catch{
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")|Out-Null
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\install_drivers.ps1") -PackageDir $fallback|Out-Null
    Start-Service AIShieldBroker -ErrorAction SilentlyContinue
    Start-Service AIShieldCore -ErrorAction SilentlyContinue
    throw
}

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "tests\windows_private_desktop_qualification.ps1") `
    -DurationSeconds $QualificationSeconds -OutputPath (Join-Path $root "consumer-qualification-elevated.json")
if($LASTEXITCODE-ne0){throw "Elevated consumer qualification failed."}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "platform\windows\verification\driver_security_lab.ps1") -Action preflight|Out-Null
if($LASTEXITCODE-ne0){throw "Driver security preflight failed."}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $repo "platform\windows\qualification\recovery_drills.ps1") -Action inspect|Out-Null
if($LASTEXITCODE-ne0){throw "Recovery inspection failed."}

$report=Get-Content $reportPath -Raw|ConvertFrom-Json
$report.checks=@($report.checks|Where-Object{$_.name-notin@('signed-consumer-package','elevated-consumer-qualification','driver-security-preflight','recovery-inspection')})
$report.checks+=@([pscustomobject]@{name='signed-consumer-package';passed=$true;evidence="sha256=$hashB"},
    [pscustomobject]@{name='elevated-consumer-qualification';passed=$true;evidence='exit=0'},
    [pscustomobject]@{name='driver-security-preflight';passed=$true;evidence='state captured'},
    [pscustomobject]@{name='recovery-inspection';passed=$true;evidence='state captured'})
$report.completed_utc=[DateTime]::UtcNow.ToString('o')
[IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output "signed consumer RC: $final"
Write-Output "sha256=$hashB"
