param(
    [ValidateRange(5,3600)][int]$QualificationSeconds = 30,
    [string]$CMakeExe = "C:\Program Files\CMake\bin\cmake.exe",
    [string]$CTestExe = "C:\Program Files\CMake\bin\ctest.exe"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$root = Join-Path $repo "runtime\private-release"
$reportPath = Join-Path $root "RC_REPORT.json"
$buildA = Join-Path $root "build-release-a"
$buildB = Join-Path $root "build-release-b"
$buildDebug = Join-Path $root "build-debug"
$driverA = Join-Path $root "drivers-a"
$driverB = Join-Path $root "drivers-b"
$submission = Join-Path $root "microsoft-submission"
$qualification = Join-Path $root "consumer-qualification.json"
$checks = [Collections.Generic.List[object]]::new()
$release = (Get-Content -LiteralPath (Join-Path $repo "editions\private_desktop\RELEASE_CONTRACT.json") `
    -Raw | ConvertFrom-Json).release

function Add-Check([string]$Name,[bool]$Passed,[string]$Evidence) {
    $checks.Add([ordered]@{name=$Name;passed=$Passed;evidence=$Evidence})
    Write-Output "[$(if($Passed){'PASS'}else{'FAIL'})] $Name - $Evidence"
}
function Assert-ExternalSuccess([string]$Name) {
    if($LASTEXITCODE-ne0){Add-Check $Name $false "exit=$LASTEXITCODE";throw "$Name failed."}
    Add-Check $Name $true "exit=0"
}
function Reset-ReleaseDirectory([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    $prefix=[IO.Path]::GetFullPath($root).TrimEnd('\')+'\'
    if(-not$full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw "Release cleanup escaped root: $full"}
    if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
function Get-ArtifactHashes([string]$Directory,[string[]]$Names) {
    $result=[ordered]@{}
    foreach($name in $Names){$path=Join-Path $Directory $name;if(-not(Test-Path -LiteralPath $path)){throw "Artifact missing: $path"};$result[$name]=(Get-FileHash $path -Algorithm SHA256).Hash}
    return $result
}

New-Item -ItemType Directory -Force -Path $root|Out-Null
$started=[DateTime]::UtcNow
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "editions\private_desktop\validate_release_freeze.ps1")
    Assert-ExternalSuccess "release-contract-freeze"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\verification\validate_abi_freeze.ps1")
    Assert-ExternalSuccess "kernel-abi-freeze"

    foreach($directory in @($buildA,$buildB,$buildDebug,$driverA,$driverB,$submission)){Reset-ReleaseDirectory $directory}
    foreach($releaseBuild in @($buildA,$buildB)){
        & $CMakeExe -S $repo -B $releaseBuild -G "Visual Studio 17 2022" -A x64 -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
        Assert-ExternalSuccess "cmake-configure-$([IO.Path]::GetFileName($releaseBuild))"
        & $CMakeExe --build $releaseBuild --config Release --parallel
        Assert-ExternalSuccess "cmake-build-$([IO.Path]::GetFileName($releaseBuild))"
        & $CTestExe --test-dir $releaseBuild -C Release --output-on-failure
        Assert-ExternalSuccess "ctest-$([IO.Path]::GetFileName($releaseBuild))"
    }
    & $CMakeExe -S $repo -B $buildDebug -G "Visual Studio 17 2022" -A x64 -DAI_SHIELD_ENABLE_WINDOWS_PLATFORM=ON
    Assert-ExternalSuccess "cmake-configure-debug"
    & $CMakeExe --build $buildDebug --config Debug --parallel
    Assert-ExternalSuccess "cmake-build-debug"
    & $CTestExe --test-dir $buildDebug -C Debug --output-on-failure
    Assert-ExternalSuccess "ctest-debug"

    $executables=@("ai_shield_broker.exe","ai_shield_driverctl.exe","ai_shield_integrations.exe","ai_shield_file_scanner.exe",
        "ai_shield_kernelctl.exe","ai_shield_service.exe")
    $hashA=Get-ArtifactHashes (Join-Path $buildA "Release") $executables
    $hashB=Get-ArtifactHashes (Join-Path $buildB "Release") $executables
    $userModeMismatch=@($executables|Where-Object{$hashA[$_]-ne$hashB[$_]})
    Add-Check "reproducible-user-mode-binaries" ($userModeMismatch.Count-eq0) `
        $(if($userModeMismatch.Count){$userModeMismatch-join','}else{"five executable hashes match"})

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\build_drivers.ps1") -Configuration Release `
        -PackageDirectory $driverA -Rebuild
    Assert-ExternalSuccess "driver-build-a"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\build_drivers.ps1") -Configuration Release `
        -PackageDirectory $driverB -Rebuild
    Assert-ExternalSuccess "driver-build-b"
    $drivers=@("AIShieldWfp.sys","AIShieldMiniFilter.sys","AIShieldProcessGuard.sys")
    $driverHashA=Get-ArtifactHashes $driverA $drivers
    $driverHashB=Get-ArtifactHashes $driverB $drivers
    $driverMismatch=@($drivers|Where-Object{$driverHashA[$_]-ne$driverHashB[$_]})
    Add-Check "reproducible-driver-binaries" ($driverMismatch.Count-eq0) `
        $(if($driverMismatch.Count){$driverMismatch-join','}else{"three driver hashes match"})

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\installer\prepare_microsoft_submission.ps1") `
        -PackageDirectory $driverB -OutputDirectory $submission
    Assert-ExternalSuccess "inf2cat-cab-submission-staging"

    $zipA=Join-Path $root "private-a.zip";$zipB=Join-Path $root "private-b.zip"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tools\package_private_desktop.ps1") -Output $zipA -DriverPackageDirectory $driverB
    Assert-ExternalSuccess "consumer-package-a"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tools\package_private_desktop.ps1") -Output $zipB -DriverPackageDirectory $driverB
    Assert-ExternalSuccess "consumer-package-b"
    $zipHashA=(Get-FileHash $zipA -Algorithm SHA256).Hash;$zipHashB=(Get-FileHash $zipB -Algorithm SHA256).Hash
    Add-Check "reproducible-consumer-package" ($zipHashA-eq$zipHashB) "a=$zipHashA b=$zipHashB"
    $releaseLabel = ([string]$release -replace '[^A-Za-z0-9._-]', '_')
    Copy-Item -LiteralPath $zipB -Destination `
        (Join-Path $repo "AI_Shield_Private_Desktop_$releaseLabel.zip") -Force

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tests\windows_private_desktop_qualification.ps1") `
        -DurationSeconds $QualificationSeconds -OutputPath $qualification
    Assert-ExternalSuccess "consumer-runtime-qualification"

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "platform\windows\verification\prepare_hlk_lab.ps1") `
        -SubmissionDirectory $submission | Out-Null
    Add-Check "hlk-readiness-inventory" ($LASTEXITCODE-eq0) "readiness report generated; external blockers remain pending"

    $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if($isAdmin){
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
            (Join-Path $repo "platform\windows\verification\driver_security_lab.ps1") -Action preflight | Out-Null
        Add-Check "driver-security-preflight" ($LASTEXITCODE-eq0) "HVCI and Verifier state captured"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
            (Join-Path $repo "platform\windows\qualification\recovery_drills.ps1") -Action inspect | Out-Null
        Add-Check "recovery-inspection" ($LASTEXITCODE-eq0) "runtime and service state captured"
    } else {
        Add-Check "driver-security-preflight" $false "requires elevated PowerShell"
        Add-Check "recovery-inspection" $false "requires elevated PowerShell"
    }
} finally {
    $localFailures=@($checks|Where-Object{-not$_.passed-and$_.name-notin@('driver-security-preflight','recovery-inspection')}).Count
    $report=[ordered]@{schema="AIShieldPrivateReleaseCandidate/1";release=$release;
        started_utc=$started.ToString('o');completed_utc=[DateTime]::UtcNow.ToString('o');
        local_passed=($localFailures-eq0);checks=$checks;
        external_gates=[ordered]@{driver_verifier_reboot="pending";hlk_whcp="pending external laboratory";
            independent_kernel_review="pending external reviewer";penetration_test="pending external laboratory";
            microsoft_production_signature="pending Partner Center"}}
    [IO.File]::WriteAllText($reportPath,($report|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
    Write-Output "release_report=$reportPath"
}
