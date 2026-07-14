param([switch]$Elevated)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$log=Join-Path $repo 'build_vs\scanner-network-driver-deploy.log'
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){
    if($Elevated){throw 'Elevation failed.'}
    $process=Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated') -Wait -PassThru
    if(Test-Path $log){Get-Content $log}
    exit $process.ExitCode
}
Set-Location $repo
Start-Transcript -Path $log -Force|Out-Null
$package=Join-Path $repo 'driver_package\Release'
$backup=Join-Path $repo 'build_vs\driver-package-before-scanner-network'
try{
    Remove-Item $backup -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item $package $backup -Recurse -Force
    Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
    & .\build_vs\Release\ai_shield_driverctl.exe stop
    if($LASTEXITCODE-ne0){throw 'Driver stop failed.'}
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\build_drivers.ps1 -Configuration Release
    if($LASTEXITCODE-ne0){throw 'Driver package refresh failed.'}
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\installer\sign_driver_package.ps1 -PackageDir $package
    if($LASTEXITCODE-ne0){throw 'Driver signing failed.'}
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\installer\install_drivers.ps1 -PackageDir $package
    if($LASTEXITCODE-ne0){throw 'Driver installation failed.'}
    Start-Service AIShieldBroker,AIShieldCore
    foreach($name in 'AIShieldWfp','AIShieldMiniFilter','AIShieldProcessGuard','AIShieldBroker','AIShieldCore'){
        (Get-Service $name).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    }
    Remove-Item $backup -Recurse -Force
    Write-Output 'scanner_network_isolation_driver=installed'
    Write-Output "wfp_sha256=$((Get-FileHash (Join-Path $package 'AIShieldWfp.sys') -Algorithm SHA256).Hash)"
    Stop-Transcript|Out-Null
}catch{
    & .\build_vs\Release\ai_shield_driverctl.exe stop|Out-Null
    if(Test-Path $backup){Copy-Item (Join-Path $backup '*') $package -Recurse -Force}
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\platform\windows\installer\install_drivers.ps1 -PackageDir $package|Out-Null
    Start-Service AIShieldBroker,AIShieldCore -ErrorAction SilentlyContinue
    Write-Error $_
    Stop-Transcript|Out-Null
    exit 1
}
