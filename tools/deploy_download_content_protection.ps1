param([switch]$Elevated)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){
    if($Elevated){throw 'Elevation failed.'}
    $arguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Elevated')
    $process=Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    $log=Join-Path $repo 'build_vs\download-content-protection-deploy.log'
    if(Test-Path $log){Get-Content $log}
    exit $process.ExitCode
}
$log=Join-Path $repo 'build_vs\download-content-protection-deploy.log'
Start-Transcript -Path $log -Force|Out-Null
$source=Join-Path $repo 'build_vs\Release\ai_shield_broker.exe'
$scannerSource=Join-Path $repo 'build_vs\Release\ai_shield_file_scanner.exe'
$profileTool=Join-Path $repo 'build_vs\Release\ai_shield_integrations.exe'
$test=Join-Path $repo 'tests\windows_download_content_protection.ps1'
$uiSource=Join-Path $repo 'editions\private_desktop\ui\AIShield.PrivateDesktop.UI.xaml'
$uiScriptSource=Join-Path $repo 'editions\private_desktop\ui\start_private_ui.ps1'
$uiLauncherSource=Join-Path $repo 'editions\private_desktop\AI_Shield_UI.cmd'
$auditViewerSource=Join-Path $repo 'editions\private_desktop\ui\AIShield.AuditViewer.xaml'
$diagSource=Join-Path $repo 'build_vs\Release\ai_shield_diag.exe'
if(-not(Test-Path $source)-or-not(Test-Path $scannerSource)){throw 'Release broker or isolated scanner is missing.'}
& $source self-test
if($LASTEXITCODE-ne0){throw 'Broker self-test failed.'}
$service=Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
if(-not$service){throw 'AIShieldBroker service is not installed.'}
$installed=([regex]::Match($service.PathName,'^"?([^\"]+?\.exe)"?(?:\s|$)')).Groups[1].Value
if(-not$installed){throw 'Could not resolve installed broker path.'}
$backup=$installed+'.before-content-protection.bak'
$scannerInstalled=Join-Path (Split-Path $installed -Parent) 'ai_shield_file_scanner.exe'
$scannerBackup=$scannerInstalled+'.before-content-protection.bak'
$uiInstalled='C:\Program Files\AI_Shield_Private_Desktop\ui\AIShield.PrivateDesktop.UI.xaml'
$uiBackup=$uiInstalled+'.before-content-protection.bak'
$uiScriptInstalled='C:\Program Files\AI_Shield_Private_Desktop\ui\start_private_ui.ps1'
$uiScriptBackup=$uiScriptInstalled+'.before-content-protection.bak'
$uiLauncherInstalled='C:\Program Files\AI_Shield_Private_Desktop\AI_Shield_UI.cmd'
$uiLauncherBackup=$uiLauncherInstalled+'.before-content-protection.bak'
$auditViewerInstalled='C:\Program Files\AI_Shield_Private_Desktop\ui\AIShield.AuditViewer.xaml'
$auditViewerBackup=$auditViewerInstalled+'.before-content-protection.bak'
$diagInstalled='C:\Program Files\AI_Shield_Private_Desktop\build_vs\Release\ai_shield_diag.exe'
$diagBackup=$diagInstalled+'.before-audit-viewer.bak'
$updated=$false
try {
    Stop-Service AIShieldBroker -Force
    (Get-Service AIShieldBroker).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Remove-Item (Join-Path $env:ProgramData 'AIShield\quarantine\scanner-health.jsonl') -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $installed -Destination $backup -Force
    if(Test-Path $scannerInstalled){Copy-Item -LiteralPath $scannerInstalled -Destination $scannerBackup -Force}
    Copy-Item -LiteralPath $source -Destination $installed -Force
    Copy-Item -LiteralPath $scannerSource -Destination $scannerInstalled -Force
    $parserSid=(& $profileTool appcontainer-sid|Select-Object -First 1).Trim()
    if($LASTEXITCODE-ne0-or$parserSid-notmatch'^S-1-15-2-'){throw 'AppContainer parser profile provisioning failed.'}
    $parserBin=Split-Path $scannerInstalled -Parent
    & icacls.exe (Split-Path $parserBin -Parent) /grant "*$parserSid`:(RX)"|Out-Null
    if($LASTEXITCODE-ne0){throw 'AppContainer parser traversal ACL provisioning failed.'}
    & icacls.exe $parserBin /grant "*$parserSid`:(OI)(CI)(RX)" /T /C|Out-Null
    if($LASTEXITCODE-ne0){throw 'AppContainer parser read/execute ACL provisioning failed.'}
    if(Test-Path $uiInstalled){
        Copy-Item -LiteralPath $uiInstalled -Destination $uiBackup -Force
        Copy-Item -LiteralPath $uiSource -Destination $uiInstalled -Force
    }
    if(Test-Path $uiScriptInstalled){
        Copy-Item -LiteralPath $uiScriptInstalled -Destination $uiScriptBackup -Force
        Copy-Item -LiteralPath $uiScriptSource -Destination $uiScriptInstalled -Force
    }
    if(Test-Path $uiLauncherInstalled){
        Copy-Item -LiteralPath $uiLauncherInstalled -Destination $uiLauncherBackup -Force
        Copy-Item -LiteralPath $uiLauncherSource -Destination $uiLauncherInstalled -Force
    }
    if(Test-Path $auditViewerInstalled){Copy-Item -LiteralPath $auditViewerInstalled -Destination $auditViewerBackup -Force}
    Copy-Item -LiteralPath $auditViewerSource -Destination $auditViewerInstalled -Force
    if(Test-Path $diagInstalled){Copy-Item -LiteralPath $diagInstalled -Destination $diagBackup -Force}
    Copy-Item -LiteralPath $diagSource -Destination $diagInstalled -Force
    Start-Service AIShieldBroker
    (Get-Service AIShieldBroker).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    if(Get-Service AIShieldCore -ErrorAction SilentlyContinue){
        Start-Service AIShieldCore
        (Get-Service AIShieldCore).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    }
    Start-Sleep -Seconds 4
    $updated=$true
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $test -TimeoutSeconds 45
    if($LASTEXITCODE-ne0){
        Get-Content (Join-Path $env:ProgramData 'AIShield\quarantine\scanner-health.jsonl') -Tail 30 -ErrorAction SilentlyContinue
        throw 'Content-protection qualification failed.'
    }
    Remove-Item -LiteralPath $backup,$scannerBackup,$uiBackup,$uiScriptBackup,$uiLauncherBackup,$auditViewerBackup,$diagBackup -Force -ErrorAction SilentlyContinue
    Write-Output 'download_content_protection=installed'
    Write-Output "broker_sha256=$((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash)"
    Stop-Transcript|Out-Null
} catch {
    if($updated-or(Test-Path $backup)){
        Stop-Service AIShieldBroker -Force -ErrorAction SilentlyContinue
        if(Test-Path $backup){Copy-Item -LiteralPath $backup -Destination $installed -Force}
        if(Test-Path $scannerBackup){Copy-Item -LiteralPath $scannerBackup -Destination $scannerInstalled -Force}
        elseif(Test-Path $scannerInstalled){Remove-Item -LiteralPath $scannerInstalled -Force}
        if(Test-Path $uiBackup){Copy-Item -LiteralPath $uiBackup -Destination $uiInstalled -Force}
        if(Test-Path $uiScriptBackup){Copy-Item -LiteralPath $uiScriptBackup -Destination $uiScriptInstalled -Force}
        if(Test-Path $uiLauncherBackup){Copy-Item -LiteralPath $uiLauncherBackup -Destination $uiLauncherInstalled -Force}
        if(Test-Path $auditViewerBackup){Copy-Item -LiteralPath $auditViewerBackup -Destination $auditViewerInstalled -Force}
        elseif(Test-Path $auditViewerInstalled){Remove-Item -LiteralPath $auditViewerInstalled -Force}
        if(Test-Path $diagBackup){Copy-Item -LiteralPath $diagBackup -Destination $diagInstalled -Force}
        Start-Service AIShieldBroker -ErrorAction SilentlyContinue
    }
    Write-Error $_
    Stop-Transcript|Out-Null
    exit 1
}
