param([int]$TimeoutSeconds=150)
$ErrorActionPreference='Stop'
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this test from an elevated PowerShell.'}
if((Get-Service AIShieldBroker -ErrorAction Stop).Status-ne'Running'){throw 'AIShieldBroker is not running.'}
$downloads=Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
$run=[Guid]::NewGuid().ToString('N')
$safe=Join-Path $downloads "ai-shield-safe-$run.png"
$dangerous=Join-Path $downloads "ai-shield-active-$run.pdf"
$journal=Join-Path $env:ProgramData 'AIShield\quarantine\journal.jsonl'
$provenance=Join-Path $env:ProgramData 'AIShield\quarantine\provenance.jsonl'
$cleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.pdf"
$quarantineId=$null
try {
    [IO.File]::WriteAllBytes($safe,[byte[]](137,80,78,71,13,10,26,10,0,0,0,0))
    [IO.File]::WriteAllText($dangerous,"%PDF-1.7`n1 0 obj`n<</OpenAction<</S/JavaScript/JS(alert(1))>>>>`nendobj`nxref`n%%EOF",[Text.UTF8Encoding]::new($false))
    foreach($path in @($safe,$dangerous)){Set-Content -LiteralPath ($path+':Zone.Identifier') -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII}
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $dangerousMoved=-not(Test-Path -LiteralPath $dangerous)
        $safeRecorded=(Test-Path $provenance) -and [bool](Get-Content $provenance -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*external_content_scanned_safe*"})
    } until(($dangerousMoved-and$safeRecorded)-or[DateTime]::UtcNow-ge$deadline)
    $quarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $quarantined=[bool]$quarantineRecord
    if($quarantined){$quarantineId=($quarantineRecord|ConvertFrom-Json).id}
    if(-not(Test-Path -LiteralPath $safe)){throw 'Safe image was not retained.'}
    if(-not$dangerousMoved-or-not$quarantined-or-not$safeRecorded){
        throw "Content protection failed: dangerous_moved=$dangerousMoved quarantined=$quarantined safe_recorded=$safeRecorded"
    }
    Write-Output 'safe_image_retained=true'
    Write-Output 'active_pdf_quarantined=true'
    Write-Output 'provenance_recorded=true'
} finally {
    Remove-Item -LiteralPath $safe,$dangerous -Force -ErrorAction SilentlyContinue
    if($quarantineId){
        $broker=(Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'").PathName.Trim('"')
        & $broker quarantine-restore $quarantineId $cleanupDestination 'Automated content-protection qualification cleanup'|Out-Null
        Remove-Item -LiteralPath $cleanupDestination -Force -ErrorAction SilentlyContinue
    }
}
