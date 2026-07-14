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
$safeCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.png"
$quarantineIds=@()
try {
    [IO.File]::WriteAllBytes($safe,[byte[]](137,80,78,71,13,10,26,10,0,0,0,0))
    [IO.File]::WriteAllText($dangerous,"%PDF-1.7`n1 0 obj`n<</OpenAction<</S/JavaScript/JS(alert(1))>>>>`nendobj`nxref`n%%EOF",[Text.UTF8Encoding]::new($false))
    foreach($path in @($safe,$dangerous)){Set-Content -LiteralPath ($path+':Zone.Identifier') -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII}
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $dangerousMoved=-not(Test-Path -LiteralPath $dangerous)
        $safeMoved=-not(Test-Path -LiteralPath $safe)
        $safeRecorded=(Test-Path $provenance) -and [bool](Get-Content $provenance -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*pending_user_release*"})
    } until(($dangerousMoved-and$safeMoved-and$safeRecorded)-or[DateTime]::UtcNow-ge$deadline)
    $quarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $safeQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*pending_user_release*committed*"}|Select-Object -Last 1
    $quarantined=[bool]$quarantineRecord
    $safeQuarantined=[bool]$safeQuarantineRecord
    if($quarantined){$quarantineIds+=@([pscustomobject]@{Id=($quarantineRecord|ConvertFrom-Json).id;Destination=$cleanupDestination})}
    if($safeQuarantined){$quarantineIds+=@([pscustomobject]@{Id=($safeQuarantineRecord|ConvertFrom-Json).id;Destination=$safeCleanupDestination})}
    if(-not$dangerousMoved-or-not$safeMoved-or-not$quarantined-or-not$safeQuarantined-or-not$safeRecorded){
        throw "Content protection failed: dangerous_moved=$dangerousMoved safe_moved=$safeMoved dangerous_quarantined=$quarantined safe_quarantined=$safeQuarantined safe_recorded=$safeRecorded"
    }
    Write-Output 'safe_image_requires_release=true'
    Write-Output 'active_pdf_quarantined=true'
    Write-Output 'provenance_recorded=true'
} finally {
    Remove-Item -LiteralPath $safe,$dangerous -Force -ErrorAction SilentlyContinue
    if($quarantineIds.Count){
        $broker=(Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'").PathName.Trim('"')
        foreach($entry in $quarantineIds){
            & $broker quarantine-restore $entry.Id $entry.Destination 'Automated content-protection qualification cleanup'|Out-Null
            Remove-Item -LiteralPath $entry.Destination -Force -ErrorAction SilentlyContinue
        }
    }
}
