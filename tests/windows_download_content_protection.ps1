param([int]$TimeoutSeconds=150)
$ErrorActionPreference='Stop'
if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this test from an elevated PowerShell.'}
if((Get-Service AIShieldBroker -ErrorAction Stop).Status-ne'Running'){throw 'AIShieldBroker is not running.'}
$downloads=Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads'
$run=[Guid]::NewGuid().ToString('N')
$safe=Join-Path $downloads "ai-shield-safe-$run.png"
    $dangerous=Join-Path $downloads "ai-shield-active-$run.pdf"
    $suspiciousWav=Join-Path $downloads "ai-shield-command-metadata-$run.wav"
    $disguisedPe=Join-Path $downloads "ai-shield-disguised-$run.jpg"
    $activeSvg=Join-Path $downloads "ai-shield-active-$run.svg"
    $unknown=Join-Path $downloads "ai-shield-unknown-$run.specialblob"
$journal=Join-Path $env:ProgramData 'AIShield\quarantine\journal.jsonl'
$provenance=Join-Path $env:ProgramData 'AIShield\quarantine\provenance.jsonl'
$cleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.pdf"
    $safeCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.png"
    $wavCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.wav"
    $peCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.jpg"
    $svgCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.svg"
    $unknownCleanupDestination=Join-Path $env:TEMP "ai-shield-content-test-$run.specialblob"
$quarantineIds=@()
try {
    [IO.File]::WriteAllBytes($safe,[byte[]](137,80,78,71,13,10,26,10,0,0,0,0))
    [IO.File]::WriteAllText($dangerous,"%PDF-1.7`n1 0 obj`n<</OpenAction<</S/JavaScript/JS(alert(1))>>>>`nendobj`nxref`n%%EOF",[Text.UTF8Encoding]::new($false))
    $payload=[Text.Encoding]::ASCII.GetBytes('curl.exe example.com')
    $wav=[Collections.Generic.List[byte]]::new()
    $wav.AddRange([Text.Encoding]::ASCII.GetBytes('RIFF'))
    $wav.AddRange([BitConverter]::GetBytes([uint32](36+$payload.Length)))
    $wav.AddRange([Text.Encoding]::ASCII.GetBytes('WAVEfmt '))
    $wav.AddRange([BitConverter]::GetBytes([uint32]16))
    $wav.AddRange([byte[]](1,0,1,0,68,172,0,0,68,172,0,0,1,0,8,0))
    $wav.AddRange([Text.Encoding]::ASCII.GetBytes('LIST'))
    $wav.AddRange([BitConverter]::GetBytes([uint32]$payload.Length))
    $wav.AddRange($payload)
    [IO.File]::WriteAllBytes($suspiciousWav,$wav.ToArray())
    $pe=[byte[]]::new(512);$pe[0]=[byte][char]'M';$pe[1]=[byte][char]'Z';[IO.File]::WriteAllBytes($disguisedPe,$pe)
    [IO.File]::WriteAllText($activeSvg,'<svg xmlns="http://www.w3.org/2000/svg" onload="fetch(''https://example.invalid/x'')"><script/></svg>',[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($unknown,'unknown format must enter the release gate',[Text.UTF8Encoding]::new($false))
    foreach($path in @($safe,$dangerous)){Set-Content -LiteralPath ($path+':Zone.Identifier') -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII}
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $dangerousMoved=-not(Test-Path -LiteralPath $dangerous)
        $safeMoved=-not(Test-Path -LiteralPath $safe)
        $wavMoved=-not(Test-Path -LiteralPath $suspiciousWav)
        $peMoved=-not(Test-Path -LiteralPath $disguisedPe)
        $svgMoved=-not(Test-Path -LiteralPath $activeSvg)
        $unknownMoved=-not(Test-Path -LiteralPath $unknown)
        $safeRecorded=(Test-Path $provenance) -and [bool](Get-Content $provenance -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*pending_user_release*"})
    } until(($dangerousMoved-and$safeMoved-and$wavMoved-and$peMoved-and$svgMoved-and$unknownMoved-and$safeRecorded)-or[DateTime]::UtcNow-ge$deadline)
    $quarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*ai-shield-active-$run.pdf*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $safeQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*$run*pending_user_release*committed*"}|Select-Object -Last 1
    $wavQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*ai-shield-command-metadata-$run.wav*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $peQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*ai-shield-disguised-$run.jpg*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $svgQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*ai-shield-active-$run.svg*suspicious_file_structure*committed*"}|Select-Object -Last 1
    $unknownQuarantineRecord=Get-Content $journal -ErrorAction SilentlyContinue|Where-Object{$_-like"*ai-shield-unknown-$run.specialblob*pending_user_release*committed*"}|Select-Object -Last 1
    $unknownRecordObject=$(if($unknownQuarantineRecord){$unknownQuarantineRecord|ConvertFrom-Json}else{$null})
    $contentHashRecorded=$null -ne $unknownRecordObject -and [string]$unknownRecordObject.sha256 -match '^[0-9a-f]{64}$'
    $quarantined=[bool]$quarantineRecord
    $safeQuarantined=[bool]$safeQuarantineRecord
    if($quarantined){$quarantineIds+=@([pscustomobject]@{Id=($quarantineRecord|ConvertFrom-Json).id;Destination=$cleanupDestination})}
    if($safeQuarantined){$quarantineIds+=@([pscustomobject]@{Id=($safeQuarantineRecord|ConvertFrom-Json).id;Destination=$safeCleanupDestination})}
    if($wavQuarantineRecord){$quarantineIds+=@([pscustomobject]@{Id=($wavQuarantineRecord|ConvertFrom-Json).id;Destination=$wavCleanupDestination})}
    if($peQuarantineRecord){$quarantineIds+=@([pscustomobject]@{Id=($peQuarantineRecord|ConvertFrom-Json).id;Destination=$peCleanupDestination})}
    if($svgQuarantineRecord){$quarantineIds+=@([pscustomobject]@{Id=($svgQuarantineRecord|ConvertFrom-Json).id;Destination=$svgCleanupDestination})}
    if($unknownQuarantineRecord){$quarantineIds+=@([pscustomobject]@{Id=($unknownQuarantineRecord|ConvertFrom-Json).id;Destination=$unknownCleanupDestination})}
    if(-not$dangerousMoved-or-not$safeMoved-or-not$wavMoved-or-not$peMoved-or-not$svgMoved-or-not$unknownMoved-or-not$quarantined-or-not$safeQuarantined-or-not$wavQuarantineRecord-or-not$peQuarantineRecord-or-not$svgQuarantineRecord-or-not$unknownQuarantineRecord-or-not$contentHashRecorded-or-not$safeRecorded){
        throw "Content protection failed: dangerous_moved=$dangerousMoved safe_moved=$safeMoved dangerous_quarantined=$quarantined safe_quarantined=$safeQuarantined safe_recorded=$safeRecorded"
    }
    Write-Output 'safe_image_requires_release=true'
    Write-Output 'active_pdf_quarantined=true'
    Write-Output 'wav_without_motw_quarantined=true'
    Write-Output 'disguised_pe_quarantined=true'
    Write-Output 'active_svg_quarantined=true'
    Write-Output 'unknown_extension_release_gated=true'
    Write-Output 'content_sha256_recorded=true'
    Write-Output 'provenance_recorded=true'
} finally {
    Remove-Item -LiteralPath $safe,$dangerous,$suspiciousWav,$disguisedPe,$activeSvg,$unknown -Force -ErrorAction SilentlyContinue
    if($quarantineIds.Count){
        $broker=(Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'").PathName.Trim('"')
        foreach($entry in $quarantineIds){
            & $broker quarantine-restore $entry.Id $entry.Destination 'Automated content-protection qualification cleanup'|Out-Null
            Remove-Item -LiteralPath $entry.Destination -Force -ErrorAction SilentlyContinue
        }
    }
}
