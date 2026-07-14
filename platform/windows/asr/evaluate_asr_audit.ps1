param(
    [ValidateRange(1,90)][int]$LookbackDays=14,
    [ValidateRange(1,10000)][int]$MinimumEvents=20,
    [ValidateRange(1,100)][int]$MaximumDistinctApplications=5,
    [string]$OutputPath=""
)

$ErrorActionPreference="Stop"
$start=(Get-Date).AddDays(-$LookbackDays)
$events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';
    Id=1122;StartTime=$start} -ErrorAction SilentlyContinue)
$records=foreach($event in $events){
    $xml=[xml]$event.ToXml();$fields=@{}
    foreach($item in $xml.Event.EventData.Data){$fields[[string]$item.Name]=[string]$item.'#text'}
    [pscustomobject]@{rule_id=([string]$fields.ID).ToLowerInvariant();application=[string]$fields.ProcessName;
        target=[string]$fields.Path;record_id=$event.RecordId}
}
$rules=@($records|Where-Object {$_.rule_id -match '^[0-9a-f-]{36}$'}|Group-Object rule_id|ForEach-Object{
    $applications=@($_.Group.application|Where-Object {$_}|Sort-Object -Unique)
    $targets=@($_.Group.target|Where-Object {$_}|Sort-Object -Unique)
    $enough=$_.Count-ge$MinimumEvents
    [ordered]@{rule_id=$_.Name;audit_events=$_.Count;distinct_applications=$applications.Count;
        sample_applications=@($applications|Select-Object -First 10);distinct_targets=$targets.Count;
        recommendation=$(if($enough-and$applications.Count-le$MaximumDistinctApplications){'candidate_after_manual_review'}
            elseif(-not$enough){'collect_more_evidence'}else{'requires_allowlist_or_remediation'});
        auto_enforced=$false}
})
$report=[ordered]@{schema='AIShieldAsrEvidence/1';generated_utc=[DateTime]::UtcNow.ToString('o');
    lookback_days=$LookbackDays;minimum_events=$MinimumEvents;total_audit_events=$events.Count;rules=$rules;
    notice='Recommendations never modify Defender policy and require manual compatibility approval.'}
if(-not[string]::IsNullOrWhiteSpace($OutputPath)){
    $temporary="$OutputPath.$PID.tmp";$report|ConvertTo-Json -Depth 7|Set-Content $temporary -Encoding UTF8
    Move-Item $temporary $OutputPath -Force
}
$report|ConvertTo-Json -Depth 7
