param(
    [ValidateSet("inspect","generate","apply-audit","evaluate","reconcile","rollback")][string]$Action = "inspect",
    [ValidateRange(1,90)][int]$LookbackDays = 14,
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$root = Join-Path $env:ProgramData "AIShield\wdac"
$xmlPath = Join-Path $root "AIShield-Audit.xml"
$binaryPath = Join-Path $root "AIShield-Audit.cip"
$statePath = Join-Path $root "state.json"

if ($Action -eq "inspect") {
    [ordered]@{ module=[bool](Get-Module ConfigCI -ListAvailable); citool=[bool](Get-Command CiTool.exe -ErrorAction SilentlyContinue);
        generated=(Test-Path $binaryPath -ErrorAction SilentlyContinue); deployed=$(if(Test-Path $statePath -ErrorAction SilentlyContinue){
        Get-Content $statePath -Raw -ErrorAction SilentlyContinue|ConvertFrom-Json}else{$null}) } |
        ConvertTo-Json -Depth 5
    exit 0
}
if ($Action -eq "evaluate") {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';
        Id=3076; StartTime=(Get-Date).AddDays(-$LookbackDays)} -ErrorAction SilentlyContinue)
    $records = foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $fields = @{}
        foreach ($item in $xml.Event.EventData.Data) { $fields[[string]$item.Name] = [string]$item.'#text' }
        [pscustomobject]@{ file=$fields.FileName; process=$fields.ProcessName; policy=$fields.PolicyName;
            publisher=$fields.PublisherName; record_id=$event.RecordId }
    }
    $groups = @($records | Group-Object file,process | Sort-Object Count -Descending | Select-Object -First 100 | ForEach-Object {
        [ordered]@{ count=$_.Count; file=$_.Group[0].file; process=$_.Group[0].process;
            publisher=$_.Group[0].publisher }
    })
    [ordered]@{ schema="AIShieldWdacCompatibility/1"; lookback_days=$LookbackDays; audit_events=$events.Count;
        ready_for_enforcement=($events.Count -eq 0); recommendation=$(if($events.Count -eq 0){
        "No audit denials observed; require a representative soak period before enforcement."}else{
        "Resolve or explicitly allow every grouped audit denial before enforcement."}); groups=$groups } |
        ConvertTo-Json -Depth 6
    exit 0
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not $ConfirmSystemChange) { throw "Elevated execution and -ConfirmSystemChange are required." }
Import-Module ConfigCI -ErrorAction Stop
New-Item -ItemType Directory -Force -Path $root | Out-Null
& icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure WDAC state directory." }
if($Action-eq"reconcile"){
    $inventory=(& CiTool.exe --list-policies --json|ConvertFrom-Json)
    $matches=@($inventory.Policies|Where-Object {$_.FriendlyName-eq'AI Shield Audit Baseline'-and$_.IsOnDisk})
    if($matches.Count-ne1){throw "Expected exactly one deployed AI Shield WDAC audit policy."}
    [ordered]@{schema='AIShieldWdacState/1';policy_id=('{'+$matches[0].PolicyID+'}');deployed=$true;
        reconciled_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress|
        Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Output "WDAC state reconciled policy=$($matches[0].PolicyID)";exit 0
}
if ($Action -eq "generate") {
    $policyId = [Guid]::NewGuid()
    New-CIPolicy -ScanPath (Join-Path $env:ProgramFiles "AIShield") -FilePath $xmlPath `
        -Level Publisher -Fallback Hash -UserPEs -Audit -MultiplePolicyFormat
    Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName "AI Shield Audit Baseline" `
        -PolicyId $policyId.ToString('B') -ResetPolicyID | Out-Null
    Set-RuleOption -FilePath $xmlPath -Option 3
    ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath | Out-Null
    $policyXml=[xml](Get-Content $xmlPath -Raw)
    $actualPolicyId=[string]($policyXml.SelectSingleNode("//*[local-name()='PolicyID']").InnerText)
    if($actualPolicyId -notmatch '^\{[0-9a-fA-F-]{36}\}$'){throw "Generated WDAC PolicyID is invalid."}
    [ordered]@{ schema="AIShieldWdacState/1"; policy_id=$actualPolicyId; deployed=$false;
        generated_utc=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress |
        Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Output "WDAC audit policy generated: $binaryPath"
    exit 0
}
if (-not (Test-Path $statePath) -or -not (Test-Path $binaryPath)) { throw "Generate the WDAC audit policy first." }
$state = Get-Content $statePath -Raw | ConvertFrom-Json
if ($state.schema -ne "AIShieldWdacState/1" -or [string]$state.policy_id -notmatch '^\{[0-9a-fA-F-]{36}\}$') {
    throw "WDAC state is invalid."
}
if ($Action -eq "apply-audit") {
    $operation=Start-Process CiTool.exe -ArgumentList @('--update-policy',('"'+$binaryPath+'"')) -PassThru
    if(-not$operation.WaitForExit(60000)){Stop-Process -Id $operation.Id -Force}
    $inventory=(& CiTool.exe --list-policies --json|ConvertFrom-Json)
    $normalized=[string]$state.policy_id.Trim('{}').ToLowerInvariant()
    $present=@($inventory.Policies|Where-Object {$_.PolicyID.ToLowerInvariant()-eq$normalized-and$_.IsOnDisk}).Count-eq1
    if(-not$present){throw "WDAC audit policy deployment could not be verified."}
    $state.deployed=$true
    $state | ConvertTo-Json -Compress | Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Output "WDAC audit policy deployed; enforcement remains disabled"
    exit 0
}
$remove=Start-Process CiTool.exe -ArgumentList @('--remove-policy',([string]$state.policy_id)) -PassThru
if(-not$remove.WaitForExit(60000)){Stop-Process -Id $remove.Id -Force}
$inventory=(& CiTool.exe --list-policies --json|ConvertFrom-Json)
$normalized=[string]$state.policy_id.Trim('{}').ToLowerInvariant()
if(@($inventory.Policies|Where-Object {$_.PolicyID.ToLowerInvariant()-eq$normalized-and$_.IsOnDisk}).Count-ne0){
    throw "WDAC audit policy removal could not be verified."
}
$state.deployed=$false
$state | ConvertTo-Json -Compress | Set-Content -LiteralPath $statePath -Encoding UTF8
Write-Output "WDAC audit policy rolled back"
