param(
    [ValidateSet("inspect","configure-local","configure","run","rollback")][string]$Action = "inspect",
    [string]$Endpoint = "",
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$CertificateSha256 = "",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$root = Join-Path $env:ProgramData "AIShield\powershell-logging"
$statePath = Join-Path $root "state.json"
$keyPath = Join-Path $root "hmac-key.dpapi"
$backupPath = Join-Path $root "registry-backup.json"
$taskName = "AIShieldPowerShellPrivacyForwarder"
$scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

function Read-Value([string]$Path,[string]$Name) {
    $item=Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if($null-eq$item){return $null}; return $item.$Name
}
function CertPin([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    return $Certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
}
function Get-Key {
    $protected=[IO.File]::ReadAllBytes($keyPath)
    return [Security.Cryptography.ProtectedData]::Unprotect($protected,$null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
}

if($Action-eq"inspect"){
    [ordered]@{configured=(Test-Path $statePath);script_block_logging=(Read-Value $scriptBlockPath "EnableScriptBlockLogging");
        module_logging=(Read-Value $modulePath "EnableModuleLogging");state=$(if(Test-Path $statePath){
        Get-Content $statePath -Raw|ConvertFrom-Json}else{$null})}|ConvertTo-Json -Depth 5;exit 0
}
if($Action-eq"run"){
    if(-not(Test-Path $statePath)-or-not(Test-Path $keyPath)){exit 2}
    $state=Get-Content $statePath -Raw|ConvertFrom-Json
    $key=Get-Key
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4103,4104;
        StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue|Where-Object RecordId -gt ([uint64]$state.last_record_id)|
        Sort-Object RecordId|Select-Object -First 500)
    if($events.Count-eq0){exit 0}
    $sanitized=foreach($event in $events){
        $hmac=[Security.Cryptography.HMACSHA256]::new($key)
        $digest=([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($event.Message)))).Replace('-','')
        $hmac.Dispose()
        [ordered]@{record_id=$event.RecordId;event_id=$event.Id;time_utc=$event.TimeCreated.ToUniversalTime().ToString('o');
            provider=$event.ProviderName;message_hmac=$digest;message_length=$event.Message.Length;machine=$env:COMPUTERNAME}
    }
    $handler=[Net.Http.HttpClientHandler]::new()
    $expected=[string]$state.certificate_sha256
    $handler.ServerCertificateCustomValidationCallback={param($request,$cert,$chain,$errors)
        return $errors-eq[Net.Security.SslPolicyErrors]::None-and(CertPin $cert)-eq$expected}
    $client=[Net.Http.HttpClient]::new($handler)
    $body=[Net.Http.StringContent]::new(($sanitized|ConvertTo-Json -Depth 4),[Text.Encoding]::UTF8,'application/json')
    $response=$client.PostAsync([string]$state.endpoint,$body).GetAwaiter().GetResult()
    if(-not$response.IsSuccessStatusCode){throw "PowerShell privacy forwarding failed HTTP $([int]$response.StatusCode)."}
    $state.last_record_id=[uint64]$events[-1].RecordId
    $state|ConvertTo-Json -Compress|Set-Content -LiteralPath $statePath -Encoding UTF8
    $client.Dispose();exit 0
}

$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or-not$ConfirmSystemChange){
    throw "Elevated execution and -ConfirmSystemChange are required."
}
if($Action-eq"rollback"){
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    if(Test-Path $backupPath){
        $backup=Get-Content $backupPath -Raw|ConvertFrom-Json
        foreach($entry in $backup.values){
            if($null-eq$entry.value){Remove-ItemProperty -Path $entry.path -Name $entry.name -ErrorAction SilentlyContinue}
            else{New-Item -Path $entry.path -Force|Out-Null;Set-ItemProperty -Path $entry.path -Name $entry.name -Value $entry.value}
        }
    }
    Remove-Item $statePath,$keyPath,$backupPath -Force -ErrorAction SilentlyContinue
    Write-Output "PowerShell privacy logging rolled back";exit 0
}
if($Action-eq'configure'-and(-not[Uri]::IsWellFormedUriString($Endpoint,[UriKind]::Absolute)-or
    -not$Endpoint.StartsWith('https://'))){
    throw "Endpoint must be an absolute HTTPS URL."
}
New-Item -ItemType Directory -Force -Path $root|Out-Null
& icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"|Out-Null
if($LASTEXITCODE-ne0){throw "Could not secure PowerShell logging state."}
if(-not(Test-Path $backupPath)){
    $values=@(
        [ordered]@{path=$scriptBlockPath;name='EnableScriptBlockLogging';value=(Read-Value $scriptBlockPath 'EnableScriptBlockLogging')},
        [ordered]@{path=$scriptBlockPath;name='EnableScriptBlockInvocationLogging';value=(Read-Value $scriptBlockPath 'EnableScriptBlockInvocationLogging')},
        [ordered]@{path=$modulePath;name='EnableModuleLogging';value=(Read-Value $modulePath 'EnableModuleLogging')}
    )
    [ordered]@{schema='AIShieldPowerShellLoggingBackup/1';values=$values}|ConvertTo-Json -Depth 5|
        Set-Content -LiteralPath $backupPath -Encoding UTF8
}
New-Item -Path $scriptBlockPath -Force|Out-Null
Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1
Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockInvocationLogging -Value 0
New-Item -Path $modulePath -Force|Out-Null
Set-ItemProperty -Path $modulePath -Name EnableModuleLogging -Value 1
$moduleNames=Join-Path $modulePath 'ModuleNames';New-Item -Path $moduleNames -Force|Out-Null
Set-ItemProperty -Path $moduleNames -Name 'Microsoft.PowerShell.*' -Value 1
if($Action-eq'configure-local'){
    [ordered]@{schema='AIShieldPowerShellPrivacy/1';endpoint='';certificate_sha256='';last_record_id=[uint64]0;
        local_logging=$true;configured_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress|
        Set-Content -LiteralPath $statePath -Encoding UTF8
    Write-Output "Local PowerShell logging enabled; external forwarding remains unconfigured";exit 0
}
$key=New-Object byte[] 32
$rng=[Security.Cryptography.RNGCryptoServiceProvider]::new();$rng.GetBytes($key);$rng.Dispose()
$protected=[Security.Cryptography.ProtectedData]::Protect($key,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
[IO.File]::WriteAllBytes($keyPath,$protected)
[ordered]@{schema='AIShieldPowerShellPrivacy/1';endpoint=$Endpoint;certificate_sha256=$CertificateSha256.ToUpperInvariant();
    last_record_id=[uint64]0;configured_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress|
    Set-Content -LiteralPath $statePath -Encoding UTF8
$actionObject=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
    "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action run"
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$taskPrincipal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $actionObject -Trigger $trigger -Principal $taskPrincipal -Force|Out-Null
Write-Output "PowerShell logging configured; external payload contains metadata and HMAC only"
