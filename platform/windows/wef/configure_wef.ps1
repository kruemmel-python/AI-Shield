param(
    [ValidateSet("inspect","apply","validate","rollback")][string]$Action = "inspect",
    [string]$CollectorUri = "",
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$CertificateSha256 = "",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$root = Join-Path $env:ProgramData "AIShield\wef"
$statePath = Join-Path $root "collector-state.json"
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
$taskName = "AIShieldWefPinValidation"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")

function Test-CollectorPin([Uri]$Uri, [string]$Expected) {
    if ($Uri.Scheme -ne "https") { return $false }
    $port = if ($Uri.IsDefaultPort) { 443 } else { $Uri.Port }
    $tls = @{ observed=""; errors=[Net.Security.SslPolicyErrors]::None }
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect($Uri.DnsSafeHost,$port)
    $validation = {
        param($sender,$certificate,$chain,$errors)
        $tls.errors = $errors
        if ($null -ne $certificate) {
            $tls.observed = $certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
        }
        return $true
    }
    $stream = [Net.Security.SslStream]::new($client.GetStream(),$false,$validation)
    $stream.AuthenticateAsClient($Uri.DnsSafeHost)
    $stream.Dispose()
    $client.Dispose()
    return $tls.errors -eq [Net.Security.SslPolicyErrors]::None -and $tls.observed -eq $Expected.ToUpperInvariant()
}

if ($Action -eq "inspect") {
    [ordered]@{ configured=(Test-Path $statePath); state=$(if(Test-Path $statePath){
        Get-Content $statePath -Raw|ConvertFrom-Json}else{$null}); subscription_manager=$(
        Get-ItemProperty $policyPath -ErrorAction SilentlyContinue) } | ConvertTo-Json -Depth 6
    exit 0
}
if ($Action -eq "validate") {
    if (-not (Test-Path $statePath)) { exit 2 }
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    $valid = Test-CollectorPin ([Uri]$state.collector_uri) ([string]$state.certificate_sha256)
    if (-not $valid) {
        Remove-Item -LiteralPath $policyPath -Recurse -Force -ErrorAction SilentlyContinue
        & eventcreate.exe /T ERROR /ID 2002 /L APPLICATION /SO AIShieldCore `
            /D "AI Shield disabled WEF forwarding because collector certificate pin validation failed." | Out-Null
        exit 4
    }
    exit 0
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not $ConfirmSystemChange) { throw "Elevated execution and -ConfirmSystemChange are required." }
if ($Action -eq "rollback") {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $policyPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
    Write-Output "WEF source forwarding rolled back"
    exit 0
}
if ([string]::IsNullOrWhiteSpace($CollectorUri) -or [string]::IsNullOrWhiteSpace($CertificateSha256)) {
    throw "CollectorUri and CertificateSha256 are required."
}
$uri = [Uri]$CollectorUri
if ($uri.Scheme -ne "https" -or -not (Test-CollectorPin $uri $CertificateSha256)) {
    throw "Collector TLS chain or pinned certificate identity validation failed."
}
New-Item -ItemType Directory -Force -Path $root | Out-Null
& icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure WEF state." }
[ordered]@{ schema="AIShieldWefCollector/1"; collector_uri=$uri.AbsoluteUri;
    certificate_sha256=$CertificateSha256.ToUpperInvariant(); configured_utc=[DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json -Compress | Set-Content -LiteralPath $statePath -Encoding UTF8
New-Item -Path $policyPath -Force | Out-Null
$manager = "Server=$($uri.AbsoluteUri),Refresh=60"
New-ItemProperty -Path $policyPath -Name "1" -Value $manager -PropertyType String -Force | Out-Null
$script = Join-Path $repo "platform\windows\wef\configure_wef.ps1"
$actionObject = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Action validate"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
$principalObject = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $actionObject -Trigger $trigger `
    -Principal $principalObject -Force | Out-Null
Write-Output "WEF source forwarding configured with five-minute certificate pin enforcement"
