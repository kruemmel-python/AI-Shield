param(
    [ValidateSet("inspect","apply","rollback")][string]$Action = "inspect",
    [string[]]$VpnProgram = @(),
    [ValidateRange(1,65535)][int[]]$DevelopmentPort = @(),
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference="Stop"
$root=Join-Path $env:ProgramData "AIShield\firewall"
$backup=Join-Path $root "before.wfw"
$statePath=Join-Path $root "state.json"
$group="AI Shield Managed Baseline"
if($Action-eq"inspect"){
    [ordered]@{profiles=@(Get-NetFirewallProfile|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);
        transaction=(Test-Path $statePath);managed_rules=@(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue|
        Select-Object Name,DisplayName,Enabled,Direction,Action)}|ConvertTo-Json -Depth 6;exit 0
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or-not$ConfirmSystemChange){
    throw "Elevated execution and -ConfirmSystemChange are required."
}
if($Action-eq"rollback"){
    if(-not(Test-Path $backup)){throw "No firewall backup exists."}
    & netsh.exe advfirewall import $backup|Out-Null
    if($LASTEXITCODE-ne0){throw "Windows Firewall restore failed."}
    Remove-Item $statePath,$backup -Force -ErrorAction SilentlyContinue
    Write-Output "Windows Firewall baseline rolled back";exit 0
}
if(Test-Path $statePath){throw "A firewall baseline transaction already exists; roll it back first."}
foreach($program in $VpnProgram){
    $full=[IO.Path]::GetFullPath($program)
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)-or[IO.Path]::GetExtension($full)-ne'.exe'){
        throw "VPN allowlist path is not an executable file: $program"
    }
}
New-Item -ItemType Directory -Force -Path $root|Out-Null
& icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"|Out-Null
if($LASTEXITCODE-ne0){throw "Could not secure firewall state."}
& netsh.exe advfirewall export $backup|Out-Null
if($LASTEXITCODE-ne0-or-not(Test-Path $backup)){throw "Windows Firewall export failed."}
[ordered]@{schema='AIShieldFirewallTransaction/1';created_utc=[DateTime]::UtcNow.ToString('o');
    vpn_programs=$VpnProgram;development_ports=$DevelopmentPort}|ConvertTo-Json -Depth 4|
    Set-Content -LiteralPath $statePath -Encoding UTF8
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
foreach($program in $VpnProgram){
    New-NetFirewallRule -Name ("AIShield-VPN-"+[Guid]::NewGuid().ToString('N')) -DisplayName "AI Shield VPN allowlist" `
        -Group $group -Direction Outbound -Action Allow -Program ([IO.Path]::GetFullPath($program)) -Profile Any|Out-Null
}
foreach($port in $DevelopmentPort){
    New-NetFirewallRule -Name "AIShield-Dev-TCP-$port" -DisplayName "AI Shield development TCP $port" `
        -Group $group -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -RemoteAddress LocalSubnet `
        -Profile Private|Out-Null
    New-NetFirewallRule -Name "AIShield-Dev-UDP-$port" -DisplayName "AI Shield development UDP $port" `
        -Group $group -Direction Inbound -Action Allow -Protocol UDP -LocalPort $port -RemoteAddress LocalSubnet `
        -Profile Private|Out-Null
}
Write-Output "Windows Firewall enabled with inbound block/outbound allow; rollback=$backup"

