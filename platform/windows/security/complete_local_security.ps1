param(
    [ValidateSet("inspect","apply","rollback")][string]$Action="inspect",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference="Stop"
$root=Join-Path $env:ProgramData "AIShield\security-completion"
$statePath=Join-Path $root "before.json"
$deviceGuardPath="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$lsaPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

function Read-Value([string]$Path,[string]$Name){
    $item=Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if($null-eq$item){return $null};return $item.$Name
}
function Snapshot {
    $preference=Get-MpPreference -ErrorAction SilentlyContinue
    return [ordered]@{
        enable_vbs=Read-Value $deviceGuardPath "EnableVirtualizationBasedSecurity"
        lsa_cfg_flags=Read-Value $lsaPath "LsaCfgFlags"
        maps_reporting=$(if($null-eq$preference){$null}else{[int]$preference.MAPSReporting})
        sample_consent=$(if($null-eq$preference){$null}else{[int]$preference.SubmitSamplesConsent})
        block_first_seen=$(if($null-eq$preference){$null}else{[bool]$preference.DisableBlockAtFirstSeen})
    }
}

if($Action-eq"inspect"){
    $deviceGuard=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard `
        -ErrorAction SilentlyContinue
    [ordered]@{current=(Snapshot);credential_guard_running=($null -ne $deviceGuard -and
        @($deviceGuard.SecurityServicesRunning) -contains 1);transaction=(Test-Path $statePath -ErrorAction SilentlyContinue);
        restart_required=((Read-Value $lsaPath "LsaCfgFlags") -eq 2 -and -not ($null -ne $deviceGuard -and
        @($deviceGuard.SecurityServicesRunning) -contains 1))}|ConvertTo-Json -Depth 5;exit 0
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or-not$ConfirmSystemChange){
    throw "Elevated execution and -ConfirmSystemChange are required."
}
if($Action-eq"rollback"){
    if(-not(Test-Path $statePath)){throw "No local security completion transaction exists."}
    $before=Get-Content $statePath -Raw|ConvertFrom-Json
    foreach($entry in @(
        @{path=$deviceGuardPath;name='EnableVirtualizationBasedSecurity';value=$before.enable_vbs},
        @{path=$lsaPath;name='LsaCfgFlags';value=$before.lsa_cfg_flags})){
        if($null-eq$entry.value){Remove-ItemProperty -Path $entry.path -Name $entry.name -ErrorAction SilentlyContinue}
        else{if(-not(Test-Path $entry.path)){New-Item -Path $entry.path|Out-Null};
            Set-ItemProperty -Path $entry.path -Name $entry.name -Value ([int]$entry.value)}
    }
    if($null-ne$before.maps_reporting){Set-MpPreference -MAPSReporting ([int]$before.maps_reporting)}
    if($null-ne$before.sample_consent){Set-MpPreference -SubmitSamplesConsent ([int]$before.sample_consent)}
    if($null-ne$before.block_first_seen){Set-MpPreference -DisableBlockAtFirstSeen ([bool]$before.block_first_seen)}
    Remove-Item $statePath -Force
    Write-Output "Local security completion rolled back; restart required for Credential Guard state change";exit 0
}
if(Test-Path $statePath){throw "A local security completion transaction already exists."}
New-Item -ItemType Directory -Force -Path $root|Out-Null
& icacls.exe $root /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"|Out-Null
if($LASTEXITCODE-ne0){throw "Could not secure completion state."}
$before=Snapshot
[ordered]@{schema='AIShieldLocalSecurityBackup/1';created_utc=[DateTime]::UtcNow.ToString('o');
    enable_vbs=$before.enable_vbs;lsa_cfg_flags=$before.lsa_cfg_flags;maps_reporting=$before.maps_reporting;
    sample_consent=$before.sample_consent;block_first_seen=$before.block_first_seen}|ConvertTo-Json -Depth 4|
    Set-Content -LiteralPath $statePath -Encoding UTF8
if(-not(Test-Path $deviceGuardPath)){New-Item -Path $deviceGuardPath|Out-Null}
Set-ItemProperty -Path $deviceGuardPath -Name EnableVirtualizationBasedSecurity -Value 1
if(-not(Test-Path $lsaPath)){New-Item -Path $lsaPath|Out-Null}
Set-ItemProperty -Path $lsaPath -Name LsaCfgFlags -Value 2
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendSafeSamples
Set-MpPreference -DisableBlockAtFirstSeen $false
$after=Snapshot
[ordered]@{action='local-security-completion-applied';credential_guard='enabled_without_uefi_lock_pending_restart';
    defender_cloud=$after;rollback=$statePath}|ConvertTo-Json -Depth 5
