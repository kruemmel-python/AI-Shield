param(
    [ValidateSet("status","set")][string]$Action="status",
    [ValidateSet("hvci","credential_guard")][string]$Setting="hvci",
    [ValidateSet("true","false")][string]$Enabled="true"
)

$ErrorActionPreference="Stop"
$stateRoot=Join-Path $env:ProgramData "AIShield\private-desktop"
$statePath=Join-Path $stateRoot "security-settings.json"
$deviceGuardPath="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$hvciPath=Join-Path $deviceGuardPath "Scenarios\HypervisorEnforcedCodeIntegrity"
$lsaPath="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
function Read-Value([string]$Path,[string]$Name){$item=Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue;if($null-eq$item){return $null};return $item.$Name}
function Read-State {if(Test-Path -LiteralPath $statePath){$value=Get-Content $statePath -Raw|ConvertFrom-Json;if($value.schema-ne"AIShieldPrivateSecuritySettings/1"){throw "Invalid UI security state."};return $value};return [pscustomobject]@{schema="AIShieldPrivateSecuritySettings/1";hvci_backup=$null;credential_guard_backup=$null}}
function Write-State($State){New-Item -ItemType Directory -Force -Path $stateRoot|Out-Null;& icacls.exe $stateRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"|Out-Null;if($LASTEXITCODE-ne0){throw "Could not secure UI state."};$temporary="$statePath.$PID.tmp";[IO.File]::WriteAllText($temporary,($State|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false));Move-Item $temporary $statePath -Force}
function Get-Status {
    $dg=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    $hvciConfigured=(Read-Value $hvciPath "Enabled")-eq1
    $cgConfigured=(Read-Value $lsaPath "LsaCfgFlags")-in@(1,2)
    [ordered]@{schema="AIShieldPrivateSecurityStatus/1";hvci_configured=$hvciConfigured;
        hvci_running=($null-ne$dg-and@($dg.SecurityServicesRunning)-contains2);
        credential_guard_configured=$cgConfigured;
        credential_guard_running=($null-ne$dg-and@($dg.SecurityServicesRunning)-contains1);
        restart_required=(($hvciConfigured-ne($null-ne$dg-and@($dg.SecurityServicesRunning)-contains2))-or
            ($cgConfigured-ne($null-ne$dg-and@($dg.SecurityServicesRunning)-contains1)))}
}
if($Action-eq"status"){Get-Status|ConvertTo-Json -Compress;exit 0}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw "Changing Windows isolation requires elevation."}
$enable=$Enabled-eq"true";$state=Read-State
if($Setting-eq"hvci"){
    if($enable){
        if($null-eq$state.hvci_backup){$state.hvci_backup=[ordered]@{vbs=Read-Value $deviceGuardPath "EnableVirtualizationBasedSecurity";enabled=Read-Value $hvciPath "Enabled";locked=Read-Value $hvciPath "Locked"}}
        New-Item -Path $hvciPath -Force|Out-Null;Set-ItemProperty $deviceGuardPath EnableVirtualizationBasedSecurity 1;Set-ItemProperty $hvciPath Enabled 1;Set-ItemProperty $hvciPath Locked 0
    }else{
        if($null-eq$state.hvci_backup){throw "HVCI was not enabled by this UI and will not be disabled automatically."}
        if($null-eq$state.hvci_backup.enabled){Remove-ItemProperty $hvciPath Enabled -ErrorAction SilentlyContinue}else{Set-ItemProperty $hvciPath Enabled ([int]$state.hvci_backup.enabled)}
        if($null-eq$state.hvci_backup.locked){Remove-ItemProperty $hvciPath Locked -ErrorAction SilentlyContinue}else{Set-ItemProperty $hvciPath Locked ([int]$state.hvci_backup.locked)}
        $state.hvci_backup=$null
    }
}else{
    if($enable){
        if($null-eq$state.credential_guard_backup){$state.credential_guard_backup=[ordered]@{vbs=Read-Value $deviceGuardPath "EnableVirtualizationBasedSecurity";lsa=Read-Value $lsaPath "LsaCfgFlags"}}
        New-Item -Path $deviceGuardPath -Force|Out-Null;New-Item -Path $lsaPath -Force|Out-Null;Set-ItemProperty $deviceGuardPath EnableVirtualizationBasedSecurity 1;Set-ItemProperty $lsaPath LsaCfgFlags 2
    }else{
        if($null-eq$state.credential_guard_backup){throw "Credential Guard was not enabled by this UI and will not be disabled automatically."}
        if($null-eq$state.credential_guard_backup.lsa){Remove-ItemProperty $lsaPath LsaCfgFlags -ErrorAction SilentlyContinue}else{Set-ItemProperty $lsaPath LsaCfgFlags ([int]$state.credential_guard_backup.lsa)}
        $state.credential_guard_backup=$null
    }
}
Write-State $state
$status=Get-Status;$status["changed"]=$Setting;$status["requested"]=$enable;$status|ConvertTo-Json -Compress
