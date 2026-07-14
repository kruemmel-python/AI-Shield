param(
    [string]$OutputPath = "",
    [switch]$FailOnCritical
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repo "runtime\security-posture.json"
}

function Read-RegistryValue([string]$Path, [string]$Name) {
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Add-Check([Collections.Generic.List[object]]$Checks, [string]$Id, [string]$Severity,
                   [bool]$Passed, [string]$Observed, [string]$Remediation) {
    $Checks.Add([ordered]@{ id=$Id; severity=$Severity; passed=$Passed; observed=$Observed;
        remediation=$Remediation })
}

$checks = [Collections.Generic.List[object]]::new()
$secureBootValue = Read-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled"
$secureBoot = if ($null -eq $secureBootValue) { $null } else { $secureBootValue -eq 1 }
Add-Check $checks "secure_boot" "critical" ($secureBoot -eq $true) `
    $(if ($null -eq $secureBoot) { "unsupported_or_unavailable" } else { [string]$secureBoot }) `
    "Use Microsoft-signed production drivers and enable Secure Boot after prototype qualification."

$startOptions = [string](Read-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control" "SystemStartOptions")
$testSigning = $startOptions -match '(?i)(^|\s)TESTSIGNING(\s|$)'
Add-Check $checks "test_signing_disabled" "critical" (-not $testSigning) ([string]$testSigning) `
    "Disable TESTSIGNING only after installing Microsoft-signed AI Shield drivers."

$tpm = Get-Tpm -ErrorAction SilentlyContinue
$tpmReady = $null -ne $tpm -and $tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled
$tpmObserved = if ($null -eq $tpm) { "unavailable" } else {
    "present=$($tpm.TpmPresent);ready=$($tpm.TpmReady);enabled=$($tpm.TpmEnabled)"
}
$integrations = Join-Path $repo "build_vs\Release\ai_shield_integrations.exe"
$anchorStatus = "unavailable"
if (Test-Path -LiteralPath $integrations) {
    $candidate = (& $integrations tpm-status 2>$null) -join ';'
    if ($LASTEXITCODE -eq 0) {
        $anchorStatus = $candidate
        if (-not $tpmReady -and $anchorStatus -match 'provider=1' -and
            $anchorStatus -match 'hardware=1') {
            $tpmReady = $true
            $tpmObserved = $anchorStatus
        }
    }
}
Add-Check $checks "tpm_ready" "high" $tpmReady `
    $tpmObserved `
    "Enable and provision TPM 2.0 in UEFI and Windows."
$anchorReady = $anchorStatus -match 'key=1'
Add-Check $checks "ai_shield_tpm_anchor" "high" $anchorReady $anchorStatus `
    "Provision the AI Shield TPM anchor from an elevated deployment; non-administrative queries may not see the machine key."

$deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
    -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$hvci = $null -ne $deviceGuard -and @($deviceGuard.SecurityServicesRunning) -contains 2
$credentialGuard = $null -ne $deviceGuard -and @($deviceGuard.SecurityServicesRunning) -contains 1
Add-Check $checks "hvci_memory_integrity" "critical" $hvci ([string]$hvci) `
    "Enable Memory Integrity only after driver compatibility testing and a recovery plan."
Add-Check $checks "credential_guard" "high" $credentialGuard ([string]$credentialGuard) `
    "Enable Credential Guard through supported Windows security policy after compatibility testing."
$availableSecurity = @($(if($null-ne$deviceGuard){$deviceGuard.AvailableSecurityProperties}else{@()}))
$runningSecurity = @($(if($null-ne$deviceGuard){$deviceGuard.SecurityServicesRunning}else{@()}))
Add-Check $checks "kernel_dma_protection_capability" "high" ($availableSecurity -contains 3) `
    ("available="+($availableSecurity-join',')) `
    "Enable firmware virtualization and Kernel DMA Protection on supported hardware."
Add-Check $checks "system_guard_secure_launch" "high" ($runningSecurity -contains 3) `
    ("running="+($runningSecurity-join',')) `
    "Use Secure Boot, TPM 2.0 and supported DRTM firmware, then enable System Guard Secure Launch."
Add-Check $checks "smm_firmware_measurement" "medium" ($runningSecurity -contains 4) `
    ("running="+($runningSecurity-join',')) `
    "Use firmware and hardware that expose SMM firmware measurement to Windows System Guard."
Add-Check $checks "kernel_stack_protection" "medium" `
    ($runningSecurity -contains 5 -or $runningSecurity -contains 6) `
    ("running="+($runningSecurity-join',')) `
    "Enable hardware-enforced kernel-mode stack protection after driver compatibility validation."

$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$defenderActive = $null -ne $defender -and $defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled
Add-Check $checks "defender_realtime" "critical" $defenderActive `
    $(if ($null -eq $defender) { "unavailable_or_third_party_av" } else { "av=$($defender.AntivirusEnabled);realtime=$($defender.RealTimeProtectionEnabled)" }) `
    "Enable Microsoft Defender real-time protection or verify the registered third-party EDR."
$tamperProtected = $null -ne $defender -and $defender.IsTamperProtected
Add-Check $checks "defender_tamper_protection" "high" $tamperProtected ([string]$tamperProtected) `
    "Enable Defender Tamper Protection through Windows Security or centrally managed policy."

$firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
$firewallActive = $firewallProfiles.Count -ge 3 -and @($firewallProfiles | Where-Object { -not $_.Enabled }).Count -eq 0
Add-Check $checks "windows_firewall" "critical" $firewallActive `
    $(if ($firewallProfiles.Count -eq 0) { "unavailable" } else { ($firewallProfiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ';' }) `
    "Enable Windows Firewall for Domain, Private and Public profiles."

$blocklist = Read-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable"
Add-Check $checks "vulnerable_driver_blocklist" "high" ($blocklist -eq 1) ([string]$blocklist) `
    "Enable the Microsoft vulnerable driver blocklist after compatibility validation."

$asrRules = @{}
$preferences = Get-MpPreference -ErrorAction SilentlyContinue
if ($null -ne $preferences) {
    $asrIds = @($preferences.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
    $asrActions = @($preferences.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    for ($i=0; $i -lt $asrIds.Count -and $i -lt $asrActions.Count; $i++) {
        $asrRules[[string]$asrIds[$i]] = [int]$asrActions[$i]
    }
}
$asrEnabled = @($asrRules.Values | Where-Object { $_ -eq 1 }).Count
$asrAudited = @($asrRules.Values | Where-Object { $_ -eq 2 }).Count
Add-Check $checks "asr_enforced_rules" "medium" ($asrEnabled -gt 0) ("enabled={0};configured={1}" -f $asrEnabled,$asrRules.Count) `
    "Deploy Microsoft-recommended ASR rules in audit mode first, then enforce measured low-noise rules."
Add-Check $checks "asr_audit_coverage" "medium" ($asrAudited -gt 0) `
    ("audit={0};configured={1}" -f $asrAudited,$asrRules.Count) `
    "Keep the audit baseline active until representative compatibility and false-positive evidence exists."
$networkProtection = if ($null -eq $preferences) { 0 } else { [int]$preferences.EnableNetworkProtection }
$controlledFolders = if ($null -eq $preferences) { 0 } else { [int]$preferences.EnableControlledFolderAccess }
$puaProtection = if ($null -eq $preferences) { 0 } else { [int]$preferences.PUAProtection }
$cloudReporting = if ($null -eq $preferences) { 0 } else { [int]$preferences.MAPSReporting }
Add-Check $checks "defender_network_protection" "high" ($networkProtection -in @(1,2)) ([string]$networkProtection) `
    "Stage Defender Network Protection in audit mode and enforce it after compatibility measurement."
Add-Check $checks "controlled_folder_access" "medium" ($controlledFolders -in @(1,2)) ([string]$controlledFolders) `
    "Stage Controlled Folder Access in audit mode before enforcement."
Add-Check $checks "pua_protection" "medium" ($puaProtection -in @(1,2)) ([string]$puaProtection) `
    "Enable potentially unwanted application protection in audit or enforcement mode."
Add-Check $checks "defender_cloud_reporting" "medium" ($cloudReporting -gt 0) ([string]$cloudReporting) `
    "Enable Defender cloud-delivered protection according to the organization's privacy policy."

$bitLocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object VolumeType -eq 'OperatingSystem')
$bitLockerActive = $bitLocker.Count -gt 0 -and $bitLocker[0].ProtectionStatus -eq 'On'
Add-Check $checks "os_volume_encryption" "high" $bitLockerActive `
    $(if ($bitLocker.Count -eq 0) { "unavailable" } else { [string]$bitLocker[0].ProtectionStatus }) `
    "Enable BitLocker or equivalent full-volume encryption and escrow the recovery key."

$lsaPpl = Read-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
Add-Check $checks "lsa_protected_process" "high" ($lsaPpl -in @(1,2)) ([string]$lsaPpl) `
    "Enable LSA protection after validating authentication packages and recovery access."
$enableLua = Read-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$uacPrompt = Read-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
Add-Check $checks "uac_admin_consent" "critical" ($enableLua -eq 1 -and $uacPrompt -ne 0) `
    "EnableLUA=$enableLua;ConsentPromptBehaviorAdmin=$uacPrompt" `
    "Keep UAC enabled and require consent or credentials for administrator elevation."

$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
$smb1Disabled = $null -ne $smb -and -not $smb.EnableSMB1Protocol
Add-Check $checks "smb1_disabled" "high" $smb1Disabled `
    $(if ($null -eq $smb) { "unavailable" } else { [string]$smb.EnableSMB1Protocol }) `
    "Disable SMB1 and remove the optional SMB1 feature after compatibility validation."
$nla = Read-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
Add-Check $checks "rdp_network_level_authentication" "high" ($nla -eq 1) ([string]$nla) `
    "Require Network Level Authentication wherever Remote Desktop is enabled."

$scriptBlock = Read-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$moduleLog = Read-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
Add-Check $checks "powershell_script_block_logging" "medium" ($scriptBlock -eq 1) ([string]$scriptBlock) `
    "Enable protected central collection of PowerShell Script Block Logging."
Add-Check $checks "powershell_module_logging" "medium" ($moduleLog -eq 1) ([string]$moduleLog) `
    "Enable selected PowerShell Module Logging and forward the event channel externally."

$services = @(Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker' OR Name='AIShieldCore'" `
    -ErrorAction SilentlyContinue)
$secureServiceRoot = ([IO.Path]::Combine($env:ProgramFiles, "AIShield", "bin") + "\").ToLowerInvariant()
$secureServices = $services.Count -eq 2 -and @($services | Where-Object {
    $path = ([string]$_.PathName).Trim('"').ToLowerInvariant()
    -not $path.StartsWith($secureServiceRoot)
}).Count -eq 0
Add-Check $checks "ai_shield_secure_service_path" "critical" $secureServices `
    $(if ($services.Count -eq 0) { "services_unavailable" } else { ($services | ForEach-Object { "$($_.Name)=$($_.PathName)" }) -join ';' }) `
    "Reinstall Broker and Core so binaries run from the ACL-protected Program Files directory."

$browserHost=Join-Path $env:ProgramFiles "AIShield\browser\ai_shield_browser_host.exe"
$browserChromeRegistry=Get-Item "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\de.ai_shield.browser" `
    -ErrorAction SilentlyContinue
$browserEdgeRegistry=Get-Item "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\de.ai_shield.browser" `
    -ErrorAction SilentlyContinue
$browserExtension=Join-Path $env:ProgramFiles "AIShield\browser\extension\manifest.json"
$browserHostPresent=Test-Path -LiteralPath $browserHost -ErrorAction SilentlyContinue
$browserSignature=if($browserHostPresent){Get-AuthenticodeSignature $browserHost}else{$null}
$browserReady=$null-ne$browserChromeRegistry-and$null-ne$browserEdgeRegistry-and
    (Test-Path -LiteralPath $browserExtension -ErrorAction SilentlyContinue)-and
    $null-ne$browserSignature-and$browserSignature.Status-eq'Valid'
Add-Check $checks "signed_browser_sensor" "medium" $browserReady `
    $(if(-not$browserHostPresent){"not_installed"}else{"signature=$($browserSignature.Status);chrome=$($null-ne$browserChromeRegistry);edge=$($null-ne$browserEdgeRegistry)"}) `
    "Install the managed extension and its publisher-pinned signed Native Messaging host."
$wefState=Join-Path $env:ProgramData "AIShield\wef\collector-state.json"
$wefTask=Get-ScheduledTask -TaskName "AIShieldWefPinValidation" -ErrorAction SilentlyContinue
$wefStatePresent=Test-Path -LiteralPath $wefState -ErrorAction SilentlyContinue
Add-Check $checks "pinned_wef_forwarding" "high" ($wefStatePresent-and$null-ne$wefTask) `
    $(if($wefStatePresent){"configured"}else{"not_configured"}) `
    "Configure an HTTPS Windows Event Collector and pin its SHA-256 certificate identity."
$wdacStatePath=Join-Path $env:ProgramData "AIShield\wdac\state.json"
$wdacState=if(Test-Path $wdacStatePath -ErrorAction SilentlyContinue){
    Get-Content $wdacStatePath -Raw -ErrorAction SilentlyContinue|ConvertFrom-Json}else{$null}
Add-Check $checks "wdac_audit_policy" "medium" ($null-ne$wdacState-and$wdacState.deployed-eq$true) `
    $(if($null-eq$wdacState){"not_configured"}else{"deployed=$($wdacState.deployed)"}) `
    "Deploy the AI Shield WDAC policy in audit mode and evaluate Code Integrity event 3076."
$psPrivacyState=Join-Path $env:ProgramData "AIShield\powershell-logging\state.json"
$psTask=Get-ScheduledTask -TaskName "AIShieldPowerShellPrivacyForwarder" -ErrorAction SilentlyContinue
$psPrivacyStatePresent=Test-Path -LiteralPath $psPrivacyState -ErrorAction SilentlyContinue
Add-Check $checks "powershell_privacy_forwarding" "medium" ($psPrivacyStatePresent-and$null-ne$psTask) `
    $(if($psPrivacyStatePresent){"configured"}else{"not_configured"}) `
    "Configure a pinned HTTPS endpoint for metadata-only PowerShell event forwarding."

$criticalFailures = @($checks | Where-Object { $_.severity -eq 'critical' -and -not $_.passed }).Count
$report = [ordered]@{
    schema = "AIShieldSecurityPosture/1"
    generated_utc = [DateTime]::UtcNow.ToString('o')
    computer = $env:COMPUTERNAME
    critical_failures = $criticalFailures
    passed = @($checks | Where-Object passed).Count
    total = $checks.Count
    checks = $checks
}
$json = $report | ConvertTo-Json -Depth 6
$directory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $directory | Out-Null
$temporary = "$OutputPath.$PID.tmp"
[IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
$digest = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
[IO.File]::WriteAllText("$OutputPath.sha256", "$digest  $([IO.Path]::GetFileName($OutputPath))`r`n",
    [Text.ASCIIEncoding]::new())
Write-Output ("security posture: passed={0}/{1} critical_failures={2}" -f $report.passed,$report.total,$criticalFailures)
Write-Output "report: $OutputPath"
if ($FailOnCritical -and $criticalFailures -gt 0) { exit 3 }
