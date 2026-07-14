# CodeDump for Project: `AI_Shield_Private_Desktop.zip`

_Generated on 2026-07-13T09:31:45.538Z_

No LLM call was made. Token/cost values are offline estimates only.

LLM Code Review Mode is enabled: generated/vendor/report/lockfile noise is filtered across languages.

## Repository Map

```text
.
└── AI_Shield_Private_Desktop/
    ├── platform/
    │   └── windows/
    │       ├── admin/
    │       │   └── ai_shield_admin.ps1
    │       ├── firewall/
    │       │   └── firewall_baseline.ps1
    │       ├── installer/
    │       │   ├── install_broker.ps1
    │       │   ├── install_core_service.ps1
    │       │   ├── install_drivers.ps1
    │       │   ├── uninstall_drivers.ps1
    │       │   └── uninstall_product.ps1
    │       ├── policy/
    │       │   └── ai_shield_policy.ps1
    │       ├── security/
    │       │   ├── defender_audit_baseline.ps1
    │       │   └── system_security_posture.ps1
    │       ├── protect_system.ps1
    │       └── stop_ai_shield.ps1
    ├── ui/
    │   ├── AIShield.PrivateDesktop.UI.xaml
    │   ├── private_security_settings.ps1
    │   ├── README.md
    │   ├── start_private_ui.ps1
    │   └── verify_ui_contract.ps1
    ├── AI_Shield_UI.cmd
    ├── Deinstallieren.cmd
    ├── edition.json
    ├── install_private_desktop.ps1
    ├── Installieren.cmd
    ├── PACKAGE_MANIFEST.json
    ├── private_common.ps1
    ├── private_posture.ps1
    ├── QUALIFIKATIONSSTATUS.md
    ├── README.md
    ├── RELEASE_CONTRACT.json
    ├── Schutz_beenden.cmd
    ├── Schutz_starten.cmd
    ├── SOFTWAREBEWERTUNG_PRIVAT.md
    ├── start_private_desktop.ps1
    ├── Status_anzeigen.cmd
    ├── status_private_desktop.ps1
    ├── stop_private_desktop.ps1
    └── uninstall_private_desktop.ps1
```

## File: `AI_Shield_Private_Desktop/README.md`  
- Path: `AI_Shield_Private_Desktop/README.md`  
- Size: 5478 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```markdown
# AI Shield Private Desktop

Release Candidate: `2.0.0-rc.2`. ABI-, Policy- und Funktionsumfang sind durch
[`RELEASE_CONTRACT.json`](RELEASE_CONTRACT.json) eingefroren. Änderungen an sicherheitsrelevanten
Verträgen werden von `validate_release_freeze.ps1` abgelehnt, bis ein bewusst neuer Vertrag erstellt
wird.

Ein installierbares RC-Paket darf nur aus dem frisch gebauten und anschließend testsignierten
Treiber-Staging erzeugt werden. `tools\complete_private_rc_admin.ps1` führt dieses erhöhte Gate aus;
der Packager lehnt unsignierte Treiber ab.

## Ziel dieser Edition

Diese Edition richtet sich ausschließlich an private Windows-Nutzer mit einem einzelnen PC. Sie
verwendet die gemeinsame AI-Shield-Sicherheitsengine, enthält im Bedien- und Auslieferungspaket aber
keine zentralen Collector-, Flottenverwaltungs- oder SOC-Funktionen. Ein Webserver, Test-Backend oder
freier Listener-Port ist für den normalen Schutzbetrieb nicht erforderlich.

Der Standardstart aktiviert:

- IPv4-/IPv6-WFP-Telemetrie und den lokalen Wurm-Egress-Schutz;
- Minifilter-Provenance und Quarantäneschutz;
- ProcessGuard gegen ausgewählte riskante Prozessketten;
- Broker, Core-Überwachung und signierte lokale Policy;
- Blockierung von Ausführung aus Quarantäne und Benutzer-Temp;
- Regeln gegen riskante Skriptbefehle und Office-Kindprozesse.

Die Installation aktiviert außerdem die Windows-Firewall mit `Inbound=Block` und `Outbound=Allow`
sowie Microsoft-Defender-, ASR-, Network-Protection- und Controlled-Folder-Access-Regeln im
Auditmodus. Vorherige Einstellungen werden gesichert und bei Deinstallation nur dann zurückgerollt,
wenn diese Edition die Transaktion selbst angelegt hat.

## Wichtige Prototypgrenze

Die aktuellen Treiber sind lokal testsigniert. Deshalb funktioniert diese Ausgabe nur mit
deaktiviertem Secure Boot und aktiviertem Windows-TESTSIGNING. Das ist für einen gewöhnlichen
privaten Produktiv-PC kein empfohlener Dauerzustand. Vor einer öffentlichen Endanwenderfreigabe
werden von Microsoft signierte Treiber benötigt; anschließend müssen Secure Boot aktiviert und
TESTSIGNING deaktiviert werden.

Für den lokalen Prototyptest muss zuerst im UEFI-Setup Secure Boot deaktiviert werden. Danach in
einer als Administrator gestarteten PowerShell ausführen und Windows neu starten:

```powershell
bcdedit.exe /set testsigning on
Restart-Computer
```

Falls Windows meldet, dass der Wert durch die Richtlinie für sicheres Starten geschützt ist, ist
Secure Boot noch aktiv. AI Shield umgeht diese Sperre nicht und ändert die Bootkonfiguration nicht
automatisch.

## Bedienung

1. Das vollständige Paket in einen lokalen Ordner entpacken.
2. `Installieren.cmd` doppelt anklicken und die UAC-Abfrage bestätigen.
   Nach der Installation startet die grafische Oberfläche automatisch und ist danach im Startmenü
   unter **AI Shield Private Desktop** erreichbar. Alternativ öffnet `AI_Shield_UI.cmd` die UI.
3. Nach erfolgreicher Installation mit `Status_anzeigen.cmd` prüfen, dass drei Treiber sowie Broker
   und Core laufen.
4. `Schutz_starten.cmd` aktiviert den Schutz nach einem manuellen Stopp erneut.
5. `Schutz_beenden.cmd` setzt die Policy in den Auditmodus und stoppt Sensoren und Broker.
6. `Deinstallieren.cmd` entfernt die Edition und rollt ihre eigenen Firewall-/Defender-Baselines
   zurück. Audit- und Quarantänedaten bleiben standardmäßig erhalten.

Die Oberfläche bietet fünf Bereiche für Status, Schutzschalter, Auditprüfung/-export, Quarantäne
und Windows-Sicherheit. HVCI und Credential Guard zeigen bei notwendigen Systemänderungen eine
Neustartschaltfläche. Nach Bestätigung startet Windows neu; bei der nächsten Anmeldung öffnet eine
einmalige erhöhte Aufgabe die UI wieder und liest den wirksamen Zustand ein. Details stehen in
[`ui\README.md`](ui/README.md).

Nach der Deinstallation kann der Testmodus in einer erhöhten PowerShell beendet werden:

```powershell
bcdedit.exe /set testsigning off
Restart-Computer
```

Anschließend Secure Boot im UEFI-Setup wieder aktivieren und den Status mit
`Confirm-SecureBootUEFI` prüfen. Diese Rückkehr zum normalen Windows-Vertrauensmodell ist für einen
privaten Alltags-PC wichtig.

Die Standardkonfiguration blockiert heruntergeladene Programme nicht pauschal und beschränkt
Browser nicht auf feste Ports. Diese Optionen sind in der UI einzeln schaltbar und zusätzlich per
PowerShell verfügbar:

```powershell
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -HardenDownloads
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -StrictBrowser
powershell -ExecutionPolicy Bypass -File .\start_private_desktop.ps1 -BlockUnsolicitedInbound
```

Diese Optionen können legitime Installations-, Browser-, VPN-, Spiele- oder Heimnetzfunktionen
beeinträchtigen und müssen einzeln getestet werden.

## Schutzgrenzen

AI Shield ergänzt Defender, Windows-Firewall, Updates, UAC, BitLocker und sichere Backups. Es ersetzt
diese Komponenten nicht. Der Prototyp garantiert keinen vollständigen Schutz gegen Kernel-Zero-Days,
bereits erlangte Administratorrechte, Schadcode in erlaubten verschlüsselten Verbindungen,
kompromittierte Firmware oder jede unbekannte Angriffstechnik.

Die technische Einzelplatzbewertung steht in
[`SOFTWAREBEWERTUNG_PRIVAT.md`](SOFTWAREBEWERTUNG_PRIVAT.md).
Der aktuelle Release-Candidate-Nachweis und seine noch offenen Gates stehen in
[`QUALIFIKATIONSSTATUS.md`](QUALIFIKATIONSSTATUS.md).

```

## File: `AI_Shield_Private_Desktop/ui/README.md`  
- Path: `AI_Shield_Private_Desktop/ui/README.md`  
- Size: 1633 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```markdown
# Grafische Oberfläche

`AI_Shield_UI.cmd` öffnet die lokale WPF-Oberfläche. Sie fordert Administratorrechte über UAC an,
weil Treiber, Dienste, signierte Policies und Windows-Sicherheitsfunktionen nicht mit normalen
Benutzerrechten verändert werden dürfen.

Die Oberfläche enthält fünf Ansichten:

- **Übersicht:** Zustand der drei Kernel-Treiber, des Brokers und des Core-Dienstes;
- **Schutzfunktionen:** Kernschutz sowie optionale Download-, Browser- und Inbound-Regeln;
- **Audit:** vorhandene Auditdateien anzeigen, kryptografisch prüfen und exportieren;
- **Quarantäne:** isolierte Dateien anzeigen und nur mit Zielpfad und Begründung freigeben;
- **Windows-Sicherheit:** HVCI, Credential Guard, Firewall- und Defender-Auditbaseline.

HVCI und Credential Guard werden transaktional verwaltet. Die UI sichert den vorherigen Registry-
Zustand und deaktiviert keine Einstellung, die sie nicht selbst aktiviert hat. Wenn Windows einen
Neustart benötigt, erscheint **Jetzt neu starten**. Vor dem Neustart wird eine einmalige, erhöhte
Anmeldeaufgabe registriert. Nach der Anmeldung öffnet sie die Oberfläche erneut, liest den
tatsächlichen Laufzeitstatus ein und entfernt sich selbst.

Firewall- und Defender-Schalter verwenden die vorhandenen Backup-/Rollback-Skripte. Die
Defender-Baseline bleibt bewusst im Auditmodus; die UI behauptet keine Durchsetzung, solange keine
Kompatibilitätsmessung und bewusste Freigabe für den Blockiermodus vorliegen.

Die statische UI-Vertragsprüfung kann ohne Systemänderung ausgeführt werden:

```powershell
powershell -NoProfile -STA -File .\ui\verify_ui_contract.ps1
```

```

## File: `AI_Shield_Private_Desktop/platform/windows/security/defender_audit_baseline.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/security/defender_audit_baseline.ps1`  
- Size: 4423 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [ValidateSet("inspect", "apply-audit", "rollback")]
    [string]$Action = "inspect",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$stateRoot = Join-Path $env:ProgramData "AIShield\hardening"
$backupPath = Join-Path $stateRoot "defender-audit-backup.json"
$recommendedAsr = @(
    "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b"
)

function Get-DefenderSnapshot {
    $preference = Get-MpPreference -ErrorAction Stop
    $rules = [ordered]@{}
    $ids = @($preference.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
    $actions = @($preference.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
    for ($i=0; $i -lt $ids.Count -and $i -lt $actions.Count; $i++) {
        $rules[[string]$ids[$i].ToLowerInvariant()] = [int]$actions[$i]
    }
    return [ordered]@{
        network_protection = [int]$preference.EnableNetworkProtection
        controlled_folder_access = [int]$preference.EnableControlledFolderAccess
        pua_protection = [int]$preference.PUAProtection
        cloud_block_level = [int]$preference.CloudBlockLevel
        sample_submission = [int]$preference.SubmitSamplesConsent
        asr_rules = $rules
    }
}

if ($Action -eq "inspect") {
    Get-DefenderSnapshot | ConvertTo-Json -Depth 5
    exit 0
}
if (-not $isAdmin) { throw "This action requires an elevated PowerShell." }
if (-not $ConfirmSystemChange) {
    throw "Use -ConfirmSystemChange after reviewing the audit-only changes and rollback procedure."
}

New-Item -ItemType Directory -Force -Path $stateRoot | Out-Null
& icacls.exe $stateRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure hardening state directory." }

if ($Action -eq "apply-audit") {
    if (Test-Path -LiteralPath $backupPath) {
        throw "An audit-baseline transaction already exists. Roll it back before applying another one."
    }
    $before = Get-DefenderSnapshot
    $added = @($recommendedAsr | Where-Object { -not $before.asr_rules.Contains($_) })
    [ordered]@{ schema="AIShieldDefenderAuditBackup/1"; created_utc=[DateTime]::UtcNow.ToString('o');
        before=$before; added_asr_rules=$added } | ConvertTo-Json -Depth 7 |
        Set-Content -LiteralPath $backupPath -Encoding UTF8
    foreach ($id in $added) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions 2
    }
    if ([int]$before.network_protection -eq 0) { Set-MpPreference -EnableNetworkProtection 2 }
    if ([int]$before.controlled_folder_access -eq 0) { Set-MpPreference -EnableControlledFolderAccess 2 }
    if ([int]$before.pua_protection -eq 0) { Set-MpPreference -PUAProtection 2 }
    $after = Get-DefenderSnapshot
    [ordered]@{ action="audit-baseline-applied"; backup=$backupPath; state=$after } | ConvertTo-Json -Depth 6
    exit 0
}

if (-not (Test-Path -LiteralPath $backupPath)) { throw "No Defender audit-baseline backup exists." }
$backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
if ($backup.schema -ne "AIShieldDefenderAuditBackup/1") { throw "Defender backup schema is invalid." }
$addedRules = @($backup.added_asr_rules | Where-Object { $null -ne $_ })
if ($addedRules.Count -gt 0) {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids $addedRules
}
Set-MpPreference -EnableNetworkProtection ([int]$backup.before.network_protection)
Set-MpPreference -EnableControlledFolderAccess ([int]$backup.before.controlled_folder_access)
Set-MpPreference -PUAProtection ([int]$backup.before.pua_protection)
$rolledBack = Get-DefenderSnapshot
Remove-Item -LiteralPath $backupPath -Force
[ordered]@{ action="audit-baseline-rolled-back"; state=$rolledBack } | ConvertTo-Json -Depth 6

```

## File: `AI_Shield_Private_Desktop/platform/windows/security/system_security_posture.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/security/system_security_posture.ps1`  
- Size: 13983 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
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
if (-not $tpmReady) {
    $integrations = Join-Path $repo "build_vs\Release\ai_shield_integrations.exe"
    if (Test-Path -LiteralPath $integrations) {
        $anchorStatus = (& $integrations tpm-status 2>$null) -join ';'
        if ($LASTEXITCODE -eq 0 -and $anchorStatus -match 'provider=1' -and
            $anchorStatus -match 'hardware=1') {
            $tpmReady = $true
            $tpmObserved = $anchorStatus
        }
    }
}
Add-Check $checks "tpm_ready" "high" $tpmReady `
    $tpmObserved `
    "Enable and provision TPM 2.0 in UEFI and Windows."
$anchorReady = $tpmObserved -match 'key=1'
Add-Check $checks "ai_shield_tpm_anchor" "high" $anchorReady $tpmObserved `
    "Provision the AI Shield TPM anchor from an elevated deployment; non-administrative queries may not see the machine key."

$deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
    -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$hvci = $null -ne $deviceGuard -and @($deviceGuard.SecurityServicesRunning) -contains 2
$credentialGuard = $null -ne $deviceGuard -and @($deviceGuard.SecurityServicesRunning) -contains 1
Add-Check $checks "hvci_memory_integrity" "critical" $hvci ([string]$hvci) `
    "Enable Memory Integrity only after driver compatibility testing and a recovery plan."
Add-Check $checks "credential_guard" "high" $credentialGuard ([string]$credentialGuard) `
    "Enable Credential Guard through supported Windows security policy after compatibility testing."

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
$browserRegistry=Get-Item "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\de.ai_shield.browser" `
    -ErrorAction SilentlyContinue
$browserHostPresent=Test-Path -LiteralPath $browserHost -ErrorAction SilentlyContinue
$browserSignature=if($browserHostPresent){Get-AuthenticodeSignature $browserHost}else{$null}
$browserReady=$null-ne$browserRegistry-and$null-ne$browserSignature-and$browserSignature.Status-eq'Valid'
Add-Check $checks "signed_browser_sensor" "medium" $browserReady `
    $(if(-not$browserHostPresent){"not_installed"}else{"signature=$($browserSignature.Status)"}) `
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

```

## File: `AI_Shield_Private_Desktop/AI_Shield_UI.cmd`  
- Path: `AI_Shield_Private_Desktop/AI_Shield_UI.cmd`  
- Size: 133 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0ui\start_private_ui.ps1"
if errorlevel 1 pause

```

## File: `AI_Shield_Private_Desktop/Deinstallieren.cmd`  
- Path: `AI_Shield_Private_Desktop/Deinstallieren.cmd`  
- Size: 134 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_private_desktop.ps1"
if errorlevel 1 pause

```

## File: `AI_Shield_Private_Desktop/edition.json`  
- Path: `AI_Shield_Private_Desktop/edition.json`  
- Size: 685 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```json
{
  "schema": "AIShieldEdition/1",
  "id": "private-desktop",
  "display_name": "AI Shield Private Desktop",
  "release": "2.0.0-rc.2",
  "target": "private Windows single-user workstation",
  "network_mode": "local dual-stack host protection",
  "gateway_enabled_by_default": false,
  "enterprise_connectors_included": false,
  "default_policy": {
    "mode": "enforce",
    "system_network_guard": true,
    "block_quarantine_execution": true,
    "block_user_temp_execution": true,
    "block_risky_script_command": true,
    "block_office_child_process": true,
    "block_download_execution": false,
    "block_unsolicited_inbound": false,
    "block_browser_non_web": false
  }
}

```

## File: `AI_Shield_Private_Desktop/install_private_desktop.ps1`  
- Path: `AI_Shield_Private_Desktop/install_private_desktop.ps1`  
- Size: 8084 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([switch]$SkipWindowsBaseline)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($SkipWindowsBaseline) { $forward += "-SkipWindowsBaseline" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}

$root = Get-AIShieldPrivateRoot
$driverctl = Join-Path $root "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $root "build_vs\Release\ai_shield_kernelctl.exe"
$package = Join-Path $root "driver_package\Release"
$certificate = Join-Path $package "ai_shield_testsigning.cer"
$installDrivers = Join-Path $root "platform\windows\installer\install_drivers.ps1"
$installBroker = Join-Path $root "platform\windows\installer\install_broker.ps1"
$installCore = Join-Path $root "platform\windows\installer\install_core_service.ps1"
$policyScript = Join-Path $root "platform\windows\policy\ai_shield_policy.ps1"
$markerRoot = Join-Path $env:ProgramData "AIShield\private-desktop"
$markerPath = Join-Path $markerRoot "install.json"
$uiLauncher = Join-Path $PSScriptRoot "AI_Shield_UI.cmd"

function Install-AIShieldPrivateUiShortcut {
    Assert-AIShieldFile $uiLauncher "Private desktop UI launcher"
    $shortcutDirectory = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AI Shield"
    New-Item -ItemType Directory -Force -Path $shortcutDirectory | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $shortcutDirectory "AI Shield Private Desktop.lnk"))
    $shortcut.TargetPath = $uiLauncher
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = "AI Shield Private Desktop öffnen"
    $shortcut.Save()
}

if (Test-Path -LiteralPath $markerPath) {
    $existingMarker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($existingMarker.schema -ne "AIShieldPrivateDesktopInstall/1" -or
        $existingMarker.installation_complete -ne $true) {
        throw "An incomplete or invalid private desktop installation exists. Run Deinstallieren.cmd before retrying."
    }
    Write-Output "AI Shield Private Desktop is already installed; activating protection."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start_private_desktop.ps1")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Install-AIShieldPrivateUiShortcut
    Start-Process -FilePath $uiLauncher
    exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) { throw "AI Shield Private Desktop requires 64-bit Windows." }
foreach ($required in @($driverctl, $kernelctl, $certificate, $installDrivers, $installBroker, $installCore,
        $policyScript, $uiLauncher, (Join-Path $PSScriptRoot "ui\start_private_ui.ps1"),
        (Join-Path $PSScriptRoot "ui\AIShield.PrivateDesktop.UI.xaml"),
        (Join-Path $package "AIShieldWfp.sys"),
        (Join-Path $package "AIShieldMiniFilter.sys"), (Join-Path $package "AIShieldProcessGuard.sys"))) {
    Assert-AIShieldFile $required "Required package file"
}

$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if (-not $?) { $secureBoot = $null }
$bootConfiguration = (& bcdedit.exe /enum "{current}" 2>$null) -join "`n"
$testSigning = $bootConfiguration -match '(?im)^testsigning\s+Yes\s*$'
if ($secureBoot -eq $true -or -not $testSigning) {
    throw ("The prototype drivers cannot be installed in the current boot configuration. " +
        "Secure Boot must be disabled and TESTSIGNING must be enabled for this local prototype. " +
        "Do not change either setting on a production PC. SecureBoot=$secureBoot TestSigning=$testSigning")
}

Write-Output "Installing AI Shield Private Desktop"
$certificateInfo = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
$certificateThumbprint = $certificateInfo.Thumbprint
$rootCertificatePath = "Cert:\LocalMachine\Root\$certificateThumbprint"
$publisherCertificatePath = "Cert:\LocalMachine\TrustedPublisher\$certificateThumbprint"
$rootCertificateOwned = -not (Test-Path -LiteralPath $rootCertificatePath)
$publisherCertificateOwned = -not (Test-Path -LiteralPath $publisherCertificatePath)
if ($rootCertificateOwned) {
    Import-Certificate -FilePath $certificate -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
}
if ($publisherCertificateOwned) {
    Import-Certificate -FilePath $certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}

New-Item -ItemType Directory -Force -Path $markerRoot | Out-Null
& icacls.exe $markerRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not protect the private edition state directory." }
$initialMarker = [ordered]@{
    schema = "AIShieldPrivateDesktopInstall/1"
    installed_utc = [DateTime]::UtcNow.ToString("o")
    installation_complete = $false
    certificate_thumbprint = $certificateThumbprint
    root_certificate_owned = $rootCertificateOwned
    publisher_certificate_owned = $publisherCertificateOwned
    firewall_transaction_owned = $false
    defender_transaction_owned = $false
    enterprise_connectors = $false
}
[IO.File]::WriteAllText($markerPath, ($initialMarker | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installDrivers -PackageDir $package
if ($LASTEXITCODE -ne 0) { throw "Driver installation failed with exit code $LASTEXITCODE." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installBroker
if ($LASTEXITCODE -ne 0) { throw "Broker installation failed with exit code $LASTEXITCODE." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installCore
if ($LASTEXITCODE -ne 0) { throw "Core service installation failed with exit code $LASTEXITCODE." }

$pin = Join-Path $env:ProgramData "AIShield\policy\signer.thumbprint"
if (-not (Test-Path -LiteralPath $pin)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action initialize
    if ($LASTEXITCODE -ne 0) { throw "Local policy trust initialization failed." }
}

$firewallApplied = $false
$defenderApplied = $false
if (-not $SkipWindowsBaseline) {
    $firewallScript = Join-Path $root "platform\windows\firewall\firewall_baseline.ps1"
    $firewallState = Join-Path $env:ProgramData "AIShield\firewall\state.json"
    if (-not (Test-Path -LiteralPath $firewallState)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $firewallScript `
            -Action apply -ConfirmSystemChange
        if ($LASTEXITCODE -ne 0) { throw "Windows Firewall baseline failed." }
        $firewallApplied = $true
    }
    $defenderScript = Join-Path $root "platform\windows\security\defender_audit_baseline.ps1"
    $defenderState = Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json"
    if (-not (Test-Path -LiteralPath $defenderState)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $defenderScript `
            -Action apply-audit -ConfirmSystemChange
        if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender audit baseline failed." }
        $defenderApplied = $true
    }
}

$marker = [ordered]@{
    schema = "AIShieldPrivateDesktopInstall/1"
    installed_utc = [DateTime]::UtcNow.ToString("o")
    installation_complete = $true
    certificate_thumbprint = $certificateThumbprint
    root_certificate_owned = $rootCertificateOwned
    publisher_certificate_owned = $publisherCertificateOwned
    firewall_transaction_owned = $firewallApplied
    defender_transaction_owned = $defenderApplied
    enterprise_connectors = $false
}
[IO.File]::WriteAllText($markerPath, ($marker | ConvertTo-Json -Depth 3),
    [Text.UTF8Encoding]::new($false))

Install-AIShieldPrivateUiShortcut

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start_private_desktop.ps1")
if ($LASTEXITCODE -ne 0) { throw "Private desktop protection could not be started." }
Write-Output "AI Shield Private Desktop is installed and active."
Start-Process -FilePath $uiLauncher

```

## File: `AI_Shield_Private_Desktop/Installieren.cmd`  
- Path: `AI_Shield_Private_Desktop/Installieren.cmd`  
- Size: 132 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_private_desktop.ps1"
if errorlevel 1 pause

```

## File: `AI_Shield_Private_Desktop/PACKAGE_MANIFEST.json`  
- Path: `AI_Shield_Private_Desktop/PACKAGE_MANIFEST.json`  
- Size: 12300 Bytes  
- Modified: 2026-07-13 12:00:00 UTC  
- Condensed: comments and repeated blank lines reduced

```json
{
    "schema":  "AIShieldPrivatePackage/1",
    "created_utc":  "2026-07-13T12:00:00.0000000Z",
    "edition":  "private-desktop",
    "release":  "2.0.0-rc.2",
    "files":  [
                  {
                      "path":  "AI_Shield_UI.cmd",
                      "bytes":  133,
                      "sha256":  "83CD9A71DC864E50F661069F1E98D1D591A92893C52D3BB44B93D4371C15F510"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_broker.exe",
                      "bytes":  135168,
                      "sha256":  "FB703EC210F4C6051FB42DE6D24D7A9CD94EEC4B755B6D25CE37483A0E769656"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_diag.exe",
                      "bytes":  61952,
                      "sha256":  "F0D6D2394786E908A6107479AF316EAB57ECF2DC4C2E7DFA46A414D73E5EB5BB"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_driverctl.exe",
                      "bytes":  33792,
                      "sha256":  "1C1E962F39DBB7F925AFDDD91644251AAF08BE5AF64B7AB384ADACE891D27B0F"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_integrations.exe",
                      "bytes":  47104,
                      "sha256":  "C7B9AF0435195299D26763E0628464AE64E99CBD0EE7F6AB93072998E3D7E74B"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_kernelctl.exe",
                      "bytes":  20992,
                      "sha256":  "3CF9F145DF27534C04C6548EC20182ECE3ADCAE04DF56D30F28D101CD8362A6C"
                  },
                  {
                      "path":  "build_vs/Release/ai_shield_service.exe",
                      "bytes":  57344,
                      "sha256":  "665D1A71BA9820F47E0A95D354B4C000205CAD20B750861F4CD7E786E4F031F3"
                  },
                  {
                      "path":  "Deinstallieren.cmd",
                      "bytes":  134,
                      "sha256":  "D02DE58B54AD8D184F4EB521A27A3018A2A3EA2BE20807E89B4221389C073981"
                  },
                  {
                      "path":  "driver_package/Release/ai_shield_minifilter.inf",
                      "bytes":  1198,
                      "sha256":  "84481D54EE01E75BD6F7DC90A722ACF160361DC4282235C5CDB27CDE89EF493F"
                  },
                  {
                      "path":  "driver_package/Release/ai_shield_process_guard.inf",
                      "bytes":  843,
                      "sha256":  "207385A5A42C91C9944B6E4A3178EF959FFE20B12BBD903C435166D60EE0A9D8"
                  },
                  {
                      "path":  "driver_package/Release/ai_shield_testsigning.cer",
                      "bytes":  1066,
                      "sha256":  "0CBE66066CE5BF21DBB9FD1FABE58E449D38F0817660BF423E82D878407C16C3"
                  },
                  {
                      "path":  "driver_package/Release/ai_shield_wfp.inf",
                      "bytes":  769,
                      "sha256":  "F75F5CC4EA953A28E44503CB72E7BD31F94AEFE9036B37E231AA1D287FB38405"
                  },
                  {
                      "path":  "driver_package/Release/AIShieldMiniFilter.sys",
                      "bytes":  25392,
                      "sha256":  "726735C5E7DA041B1557529CD4B8D41AF7F0D78AFCE0A2F06D159665F890786C"
                  },
                  {
                      "path":  "driver_package/Release/AIShieldProcessGuard.sys",
                      "bytes":  27440,
                      "sha256":  "9F3A68E68CA822044F8FF88C68F5546C4AE05F2EF23E2DED5F26FBA88C49B4D1"
                  },
                  {
                      "path":  "driver_package/Release/AIShieldWfp.sys",
                      "bytes":  26928,
                      "sha256":  "0820FABE84F09070BE37636851AFBD2DE4FF865CFBC800214E1A9EE80204F253"
                  },
                  {
                      "path":  "edition.json",
                      "bytes":  685,
                      "sha256":  "EBCEDFCF0B9542F15FE52497C9165C36E57387D505B9C9FB4DF98A285D1FC6BF"
                  },
                  {
                      "path":  "install_private_desktop.ps1",
                      "bytes":  8084,
                      "sha256":  "884BD71B968155C72A319888A35AD2DCB3DFB24C56E56609DDB04F7193B036A4"
                  },
                  {
                      "path":  "Installieren.cmd",
                      "bytes":  132,
                      "sha256":  "CC9B5F812FCAE16BE3AC1A474A3FDC6BC3D4D5180B6F17331E5B64DE704182EC"
                  },
                  {
                      "path":  "platform/windows/admin/ai_shield_admin.ps1",
                      "bytes":  2960,
                      "sha256":  "231D0A9F968C3EBF1ACD2BFA49958E4798D9D3ED8AE9053384F6D32654FF8B31"
                  },
                  {
                      "path":  "platform/windows/firewall/firewall_baseline.ps1",
                      "bytes":  3410,
                      "sha256":  "C4A8F693D87257D8DA72AD37F56245A3DDC09360C656C28635A3728B13B5105A"
                  },
                  {
                      "path":  "platform/windows/installer/install_broker.ps1",
                      "bytes":  3461,
                      "sha256":  "B47D0B7E30FC2A9FA385CB5D5FC438D83EC5E01BED555E8EC2D98001FEC04A2B"
                  },
                  {
                      "path":  "platform/windows/installer/install_core_service.ps1",
                      "bytes":  2664,
                      "sha256":  "F3C21DEC92528F7EA1A2B233CE8D53F3AF6651923963F2FD48555273629ECAD0"
                  },
                  {
                      "path":  "platform/windows/installer/install_drivers.ps1",
                      "bytes":  976,
                      "sha256":  "CA8F8C30409FDB67B2D5BC58FBF82FD180C58C60D4D4CE9690D08E801E6E6C77"
                  },
                  {
                      "path":  "platform/windows/installer/uninstall_drivers.ps1",
                      "bytes":  302,
                      "sha256":  "A766D870A3325A4A19E24404D7B349909A5F23FAC1C7FED0C32ED8AA3A6280A1"
                  },
                  {
                      "path":  "platform/windows/installer/uninstall_product.ps1",
                      "bytes":  2296,
                      "sha256":  "6867124CBC7DAED8297016CD792304302A7A933535C85F080AB642E6D7EE0647"
                  },
                  {
                      "path":  "platform/windows/policy/ai_shield_policy.ps1",
                      "bytes":  13067,
                      "sha256":  "3DF45C2079531FA47EFF458FCA04C66DB306C3B7286E7C02918727957D9B7E08"
                  },
                  {
                      "path":  "platform/windows/protect_system.ps1",
                      "bytes":  2998,
                      "sha256":  "155CE097528EE2A9FC51A7BC8B68F3B65AC84F89D3899BADB34E47CB00F9DC01"
                  },
                  {
                      "path":  "platform/windows/security/defender_audit_baseline.ps1",
                      "bytes":  4423,
                      "sha256":  "F091EF15EE730BF68253E9A266C7FE4628393F2D939DEC5690A125BEC39FDBB1"
                  },
                  {
                      "path":  "platform/windows/security/system_security_posture.ps1",
                      "bytes":  13983,
                      "sha256":  "9514484D67CF5AA5A732C1FA36DC7D3BBDEEB6AD8BB9FEEA51E614E727D98183"
                  },
                  {
                      "path":  "platform/windows/stop_ai_shield.ps1",
                      "bytes":  3249,
                      "sha256":  "B5B823E6E26248EDFEEBD39B6CFDB083A692871A791E4C8871D16FBAA92E6945"
                  },
                  {
                      "path":  "private_common.ps1",
                      "bytes":  1198,
                      "sha256":  "1AAA03CF18B74C894E6D2858A65AC3504A0AAA315C0E85DE6FAF2311EBAC0C3E"
                  },
                  {
                      "path":  "private_posture.ps1",
                      "bytes":  2661,
                      "sha256":  "B81E05349032963696ACD69EF2E74E98551FFDB7698D0596A4C15288D1819873"
                  },
                  {
                      "path":  "QUALIFIKATIONSSTATUS.md",
                      "bytes":  3951,
                      "sha256":  "DEEC8E45C82A6046DD038A21C4F21083F8C2C63BC4989B0E4D5A7459EAC16290"
                  },
                  {
                      "path":  "README.md",
                      "bytes":  5478,
                      "sha256":  "92BC6A2EFC0D97789C1B542FF13DB0753BBE9E950403ECDBBB6296B6269B1E71"
                  },
                  {
                      "path":  "RELEASE_CONTRACT.json",
                      "bytes":  3250,
                      "sha256":  "1FF921DF601DD4A702112EFE47096AE5E71CFD093CD0D98FD1341DB724245C55"
                  },
                  {
                      "path":  "Schutz_beenden.cmd",
                      "bytes":  129,
                      "sha256":  "EE566E7A3539EE2581F95F6E509BFBA3C853622C37D1292B766509BBD6C89505"
                  },
                  {
                      "path":  "Schutz_starten.cmd",
                      "bytes":  130,
                      "sha256":  "2DA445B3162DD81B686C400ABC3F80BBE75990F043236A2C9B4EED13296BB8C9"
                  },
                  {
                      "path":  "SOFTWAREBEWERTUNG_PRIVAT.md",
                      "bytes":  5642,
                      "sha256":  "39A4B2AE546B3BE22D3D24435731A071341B3BE4CE81173B4F32523C1B4BDB5C"
                  },
                  {
                      "path":  "start_private_desktop.ps1",
                      "bytes":  1177,
                      "sha256":  "C20D1F0FC1C428A45775BB90C785308F42DBBFF4B5529614D1856E036317300A"
                  },
                  {
                      "path":  "Status_anzeigen.cmd",
                      "bytes":  115,
                      "sha256":  "DC1FD3A4A061EEF3199B82B89821029DAAF262B26735174307274D773FAC264D"
                  },
                  {
                      "path":  "status_private_desktop.ps1",
                      "bytes":  586,
                      "sha256":  "40582B5275E23963B134F3852C25AAC9977C28C75B44A20B17AB19A589ACE470"
                  },
                  {
                      "path":  "stop_private_desktop.ps1",
                      "bytes":  400,
                      "sha256":  "8AA6CB9E8096BB3B7A3E6BBFDC10DA3A47236D892EE67BA8D229CEBE16384920"
                  },
                  {
                      "path":  "ui/AIShield.PrivateDesktop.UI.xaml",
                      "bytes":  11772,
                      "sha256":  "BA7A89DFA88544BAEC4D6713068E2ED27A3C3A8FFE7CEFA511BD5BB1CEDF25D8"
                  },
                  {
                      "path":  "ui/private_security_settings.ps1",
                      "bytes":  4594,
                      "sha256":  "8D7DB8B7FC81DF0C1B80E585B6A43806C8BF346E674694B6DE35554E1890699B"
                  },
                  {
                      "path":  "ui/README.md",
                      "bytes":  1633,
                      "sha256":  "D76D6792468762C3B69253DD0C5D6CDBF3FD6CD485841CF4883BD9CF10D83490"
                  },
                  {
                      "path":  "ui/start_private_ui.ps1",
                      "bytes":  13859,
                      "sha256":  "07285FEDD2CC486B01B4837B842A67E6F060CAF8E63F9407FC225828A8BD123F"
                  },
                  {
                      "path":  "ui/verify_ui_contract.ps1",
                      "bytes":  2326,
                      "sha256":  "7E24A83E4806AA1408499D85F1FC232694B26E189562435E660C89277D3F24BB"
                  },
                  {
                      "path":  "uninstall_private_desktop.ps1",
                      "bytes":  3069,
                      "sha256":  "EC1C6F25FE5F45E3899204E4782236E6B077A4486E803D2452E7B707FE50EB8D"
                  }
              ]
}

```

## File: `AI_Shield_Private_Desktop/platform/windows/admin/ai_shield_admin.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/admin/ai_shield_admin.ps1`  
- Size: 2960 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [ValidateSet("health", "runtime-status", "rotate-key", "safe-mode-reset", "quarantine-release",
                 "audit-export", "recover")]
    [string]$Action,
    [string]$ObjectId,
    [string]$Destination,
    [string]$Reason,
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$policy = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Action -eq "health") {
    $health = Join-Path $env:ProgramData "AIShield\health.json"
    if (-not (Test-Path -LiteralPath $health)) { throw "Core health state is unavailable." }
    Get-Content -LiteralPath $health -Raw | ConvertFrom-Json | Format-List
    Get-Service AIShieldCore, AIShieldBroker, AIShieldWfp, AIShieldMiniFilter, AIShieldProcessGuard |
        Select-Object Name, Status, StartType
    exit 0
}
if (-not $isAdmin) { throw "This administrative action requires an elevated PowerShell." }
switch ($Action) {
    "runtime-status" { & $broker runtime-status; exit $LASTEXITCODE }
    "rotate-key" {
        & $broker runtime-rotate-key
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Restart-Service AIShieldBroker -Force
        exit 0
    }
    "safe-mode-reset" { & sc.exe control AIShieldCore 128; exit $LASTEXITCODE }
    "quarantine-release" {
        if ($ObjectId -notmatch '^[A-Fa-f0-9]{64}$' -or -not $Destination -or $Reason.Length -lt 3) {
            throw "ObjectId, Destination and a reason of at least three characters are required."
        }
        & $broker quarantine-restore $ObjectId $Destination $Reason
        exit $LASTEXITCODE
    }
    "audit-export" {
        if (-not $OutputDirectory) { throw "OutputDirectory is required." }
        $source = Join-Path $env:ProgramData "AIShield\audit"
        $target = Join-Path $OutputDirectory ("AIShield-Audit-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ"))
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Get-ChildItem -LiteralPath $source -File | Copy-Item -Destination $target
        Get-ChildItem -LiteralPath $target -File | ForEach-Object {
            $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            [pscustomobject]@{ file = $_.Name; sha256 = $hash.Hash }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target "manifest.json") -Encoding UTF8
        Write-Output $target
        exit 0
    }
    "recover" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policy -Action recover
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Restart-Service AIShieldBroker -Force
        Restart-Service AIShieldCore -Force
        exit 0
    }
}

```

## File: `AI_Shield_Private_Desktop/platform/windows/firewall/firewall_baseline.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/firewall/firewall_baseline.ps1`  
- Size: 3410 Bytes  
- Modified: 2026-07-13 12:00:00 UTC  
- Condensed: comments and repeated blank lines reduced

```powershell
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

```

## File: `AI_Shield_Private_Desktop/platform/windows/installer/install_broker.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/installer/install_broker.ps1`  
- Size: 3461 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [ValidateSet("install", "uninstall")]
    [string]$Action = "install"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$brokerSource = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$installRoot = Join-Path $env:ProgramFiles "AIShield\bin"
$broker = Join-Path $installRoot "ai_shield_broker.exe"
$auditDir = Join-Path $env:ProgramData "AIShield\audit"
$quarantineDir = Join-Path $env:ProgramData "AIShield\quarantine"
$serviceName = "AIShieldBroker"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script from an elevated PowerShell."
}

if ($Action -eq "uninstall") {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -notin @(0, 1060)) { exit $LASTEXITCODE }
    Write-Output "uninstalled $serviceName"
    exit 0
}

if (-not (Test-Path -LiteralPath $brokerSource)) {
    throw "Broker executable not found: $brokerSource"
}

Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
& icacls.exe (Join-Path $env:ProgramFiles "AIShield") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure AI Shield installation directory." }
Copy-Item -LiteralPath $brokerSource -Destination $broker -Force
$sourceHash = (Get-FileHash -LiteralPath $brokerSource -Algorithm SHA256).Hash
$installedHash = (Get-FileHash -LiteralPath $broker -Algorithm SHA256).Hash
if ($sourceHash -ne $installedHash) { throw "Installed broker hash verification failed." }

New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
New-Item -ItemType Directory -Force -Path $quarantineDir | Out-Null
& icacls.exe (Split-Path $auditDir -Parent) /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure broker data directory." }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    & sc.exe config $serviceName binPath= ('"' + $broker + '"') start= delayed-auto obj= LocalSystem `
        depend= "AIShieldWfp/AIShieldMiniFilter/AIShieldProcessGuard" | Out-Null
} else {
    & sc.exe create $serviceName binPath= ('"' + $broker + '"') start= delayed-auto obj= LocalSystem `
        depend= "AIShieldWfp/AIShieldMiniFilter/AIShieldProcessGuard" `
        DisplayName= "AI Shield Kernel Telemetry Broker" | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Could not configure $serviceName." }
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure broker recovery." }
& sc.exe failureflag $serviceName 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure broker failure flag." }
& sc.exe sdset $serviceName "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure broker service control permissions." }
Start-Service -Name $serviceName
Write-Output "installed and started $serviceName"
Write-Output "binary: $broker sha256=$installedHash"
Write-Output "audit directory: $auditDir"

```

## File: `AI_Shield_Private_Desktop/platform/windows/installer/install_core_service.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/installer/install_core_service.ps1`  
- Size: 2664 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([ValidateSet("install", "uninstall")][string]$Action = "install")

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$binarySource = Join-Path $repo "build_vs\Release\ai_shield_service.exe"
$installRoot = Join-Path $env:ProgramFiles "AIShield\bin"
$binary = Join-Path $installRoot "ai_shield_service.exe"
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Core service installation requires an elevated PowerShell."
}

if ($Action -eq "uninstall") {
    Stop-Service AIShieldCore -Force -ErrorAction SilentlyContinue
    & sc.exe delete AIShieldCore | Out-Null
    Write-Output "uninstalled AIShieldCore"
    exit 0
}
if (-not (Test-Path -LiteralPath $binarySource)) { throw "Core service binary not found: $binarySource" }
Stop-Service AIShieldCore -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
& icacls.exe (Join-Path $env:ProgramFiles "AIShield") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure AI Shield installation directory." }
Copy-Item -LiteralPath $binarySource -Destination $binary -Force
$sourceHash = (Get-FileHash -LiteralPath $binarySource -Algorithm SHA256).Hash
$installedHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
if ($sourceHash -ne $installedHash) { throw "Installed core service hash verification failed." }
$existing = Get-Service AIShieldCore -ErrorAction SilentlyContinue
if ($existing) {
    & sc.exe config AIShieldCore binPath= ('"' + $binary + '"') start= delayed-auto obj= LocalSystem `
        depend= "AIShieldBroker" | Out-Null
} else {
    & sc.exe create AIShieldCore binPath= ('"' + $binary + '"') start= delayed-auto obj= LocalSystem `
        depend= "AIShieldBroker" DisplayName= "AI Shield Core Orchestrator" | Out-Null
}
& sc.exe failure AIShieldCore reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure core recovery." }
& sc.exe failureflag AIShieldCore 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not configure core failure flag." }
& sc.exe sdset AIShieldCore "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure core service control permissions." }
Start-Service AIShieldCore
Write-Output "installed AIShieldCore"
Write-Output "binary: $binary sha256=$installedHash"

```

## File: `AI_Shield_Private_Desktop/platform/windows/installer/install_drivers.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/installer/install_drivers.ps1`  
- Size: 976 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [Parameter(Mandatory=$true)][string]$PackageDir
)

$ErrorActionPreference = "Stop"
$driverctl = Join-Path $PSScriptRoot "..\..\..\build_vs\Release\ai_shield_driverctl.exe"
$wfp = Join-Path $PackageDir "AIShieldWfp.sys"
$mini = Join-Path $PackageDir "AIShieldMiniFilter.sys"
$proc = Join-Path $PackageDir "AIShieldProcessGuard.sys"

$secureBoot = $null
$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if (-not $?) {
    $secureBoot = $null
}
$testSigning = (& bcdedit.exe /enum "{current}") -match "testsigning\s+Yes"
if ($secureBoot -eq $true -or -not $testSigning) {
    Write-Output "Driver load preflight failed:"
    Write-Output "  SecureBoot=$secureBoot"
    Write-Output "  TestSigning=$testSigning"
    Write-Output "Local test-signed kernel drivers require TESTSIGNING=Yes and Secure Boot disabled."
}

& $driverctl install --wfp $wfp --minifilter $mini --process $proc
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $driverctl start

```

## File: `AI_Shield_Private_Desktop/platform/windows/installer/uninstall_drivers.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/installer/uninstall_drivers.ps1`  
- Size: 302 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
$ErrorActionPreference = "Stop"
$driverctl = Join-Path $PSScriptRoot "..\..\..\build_vs\Release\ai_shield_driverctl.exe"
Stop-Service -Name "AIShieldBroker" -Force -ErrorAction SilentlyContinue
& $driverctl stop
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $driverctl uninstall
exit $LASTEXITCODE

```

## File: `AI_Shield_Private_Desktop/platform/windows/installer/uninstall_product.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/installer/uninstall_product.ps1`  
- Size: 2296 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [Parameter(Mandatory=$true)][ValidateSet("UNINSTALL-AI-SHIELD")][string]$Confirmation,
    [string]$AuditExportDirectory,
    [switch]$PurgeSecurityData
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uninstall requires an elevated PowerShell."
}
if ($AuditExportDirectory) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\admin\ai_shield_admin.ps1") `
        -Action audit-export -OutputDirectory $AuditExportDirectory
    if ($LASTEXITCODE -ne 0) { throw "Mandatory audit export failed; uninstall stopped." }
}
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
if (Test-Path $kernelctl) { & $kernelctl audit }
Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_core_service.ps1") -Action uninstall
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\install_broker.ps1") -Action uninstall
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AIShield"))
$expectedInstallRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\AIShield'
if ($installRoot -ne $expectedInstallRoot) { throw "Installation path validation failed." }
if (Test-Path -LiteralPath $installRoot) { Remove-Item -LiteralPath $installRoot -Recurse -Force }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "platform\windows\installer\uninstall_drivers.ps1")
if ($LASTEXITCODE -ne 0) { throw "Driver removal failed; security data was preserved." }
if ($PurgeSecurityData) {
    $data = [IO.Path]::GetFullPath((Join-Path $env:ProgramData "AIShield"))
    $expected = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\AIShield'
    if ($data -ne $expected) { throw "Security data path validation failed." }
    Remove-Item -LiteralPath $data -Recurse -Force
}
Write-Output "AI Shield uninstalled. Security data preserved=$(-not $PurgeSecurityData)"

```

## File: `AI_Shield_Private_Desktop/platform/windows/policy/ai_shield_policy.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/policy/ai_shield_policy.ps1`  
- Size: 13067 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [ValidateSet("initialize", "sign", "apply", "recover", "status")]
    [string]$Action,
    [string]$InputFile,
    [string]$OutputFile
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$stateDir = Join-Path $env:ProgramData "AIShield\policy"
$pinFile = Join-Path $stateDir "signer.thumbprint"
$currentFile = Join-Path $stateDir "current.aipolicy"
$previousFile = Join-Path $stateDir "previous.aipolicy"
$stagedFile = Join-Path $stateDir "staged.aipolicy"
$stateFile = Join-Path $stateDir "state.json"
$certificateSubject = "CN=AI Shield Local Policy Signing"

function Confirm-Administrator {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Policy management requires an elevated PowerShell."
    }
}

function Write-AtomicText([string]$Path, [string]$Text) {
    $temporary = "$Path.tmp"
    [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-PinnedCertificate([bool]$RequirePrivateKey) {
    if (-not (Test-Path -LiteralPath $pinFile)) { throw "Policy signer pin is missing." }
    $thumbprint = (Get-Content -LiteralPath $pinFile -Raw).Trim()
    if ($thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw "Policy signer pin is malformed." }
    $certificate = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop
    if ($RequirePrivateKey -and -not $certificate.HasPrivateKey) { throw "Policy signing private key is unavailable." }
    return $certificate
}

function Get-PayloadBytes($Policy) {
    $ordered = [ordered]@{
        schema = [uint32]1
        security_version = [uint64]$Policy.security_version
        mode = [string]$Policy.mode
        block_inbound_port = [uint32]$Policy.block_inbound_port
        redirect_outbound_port = [uint32]$Policy.redirect_outbound_port
        proxy_port = [uint32]$Policy.proxy_port
        block_quarantine_execution = [bool]$Policy.block_quarantine_execution
        block_user_temp_execution = [bool]$Policy.block_user_temp_execution
        block_download_execution = [bool]$Policy.block_download_execution
        block_risky_script_command = [bool]$Policy.block_risky_script_command
        block_office_child_process = [bool]$Policy.block_office_child_process
        system_network_guard = [bool]$Policy.system_network_guard
        block_unsolicited_inbound = [bool]$Policy.block_unsolicited_inbound
        block_browser_non_web = [bool]$Policy.block_browser_non_web
    }
    if ($ordered.security_version -eq 0) { throw "security_version must be greater than zero." }
    if ($ordered.mode -notin @("audit", "enforce")) { throw "mode must be audit or enforce." }
    foreach ($port in @($ordered.block_inbound_port, $ordered.redirect_outbound_port, $ordered.proxy_port)) {
        if ($port -gt 65535) { throw "Policy port is outside the valid range." }
    }
    if (($ordered.redirect_outbound_port -eq 0) -ne ($ordered.proxy_port -eq 0)) {
        throw "Redirect and proxy ports must be configured together."
    }
    if ($ordered.redirect_outbound_port -ne 0 -and $ordered.redirect_outbound_port -eq $ordered.proxy_port) {
        throw "Redirect and proxy ports must differ."
    }
    return [Text.Encoding]::UTF8.GetBytes(($ordered | ConvertTo-Json -Compress))
}

function New-SignedEnvelope($Policy, [string]$Destination) {
    $certificate = Get-PinnedCertificate $true
    $payload = Get-PayloadBytes $Policy
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        $signature = $rsa.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pss)
    } finally {
        $rsa.Dispose()
    }
    $envelope = [ordered]@{
        format = "AIShieldPolicy/1"
        signer = $certificate.Thumbprint
        payload = [Convert]::ToBase64String($payload)
        signature = [Convert]::ToBase64String($signature)
    }
    Write-AtomicText $Destination ($envelope | ConvertTo-Json -Compress)
}

function Read-VerifiedPolicy([string]$Path) {
    $envelope = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($envelope.format -ne "AIShieldPolicy/1") { throw "Unsupported policy envelope." }
    $certificate = Get-PinnedCertificate $false
    if ($envelope.signer -ne $certificate.Thumbprint) { throw "Policy signer does not match the pinned certificate." }
    $payload = [Convert]::FromBase64String([string]$envelope.payload)
    $signature = [Convert]::FromBase64String([string]$envelope.signature)
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        $valid = $rsa.VerifyData($payload, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pss)
    } finally {
        $rsa.Dispose()
    }
    if (-not $valid) { throw "Policy signature verification failed." }
    $policy = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
    [void](Get-PayloadBytes $policy)
    return $policy
}

function Test-VerifiedPolicy([string]$Path) {
    trap { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    [void](Read-VerifiedPolicy $Path)
    return $true
}

function Get-PolicyState {
    if (-not (Test-Path -LiteralPath $stateFile)) {
        return [ordered]@{ security_version = [uint64]0; recovery_required = $false; last_result = "uninitialized" }
    }
    return Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
}

function Set-PolicyState([uint64]$SecurityVersion, [bool]$RecoveryRequired, [string]$Result) {
    $state = [ordered]@{
        security_version = $SecurityVersion
        model_version = [uint64]1
        recovery_required = $RecoveryRequired
        last_result = $Result
        updated_utc = [DateTime]::UtcNow.ToString("o")
    }
    Write-AtomicText $stateFile ($state | ConvertTo-Json -Compress)
    if ($SecurityVersion -gt 0) {
        if (-not (Test-Path -LiteralPath $broker)) { throw "Telemetry broker is unavailable for runtime synchronization." }
        & $broker runtime-sync $SecurityVersion 1
        if ($LASTEXITCODE -ne 0) { throw "Authenticated runtime synchronization failed." }
    }
}

function Invoke-KernelPolicy($Policy) {
    if ($Policy.mode -eq "audit") {
        & $kernelctl audit
    } else {
        $arguments = @("enforce", "--confirm-enforcement")
        if ([uint32]$Policy.block_inbound_port -ne 0) { $arguments += @("--block-inbound", $Policy.block_inbound_port) }
        if ([uint32]$Policy.redirect_outbound_port -ne 0) {
            $gatewayPidFile = Join-Path $repo "runtime\ai_shield_prototype.pid"
            if (-not (Test-Path -LiteralPath $gatewayPidFile)) { throw "Gateway PID state is missing for redirect enforcement." }
            $gatewayPid = [uint32](Get-Content -LiteralPath $gatewayPidFile -Raw)
            $arguments += @("--redirect-port", $Policy.redirect_outbound_port, "--proxy-port", $Policy.proxy_port,
                "--exempt-pid", $gatewayPid)
        }
        if ([bool]$Policy.block_quarantine_execution) { $arguments += "--block-quarantine-execution" }
        if ([bool]$Policy.block_user_temp_execution) { $arguments += "--block-user-temp-execution" }
        if ([bool]$Policy.block_download_execution) { $arguments += "--block-download-execution" }
        if ([bool]$Policy.block_risky_script_command) { $arguments += "--block-risky-script-command" }
        if ([bool]$Policy.block_office_child_process) { $arguments += "--block-office-child-process" }
        if ([bool]$Policy.system_network_guard) { $arguments += "--system-network-guard" }
        if ([bool]$Policy.block_unsolicited_inbound) { $arguments += "--block-unsolicited-inbound" }
        if ([bool]$Policy.block_browser_non_web) { $arguments += "--block-browser-non-web" }
        & $kernelctl @arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "Kernel rejected the policy." }
    $driverStatus = (& $driverctl status 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or ([regex]::Matches($driverStatus, "state=4 win32_exit=0")).Count -ne 3) {
        throw "Driver health check failed after policy application."
    }
}

function Restore-ActivePolicy {
    $recoveryFile = if (Test-VerifiedPolicy $currentFile) { $currentFile }
        elseif (Test-VerifiedPolicy $previousFile) { $previousFile }
        else { $null }
    if (-not $recoveryFile) {
        & $kernelctl audit
        Set-PolicyState 0 $true "recovery-audit"
        return
    }
    $recovered = Read-VerifiedPolicy $recoveryFile
    Invoke-KernelPolicy $recovered
    if ($recoveryFile -ne $currentFile) { Copy-Item -LiteralPath $recoveryFile -Destination $currentFile -Force }
    Set-PolicyState ([uint64]$recovered.security_version) $false "rolled-back"
}

Confirm-Administrator

if ($Action -eq "initialize") {
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    & icacls.exe $stateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure policy state directory." }
    if (Test-Path -LiteralPath $pinFile) {
        if (-not (Test-Path -LiteralPath $currentFile) -or -not (Test-Path -LiteralPath $stateFile)) {
            throw "Policy initialization is incomplete; recovery requires an administrator."
        }
        $existingPolicy = Read-VerifiedPolicy $currentFile
        $existingState = Get-PolicyState
        if ([uint64]$existingPolicy.security_version -ne [uint64]$existingState.security_version) {
            throw "Policy state and signed active policy disagree."
        }
        Write-Output "policy already initialized security_version=$($existingPolicy.security_version)"
        exit 0
    }
    $certificate = New-SelfSignedCertificate -Type Custom -Subject $certificateSubject -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyUsage DigitalSignature `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(5)
    Write-AtomicText $pinFile $certificate.Thumbprint
    $default = [ordered]@{ security_version = [uint64]1; mode = "audit"; block_inbound_port = 0;
        redirect_outbound_port = 0; proxy_port = 0; block_quarantine_execution = $true;
        block_user_temp_execution = $true; block_download_execution = $false;
        block_risky_script_command = $true; block_office_child_process = $true;
        system_network_guard = $true; block_unsolicited_inbound = $false;
        block_browser_non_web = $false }
    New-SignedEnvelope $default $currentFile
    Set-PolicyState 1 $false "initialized"
    Write-Output "policy initialized signer=$($certificate.Thumbprint)"
    exit 0
}

if ($Action -eq "sign") {
    if (-not $InputFile -or -not $OutputFile) { throw "sign requires InputFile and OutputFile." }
    New-SignedEnvelope (Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json) $OutputFile
    Write-Output "signed policy: $OutputFile"
    exit 0
}

if ($Action -eq "apply") {
    if (-not $InputFile) { throw "apply requires InputFile." }
    $policy = Read-VerifiedPolicy $InputFile
    $state = Get-PolicyState
    if ([uint64]$policy.security_version -le [uint64]$state.security_version) { throw "Policy downgrade or replay rejected." }
    Copy-Item -LiteralPath $InputFile -Destination $stagedFile -Force
    Set-PolicyState ([uint64]$state.security_version) $true "applying"
    $applied = $false
    try {
        Invoke-KernelPolicy $policy
        if (Test-Path -LiteralPath $currentFile) { Copy-Item $currentFile $previousFile -Force }
        Move-Item -LiteralPath $stagedFile -Destination $currentFile -Force
        Set-PolicyState ([uint64]$policy.security_version) $false "active"
        $applied = $true
    } finally {
        if (-not $applied) { Restore-ActivePolicy }
    }
    Write-Output "policy active security_version=$($policy.security_version)"
    exit 0
}

if ($Action -eq "recover") {
    $state = Get-PolicyState
    if ([bool]$state.recovery_required) { Restore-ActivePolicy }
    elseif (Test-Path -LiteralPath $currentFile) { Invoke-KernelPolicy (Read-VerifiedPolicy $currentFile) }
    else { & $kernelctl audit }
    Write-Output "policy recovery completed"
    exit 0
}

if ($Action -eq "status") {
    $state = Get-PolicyState
    $policy = Read-VerifiedPolicy $currentFile
    Write-Output "policy signature=valid security_version=$($policy.security_version) mode=$($policy.mode)"
    Write-Output "recovery_required=$($state.recovery_required) last_result=$($state.last_result)"
    exit 0
}

```

## File: `AI_Shield_Private_Desktop/platform/windows/protect_system.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/protect_system.ps1`  
- Size: 2998 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([switch]$StrictBrowser, [switch]$BlockUnsolicitedInbound, [switch]$HardenDownloads)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = @("-NoProfile","-ExecutionPolicy","Bypass","-File",('"'+$PSCommandPath+'"'))
    if ($StrictBrowser) { $arguments += "-StrictBrowser" }
    if ($BlockUnsolicitedInbound) { $arguments += "-BlockUnsolicitedInbound" }
    if ($HardenDownloads) { $arguments += "-HardenDownloads" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"
$postureScript = Join-Path $repo "platform\windows\security\system_security_posture.ps1"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $postureScript
if ($LASTEXITCODE -ne 0) { throw "Windows security posture collection failed." }
& $driverctl start
if ($LASTEXITCODE -ne 0) { throw "Kernel sensors failed to start." }
Start-Service AIShieldBroker -ErrorAction SilentlyContinue
Start-Service AIShieldCore -ErrorAction SilentlyContinue
$state = Get-Content (Join-Path $env:ProgramData "AIShield\policy\state.json") -Raw | ConvertFrom-Json
$input = Join-Path $repo "runtime\system-protection-policy.json"
$envelope = Join-Path $repo "runtime\system-protection-policy.aipolicy"
[ordered]@{ security_version = [uint64]$state.security_version + 1; mode = "enforce";
    block_inbound_port = 0; redirect_outbound_port = 0; proxy_port = 0;
    block_quarantine_execution = $true; block_user_temp_execution = $true;
    block_download_execution = [bool]$HardenDownloads; block_risky_script_command = $true;
    block_office_child_process = $true; system_network_guard = $true;
    block_unsolicited_inbound = [bool]$BlockUnsolicitedInbound;
    block_browser_non_web = [bool]$StrictBrowser } | ConvertTo-Json -Compress |
    Set-Content -LiteralPath $input -Encoding UTF8
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign -InputFile $input -OutputFile $envelope
if ($LASTEXITCODE -ne 0) { throw "System protection policy signing failed." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $envelope
Remove-Item $input,$envelope -Force -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0) { throw "System protection policy activation failed." }
Write-Output "AI Shield system protection active"
Write-Output "dual-stack telemetry: all ALE connect/accept flows"
Write-Output "worm egress guard: active"
Write-Output "strict browser ports: $([bool]$StrictBrowser)"
Write-Output "block unsolicited inbound: $([bool]$BlockUnsolicitedInbound)"
Write-Output "block direct download execution: $([bool]$HardenDownloads)"

```

## File: `AI_Shield_Private_Desktop/platform/windows/stop_ai_shield.ps1`  
- Path: `AI_Shield_Private_Desktop/platform/windows/stop_ai_shield.ps1`  
- Size: 3249 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [switch]$KeepDrivers
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$pidFile = Join-Path $repo "runtime\ai_shield_prototype.pid"
$servicePidFile = Join-Path $env:ProgramData "AIShield\gateway.pid"
$policyScript = Join-Path $repo "platform\windows\policy\ai_shield_policy.ps1"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'))
    if ($KeepDrivers) {
        $arguments += "-KeepDrivers"
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}

if (Test-Path -LiteralPath $policyScript) {
    $stateFile = Join-Path $env:ProgramData "AIShield\policy\state.json"
    if (Test-Path -LiteralPath $stateFile) {
        $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        $version = [uint64]$state.security_version + 1
        $input = Join-Path $env:TEMP "ai-shield-stop-policy.json"
        $envelope = Join-Path $env:TEMP "ai-shield-stop-policy.aipolicy"
        [IO.File]::WriteAllText($input, (([ordered]@{ security_version=$version; mode="audit";
            block_inbound_port=0; redirect_outbound_port=0; proxy_port=0;
            block_quarantine_execution=$true; block_user_temp_execution=$true;
            block_download_execution=$false; block_risky_script_command=$true;
            block_office_child_process=$true; system_network_guard=$false;
            block_unsolicited_inbound=$false; block_browser_non_web=$false }) | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action sign -InputFile $input -OutputFile $envelope
        if ($LASTEXITCODE -eq 0) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $policyScript -Action apply -InputFile $envelope
        }
        Remove-Item -LiteralPath $input, $envelope -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $pidFile) {
    $gatewayPid = [int](Get-Content -LiteralPath $pidFile -Raw)
    $gateway = Get-Process -Id $gatewayPid -ErrorAction SilentlyContinue
    if ($gateway) {
        Stop-Process -Id $gatewayPid
        Write-Output "stopped AI Shield gateway PID $gatewayPid"
    } else {
        Write-Output "AI Shield gateway was not running"
    }
    Remove-Item -LiteralPath $pidFile -Force
    Remove-Item -LiteralPath $servicePidFile -Force -ErrorAction SilentlyContinue
} else {
    Write-Output "AI Shield gateway state file not found"
}

if (-not $KeepDrivers) {
    Stop-Service -Name "AIShieldBroker" -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $driverctl)) {
        throw "Driver control executable not found: $driverctl"
    }
    & $driverctl stop
    if ($LASTEXITCODE -ne 0) {
        throw "One or more drivers could not be stopped."
    }
}

Write-Output "AI Shield prototype stopped"

```

## File: `AI_Shield_Private_Desktop/private_common.ps1`  
- Path: `AI_Shield_Private_Desktop/private_common.ps1`  
- Size: 1198 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
function Get-AIShieldPrivateRoot {
    $sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    foreach ($candidate in @($sourceRoot, [IO.Path]::GetFullPath($PSScriptRoot))) {
        if (Test-Path -LiteralPath (Join-Path $candidate "build_vs\Release\ai_shield_driverctl.exe")) {
            return $candidate
        }
    }
    throw "AI Shield program files were not found. Extract the complete private desktop package first."
}

function Test-AIShieldAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-AIShieldElevated([string]$ScriptPath, [string[]]$ForwardedArguments = @()) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $ScriptPath + '"'))
    $arguments += $ForwardedArguments
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
}

function Assert-AIShieldFile([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing: $Path"
    }
}

```

## File: `AI_Shield_Private_Desktop/private_posture.ps1`  
- Path: `AI_Shield_Private_Desktop/private_posture.ps1`  
- Size: 2661 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([string]$OutputPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
$root = Get-AIShieldPrivateRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $env:ProgramData "AIShield\private-desktop\security-posture.json"
}
$temporary = Join-Path $env:TEMP ("ai-shield-posture-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\security\system_security_posture.ps1") -OutputPath $temporary
    if ($LASTEXITCODE -ne 0) { throw "Base security posture collection failed." }
    $base = Get-Content -LiteralPath $temporary -Raw | ConvertFrom-Json
    $excluded = @("signed_browser_sensor", "pinned_wef_forwarding", "wdac_audit_policy",
        "powershell_privacy_forwarding")
    $checks = @($base.checks | Where-Object { $_.id -notin $excluded })
    foreach ($check in $checks) {
        if ($check.id -eq "defender_cloud_reporting") {
            $check.remediation = "Enable Defender cloud-delivered protection after reviewing local privacy settings."
        }
        if ($check.id -eq "powershell_script_block_logging") {
            $check.remediation = "Enable local PowerShell Script Block Logging and protect the Windows event log."
        }
        if ($check.id -eq "powershell_module_logging") {
            $check.remediation = "Enable selected local PowerShell Module Logging."
        }
    }
    $report = [ordered]@{
        schema = "AIShieldPrivateDesktopPosture/1"
        generated_utc = [DateTime]::UtcNow.ToString("o")
        computer = $env:COMPUTERNAME
        critical_failures = @($checks | Where-Object { $_.severity -eq "critical" -and -not $_.passed }).Count
        passed = @($checks | Where-Object passed).Count
        total = $checks.Count
        checks = $checks
    }
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [IO.File]::WriteAllText($OutputPath, ($report | ConvertTo-Json -Depth 7), [Text.UTF8Encoding]::new($false))
    $digest = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText("$OutputPath.sha256", "$digest  $([IO.Path]::GetFileName($OutputPath))`r`n",
        [Text.ASCIIEncoding]::new())
    Write-Output ("private desktop posture: passed={0}/{1} critical_failures={2}" -f `
        $report.passed, $report.total, $report.critical_failures)
    Write-Output "report: $OutputPath"
} finally {
    Remove-Item -LiteralPath $temporary, "$temporary.sha256" -Force -ErrorAction SilentlyContinue
}

```

## File: `AI_Shield_Private_Desktop/QUALIFIKATIONSSTATUS.md`  
- Path: `AI_Shield_Private_Desktop/QUALIFIKATIONSSTATUS.md`  
- Size: 3951 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```markdown
# Qualifikationsstatus AI Shield Private Desktop 2.0.0-rc.2

Stand: 13. Juli 2026

## Bestätigte lokale Gates

- Kernel-ABI 1.2, Freeze-Revision 2 und internes ABI 2.0 entsprechen dem Releasevertrag.
- Zwei vollständige, getrennte Release-Builds bestanden jeweils alle 11 CTest-Ziele.
- Ein vollständiger Debug-Build bestand alle 11 CTest-Ziele.
- Fünf auslieferungsrelevante User-Mode-Programme waren zwischen beiden Release-Builds hashgleich.
- Alle drei Treiber wurden zweimal mit WDK `Rebuild` erzeugt und waren jeweils hashgleich.
- Inf2Cat erzeugte für WFP, Minifilter und ProcessGuard Kataloge ohne Fehler und Warnungen.
- Das Microsoft-Staging enthält INF, SYS, CAT, PDB, ABI- und SHA-256-Manifeste sowie CAB.
- Zwei Consumer-Paketläufe aus identischen signierten Eingaben sind bytegenau reproduzierbar.
- Der WPF-Vertrag des RC2-Interfaces enthält 30 gebundene Controls in fünf Ansichten; XAML-Laden,
  Paketentpackung und SHA-256-Prüfung aller 48 Manifestdateien waren erfolgreich.
- Der lokale Consumer-Korpus bestand sichere Prozessstarts und harmlose Downloadtypen.
- Ein fünfsekündiger Dual-Stack-Lauf übertrug 2.166.210.560 Byte in 528.860 Transfers über
  dauerhafte IPv4-/IPv6-Flows ohne Transportfehler.
- Broker und Core blieben im Messfenster unter 10 MiB Working Set und weit unter 1 Prozent
  durchschnittlicher Gesamt-CPU.
- Auf dem Testsystem wurden installierte Anwendungen in allen fünf Inventarkategorien Browser,
  VPN, Spiele, Installer und Skript-/Entwicklungswerkzeuge gefunden.

Maschinenlesbare Nachweise:

- `runtime/private-release/RC_REPORT.json`
- `runtime/private-release/consumer-qualification.json`
- `runtime/private-release/microsoft-submission/SHA256SUMS.json`
- `runtime/verification/HLK_READINESS.json`

Frische, reproduzierte Treiberhashes:

| Datei | SHA-256 |
|---|---|
| `AIShieldWfp.sys` | `3F0CE985AF35B1CDB59AF5D7DC9066D11F6F92E05FCF656EADE0973C8EC99370` |
| `AIShieldMiniFilter.sys` | `0B1D9540D8A9336F5F8AD78CFD6D2C8EDA91FF6D7FB1E6661F9E991EE2AA4620` |
| `AIShieldProcessGuard.sys` | `7D6E3E6A2F0BB43CAA3C37C6E4499BCED1F4204623198912064C31658894CF0B` |
| `AIShieldDrivers-x64.cab` | `FD25FEF7B622C6CF73CA535DE4F3AA8F0A8AC5308E3005946681DCA988F9A12F` |

## Noch nicht bestandene Gates

Das installierbare RC-ZIP wurde absichtlich nicht freigegeben. Die frisch gebauten Treiber sind
noch nicht testsigniert und noch nicht anstelle der laufenden älteren Prototyptreiber installiert.
Der Packager verweigert unsignierte Consumer-Treiber.

Der erhöhte Abschlusslauf lautet:

```powershell
Set-Location D:\AI_Shield
powershell -ExecutionPolicy Bypass -File tools\complete_private_rc_admin.ps1 `
  -QualificationSeconds 60 -ConfirmInstallCycle
```

Dieser Lauf signiert exakt das geprüfte Staging, erstellt das reproduzierbare Consumer-ZIP,
ersetzt die drei installierten Prototyptreiber kontrolliert, prüft deren Laufzustand und wiederholt
Consumer-, Security- und Recovery-Inspektion. Bei fehlgeschlagener Treiberinstallation versucht er,
das vorherige lokale Treiberpaket wiederherzustellen.

Weiterhin extern oder rebootpflichtig:

1. Driver Verifier für genau die drei RC-Treiber mit kontrolliertem Neustart und Notfallreset.
2. Neustart-, Installations-, Update-, Rollback- und Recovery-Zyklen auf einem wiederherstellbaren
   Testsystem; der aktuelle nicht erhöhte Lauf verändert diese Zustände nicht.
3. Längerer interaktiver Fehlalarmtest, bei dem Browser, VPN, Spiele, Installer und Skripte wirklich
   verwendet werden. Das vorhandene Inventar allein beweist keine Kompatibilität.
4. HLK/WHCP. HVCI läuft und alle Submission-Artefakte sind vorhanden; auf diesem Rechner fehlen HLK
   Studio/Controller und ein Controller-Endpunkt.
5. Unabhängiges Kernelreview und Penetrationstest durch eine organisatorisch getrennte Stelle.
6. Partner-Center-Upload und Microsoft-Produktionssignatur.

Keiner dieser Punkte darf ohne Ergebnisartefakt als bestanden markiert werden.

```

## File: `AI_Shield_Private_Desktop/RELEASE_CONTRACT.json`  
- Path: `AI_Shield_Private_Desktop/RELEASE_CONTRACT.json`  
- Size: 3250 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```json
{
  "schema": "AIShieldPrivateReleaseContract/1",
  "release": "2.0.0-rc.2",
  "release_epoch_utc": "2026-07-13T12:00:00Z",
  "kernel_abi": "1.2",
  "kernel_abi_freeze_revision": 2,
  "internal_abi": "2.0",
  "policy_schema": 1,
  "artifacts": [
    {
      "path": "platform/windows/common/ai_shield_driver_protocol.h",
      "sha256": "70F00ADCB61FB7A79DF40D7F4529FC24B41234ECDAF610087401802E04D52FDC"
    },
    {
      "path": "include/ai_shield/abi2.hpp",
      "sha256": "170B9D062DD18ED3FFC8B2E876252003503F5A2302696ADBA7C7447C990CB17B"
    },
    {
      "path": "platform/windows/policy/ai_shield_policy.ps1",
      "sha256": "3DF45C2079531FA47EFF458FCA04C66DB306C3B7286E7C02918727957D9B7E08"
    },
    {
      "path": "editions/private_desktop/edition.json",
      "sha256": "EBCEDFCF0B9542F15FE52497C9165C36E57387D505B9C9FB4DF98A285D1FC6BF"
    },
    {
      "path": "CMakeLists.txt",
      "sha256": "F5CC7C161DD6C516C7BF9722C396195FFCCA5B795F185A12AE41101B4D625B4B"
    },
    {
      "path": "platform/windows/drivers.props",
      "sha256": "5E6824DD961F7D2B4DC72B199E1CAE71DA79BE76201B8403B14A25A55C19B4B7"
    },
    {
      "path": "platform/windows/build_drivers.ps1",
      "sha256": "654917CFA5F7FA34BE675BF88642DC3B34B55030BFDD4A3D0F82892F665637FE"
    },
    {
      "path": "tools/package_private_desktop.ps1",
      "sha256": "CE9D524FB8B2328AF2E9B0C669603F24E6E4E92F93F9BE276AA47D1F5FFF4DC5"
    },
    {
      "path": "editions/private_desktop/install_private_desktop.ps1",
      "sha256": "884BD71B968155C72A319888A35AD2DCB3DFB24C56E56609DDB04F7193B036A4"
    },
    {
      "path": "editions/private_desktop/uninstall_private_desktop.ps1",
      "sha256": "EC1C6F25FE5F45E3899204E4782236E6B077A4486E803D2452E7B707FE50EB8D"
    },
    {
      "path": "editions/private_desktop/AI_Shield_UI.cmd",
      "sha256": "83CD9A71DC864E50F661069F1E98D1D591A92893C52D3BB44B93D4371C15F510"
    },
    {
      "path": "editions/private_desktop/ui/AIShield.PrivateDesktop.UI.xaml",
      "sha256": "BA7A89DFA88544BAEC4D6713068E2ED27A3C3A8FFE7CEFA511BD5BB1CEDF25D8"
    },
    {
      "path": "editions/private_desktop/ui/start_private_ui.ps1",
      "sha256": "07285FEDD2CC486B01B4837B842A67E6F060CAF8E63F9407FC225828A8BD123F"
    },
    {
      "path": "editions/private_desktop/ui/private_security_settings.ps1",
      "sha256": "8D7DB8B7FC81DF0C1B80E585B6A43806C8BF346E674694B6DE35554E1890699B"
    },
    {
      "path": "editions/private_desktop/ui/verify_ui_contract.ps1",
      "sha256": "7E24A83E4806AA1408499D85F1FC232694B26E189562435E660C89277D3F24BB"
    }
  ],
  "drivers": [
    "AIShieldWfp.sys",
    "AIShieldMiniFilter.sys",
    "AIShieldProcessGuard.sys"
  ],
  "services": [
    "AIShieldBroker",
    "AIShieldCore"
  ],
  "consumer_scope": [
    "dual-stack network metadata and worm egress guard",
    "file provenance and bounded quarantine",
    "process creation and handle enforcement",
    "signed local policy and rollback",
    "local audit and health posture",
    "graphical local administration with reboot resume and quarantine workflow"
  ],
  "excluded_scope": [
    "web gateway by default",
    "central collectors",
    "fleet management",
    "SOC console",
    "enterprise browser policy"
  ]
}

```

## File: `AI_Shield_Private_Desktop/Schutz_beenden.cmd`  
- Path: `AI_Shield_Private_Desktop/Schutz_beenden.cmd`  
- Size: 129 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_private_desktop.ps1"
if errorlevel 1 pause

```

## File: `AI_Shield_Private_Desktop/Schutz_starten.cmd`  
- Path: `AI_Shield_Private_Desktop/Schutz_starten.cmd`  
- Size: 130 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_private_desktop.ps1"
if errorlevel 1 pause

```

## File: `AI_Shield_Private_Desktop/SOFTWAREBEWERTUNG_PRIVAT.md`  
- Path: `AI_Shield_Private_Desktop/SOFTWAREBEWERTUNG_PRIVAT.md`  
- Size: 5642 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```markdown
# Softwarebewertung: AI Shield Private Desktop

## Bewertungsrahmen

Bewertet wird ausschließlich der Einsatz auf einem privaten Windows-Einzelplatzrechner. Zentrale
Administration, Flottenbetrieb, externe Ereignissammler und Security-Operations-Prozesse gehören
nicht zum Umfang dieser Edition und fließen weder positiv noch negativ in die Wertung ein.

Die Bewertung basiert auf Quellcode, lokalen Build- und Testergebnissen sowie dem dokumentierten
Installationsstand vom 13. Juli 2026. Sie ist kein unabhängiger Penetrationstest und keine
Produktzertifizierung.

Der RC-1-Lauf bestätigt inzwischen reproduzierbare User-Mode- und Treiberbuilds, drei erfolgreiche
Debug-/Release-Testserien, fehlerfreie Inf2Cat-Pakete sowie einen lokalen Dual-Stack-Lastlauf. Diese
Nachweise verbessern die technische Evidenz, ersetzen aber nicht die weiterhin offenen erhöhten,
rebootpflichtigen, interaktiven und unabhängigen Prüfungen.

## Kurzurteil

AI Shield Private Desktop ist ein weit entwickelter Sicherheitsprototyp für technisch versierte
Privatnutzer. Er besitzt reale Windows-Kerneltreiber für Netzwerk-, Datei- und Prozessereignisse,
eine authentisierte Ereignispipeline, lokale Policy-Durchsetzung, gehärtete Quarantäne und
überwachte Systemdienste. Der normale Einzelplatzstart benötigt weder Webserver noch Backend-Port.

Die Edition ist trotzdem noch kein allgemein freigegebenes Endanwenderprodukt. Der entscheidende
Grund ist die lokale Testsignierung der Treiber: Secure Boot muss derzeit deaktiviert sein und
Windows läuft im TESTSIGNING-Modus. Damit ist der Prototyp für ein kontrolliertes Testsystem
geeignet, nicht für eine bedenkenlose Installation auf dem einzigen privaten Alltags-PC.

**Gesamtbewertung: 7,2 von 10 - technisch starker Einzelplatzprototyp mit noch fehlender sicherer
Treiberfreigabe und Felderprobung.**

## Teilbewertungen

| Bereich | Wertung | Einordnung |
|---|---:|---|
| Lokale Schutzarchitektur | 8,2/10 | Zusammenhängender Netzwerk-, Datei-, Prozess-, Policy- und Auditpfad |
| Bedienbarkeit | 7,4/10 | Eigene Ein-Klick-Skripte für Installation, Start, Status, Stopp und Deinstallation |
| Datei- und Prozessschutz | 7,5/10 | Starke handle-basierte Quarantäne und konkrete Prozessregeln mit begrenzter Abdeckung |
| Netzwerkmetadaten und Wurmschutz | 6,8/10 | IPv4/IPv6 und ausgewählte Wurmports; keine allgemeine Entschlüsselung von HTTPS/QUIC |
| Lokaler Datenschutz | 7,8/10 | Lokale Verarbeitung und kein erforderlicher externer Ereignisexport |
| Alltagskompatibilität | 6,0/10 | Konservative Vorgaben, aber noch keine breite Messung mit Spielen, VPNs und Privatsoftware |
| Installationssicherheit | 4,5/10 | Rollback vorhanden; Testsigning und deaktivierter Secure Boot verhindern Produktfreigabe |

## Was die Privatversion schützt

- Sie beobachtet IPv4- und IPv6-Flows und kann ausgewählte typische Wurm- und
  Lateral-Movement-Verbindungen blockieren.
- Sie erkennt Internet-Provenance bei ausgewählten neuen ausführbaren Dateien in Downloads und Temp
  und kann verdächtige Dateien handle-basiert quarantänisieren.
- Sie blockiert ausgewählte riskante Starts aus Quarantäne und Benutzer-Temp sowie auffällige
  Skript-, Office- und Systemwerkzeug-Prozessketten.
- Sie authentisiert Kernelereignisse, lehnt Replay und veraltete Policyversionen ab und führt eine
  lokal prüfbare Audit-Hashkette.
- Sie überwacht Broker und Core, begrenzt Neustartschleifen und kann in einen Audit-only-Safe-Mode
  wechseln.
- Sie ergänzt Windows-Firewall und Microsoft Defender durch eine rückrollbare lokale Auditbaseline.

## Sachliche Grenzen

Die Quarantäne verarbeitet nicht jede Datei auf jedem Datenträger. Sie konzentriert sich auf neue
Dateien mit Internet-Markierung, ausgewählte riskante Erweiterungen und definierte lokale Ordner.
Die WFP-Schicht sieht bei HTTPS und QUIC überwiegend Verbindungsmetadaten, nicht den verschlüsselten
Inhalt. ProcessGuard verwendet konkrete Regeln und ist keine vollständige Verhaltensanalyse jeder
denkbaren Prozesskette.

Kein lokales Schutzprogramm garantiert Sicherheit gegen unbekannte Kernel-Lücken, einen bereits als
Administrator oder SYSTEM aktiven Angreifer, kompromittierte Firmware oder manipulierte Hardware.
AI Shield muss deshalb zusammen mit Windows Update, Defender, aktiver Firewall, UAC,
Datenträgerverschlüsselung und getrennten Backups eingesetzt werden.

## Noch erforderliche Freigaben

1. Microsoft-signierte Treiber und verifizierter Betrieb mit Secure Boot ohne TESTSIGNING.
2. HVCI-, Driver-Verifier-, Neustart-, Update-, Recovery- und mehrtägige Lastprüfungen.
3. Kompatibilitätstests mit verbreiteten Browsern, Spielen, VPNs, Druckern und Privatsoftware.
4. Repräsentative Fehlalarmmessungen für Downloads, Installer, Skripte und Heimnetzverkehr.
5. Unabhängige Überprüfung des Kernelcodes, Penetrationstest und dokumentierter Recoverytest.
6. Endanwendergerechter signierter Installer mit Publisheridentität und sauberem Updatekanal.

## Einsatzempfehlung

Der aktuelle Stand eignet sich für einen wiederherstellbaren Test-PC oder eine kontrollierte
Pilotinstallation durch technisch erfahrene Privatnutzer. Für den einzigen produktiven Familien-
oder Arbeits-PC sollte die Edition erst nach Microsoft-Treibersignierung, aktiviertem Secure Boot
und erfolgreicher Kompatibilitätsprüfung verwendet werden.

Die korrekte Einordnung ist daher nicht "unbezwingbarer Schutz", sondern:

> Ein funktionsreicher lokaler Windows-Sicherheitsprototyp, der konkrete Netzwerk-, Download- und
> Prozessangriffe erschwert und sichtbar macht, ohne vollständigen Schutz versprechen zu können.

```

## File: `AI_Shield_Private_Desktop/start_private_desktop.ps1`  
- Path: `AI_Shield_Private_Desktop/start_private_desktop.ps1`  
- Size: 1177 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param(
    [switch]$HardenDownloads,
    [switch]$StrictBrowser,
    [switch]$BlockUnsolicitedInbound
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($HardenDownloads) { $forward += "-HardenDownloads" }
    if ($StrictBrowser) { $forward += "-StrictBrowser" }
    if ($BlockUnsolicitedInbound) { $forward += "-BlockUnsolicitedInbound" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}

$root = Get-AIShieldPrivateRoot
$protectScript = Join-Path $root "platform\windows\protect_system.ps1"
Assert-AIShieldFile $protectScript "Protection script"
$arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $protectScript)
if ($HardenDownloads) { $arguments += "-HardenDownloads" }
if ($StrictBrowser) { $arguments += "-StrictBrowser" }
if ($BlockUnsolicitedInbound) { $arguments += "-BlockUnsolicitedInbound" }
& powershell.exe @arguments
if ($LASTEXITCODE -ne 0) { throw "AI Shield protection activation failed with exit code $LASTEXITCODE." }
Write-Output "Private workstation protection is active. No local web backend or server port is required."

```

## File: `AI_Shield_Private_Desktop/Status_anzeigen.cmd`  
- Path: `AI_Shield_Private_Desktop/Status_anzeigen.cmd`  
- Size: 115 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0status_private_desktop.ps1"
pause

```

## File: `AI_Shield_Private_Desktop/status_private_desktop.ps1`  
- Path: `AI_Shield_Private_Desktop/status_private_desktop.ps1`  
- Size: 586 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    Start-AIShieldElevated $PSCommandPath
    exit 0
}
$root = Get-AIShieldPrivateRoot
Write-Output "AI Shield Private Desktop status"
& (Join-Path $root "build_vs\Release\ai_shield_driverctl.exe") status
Write-Output ""
Get-Service AIShieldCore,AIShieldBroker -ErrorAction SilentlyContinue |
    Select-Object Name,Status,StartType | Format-Table -AutoSize
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_posture.ps1")

```

## File: `AI_Shield_Private_Desktop/stop_private_desktop.ps1`  
- Path: `AI_Shield_Private_Desktop/stop_private_desktop.ps1`  
- Size: 400 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    Start-AIShieldElevated $PSCommandPath
    exit 0
}
$root = Get-AIShieldPrivateRoot
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\stop_ai_shield.ps1")
if ($LASTEXITCODE -ne 0) { throw "AI Shield could not be stopped cleanly." }

```

## File: `AI_Shield_Private_Desktop/ui/AIShield.PrivateDesktop.UI.xaml`  
- Path: `AI_Shield_Private_Desktop/ui/AIShield.PrivateDesktop.UI.xaml`  
- Size: 11772 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="AI Shield Private Desktop" Width="1180" Height="760" MinWidth="980" MinHeight="640" WindowStartupLocation="CenterScreen"
 Background="#F3F6F8" FontFamily="Segoe UI" Foreground="#17212B">
 <Window.Resources>
  <SolidColorBrush x:Key="Ink" Color="#17212B"/><SolidColorBrush x:Key="Green" Color="#138A72"/>
  <Style TargetType="Button"><Setter Property="Cursor" Value="Hand"/><Setter Property="Padding" Value="14,9"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Background" Value="#E7EDF0"/><Setter Property="Foreground" Value="#17212B"/><Setter Property="FontWeight" Value="SemiBold"/></Style>
  <Style x:Key="NavButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="HorizontalContentAlignment" Value="Left"/><Setter Property="Padding" Value="20,13"/><Setter Property="Margin" Value="0,2"/><Setter Property="Background" Value="Transparent"/><Setter Property="Foreground" Value="#C7D2D9"/></Style>
  <Style TargetType="ToggleButton"><Setter Property="Width" Value="52"/><Setter Property="Height" Value="28"/><Setter Property="Background" Value="#A8B3BA"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ToggleButton"><Border x:Name="Track" Background="{TemplateBinding Background}" CornerRadius="14"><Ellipse x:Name="Knob" Width="22" Height="22" Fill="White" HorizontalAlignment="Left" Margin="3"/></Border><ControlTemplate.Triggers><Trigger Property="IsChecked" Value="True"><Setter TargetName="Track" Property="Background" Value="#138A72"/><Setter TargetName="Knob" Property="HorizontalAlignment" Value="Right"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  <Style x:Key="Card" TargetType="Border"><Setter Property="Background" Value="White"/><Setter Property="BorderBrush" Value="#D8E0E4"/><Setter Property="BorderThickness" Value="1"/><Setter Property="CornerRadius" Value="6"/><Setter Property="Padding" Value="18"/></Style>
 </Window.Resources>
 <Grid Background="#F3F6F8"><Grid.ColumnDefinitions><ColumnDefinition Width="220"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
  <Border Grid.Column="0" Background="#17242D"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
   <StackPanel Margin="20,22"><TextBlock Text="AI SHIELD" Foreground="White" FontSize="22" FontWeight="Bold"/><TextBlock Text="PRIVATE DESKTOP" Foreground="#55D1B3" FontSize="11" Margin="0,4,0,0"/></StackPanel>
   <StackPanel Grid.Row="1" Margin="10,20"><Button x:Name="NavDashboard" Style="{StaticResource NavButton}" Content="Übersicht"/><Button x:Name="NavProtection" Style="{StaticResource NavButton}" Content="Schutzfunktionen"/><Button x:Name="NavAudit" Style="{StaticResource NavButton}" Content="Audit"/><Button x:Name="NavQuarantine" Style="{StaticResource NavButton}" Content="Quarantäne"/><Button x:Name="NavSystem" Style="{StaticResource NavButton}" Content="Windows-Sicherheit"/></StackPanel>
   <StackPanel Grid.Row="2" Margin="20,16"><TextBlock Text="2.0.0-rc.2" Foreground="#7F929D"/><TextBlock x:Name="SidebarState" Text="Status wird geladen" Foreground="#55D1B3" Margin="0,5,0,0"/></StackPanel>
  </Grid></Border>
  <Grid Grid.Column="1" Background="#F3F6F8"><Grid.RowDefinitions><RowDefinition Height="64"/><RowDefinition Height="*"/><RowDefinition Height="38"/></Grid.RowDefinitions>
   <Border Background="White" BorderBrush="#D8E0E4" BorderThickness="0,0,0,1"><Grid Margin="24,0"><TextBlock x:Name="PageTitle" Text="Übersicht" FontSize="20" FontWeight="SemiBold" VerticalAlignment="Center"/><StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center"><Button x:Name="RefreshButton" Content="Aktualisieren"/><Button x:Name="RestartButton" Content="Jetzt neu starten" Background="#E59B32" Foreground="White" Margin="10,0,0,0" Visibility="Collapsed"/></StackPanel></Grid></Border>
   <TabControl x:Name="Pages" Grid.Row="1" Background="Transparent" BorderThickness="0" Margin="24,20"><TabControl.Resources><Style TargetType="TabItem"><Setter Property="Visibility" Value="Collapsed"/></Style></TabControl.Resources>
    <TabItem><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel>
     <UniformGrid Columns="3" Margin="0,0,0,16"><Border Style="{StaticResource Card}" Margin="0,0,10,0"><StackPanel><TextBlock Text="SCHUTZSTATUS" Foreground="#60717B"/><TextBlock x:Name="ProtectionState" Text="-" FontSize="25" FontWeight="Bold" Margin="0,8,0,0"/></StackPanel></Border><Border Style="{StaticResource Card}" Margin="5,0"><StackPanel><TextBlock Text="AKTIVE KOMPONENTEN" Foreground="#60717B"/><TextBlock x:Name="ComponentState" Text="-" FontSize="25" FontWeight="Bold" Margin="0,8,0,0"/></StackPanel></Border><Border Style="{StaticResource Card}" Margin="10,0,0,0"><StackPanel><TextBlock Text="LETZTES AUDIT" Foreground="#60717B"/><TextBlock x:Name="AuditState" Text="-" FontSize="18" FontWeight="Bold" Margin="0,10,0,0"/></StackPanel></Border></UniformGrid>
     <Border Style="{StaticResource Card}"><StackPanel><TextBlock Text="Komponenten" FontSize="16" FontWeight="SemiBold"/><DataGrid x:Name="ServiceGrid" Margin="0,14,0,0" AutoGenerateColumns="False" IsReadOnly="True" HeadersVisibility="Column" GridLinesVisibility="Horizontal" BorderThickness="0"><DataGrid.Columns><DataGridTextColumn Header="Komponente" Binding="{Binding Name}" Width="*"/><DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="140"/><DataGridTextColumn Header="Starttyp" Binding="{Binding StartType}" Width="160"/></DataGrid.Columns></DataGrid></StackPanel></Border>
    </StackPanel></ScrollViewer></TabItem>
    <TabItem><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel><TextBlock Text="Lokale Schutzfunktionen" FontSize="18" FontWeight="SemiBold"/><TextBlock Text="Änderungen werden als signierte lokale Policy aktiviert." Foreground="#60717B" Margin="0,4,0,16"/>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="AI-Shield-Kernschutz" FontWeight="SemiBold"/><TextBlock Text="Treiber, Broker und Core aktiv halten" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="CoreToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Downloads härten" FontWeight="SemiBold"/><TextBlock Text="Direkte Ausführung aus dem Downloadordner blockieren" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="DownloadsToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Browser auf Webprotokolle begrenzen" FontWeight="SemiBold"/><TextBlock Text="Direkte Browserverbindungen auf ungewöhnlichen Ports sperren" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="BrowserToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Unaufgeforderte Eingänge blockieren" FontWeight="SemiBold"/><TextBlock Text="Zusätzlicher lokaler Inbound-Schutz neben der Windows-Firewall" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="InboundToggle" Grid.Column="1"/></Grid></Border>
    </StackPanel></ScrollViewer></TabItem>
    <TabItem><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><StackPanel Orientation="Horizontal"><Button x:Name="VerifyAuditButton" Content="Ausgewähltes Audit prüfen" Background="#138A72" Foreground="White"/><Button x:Name="ExportAuditButton" Content="Audits exportieren" Margin="10,0,0,0"/></StackPanel><DataGrid x:Name="AuditGrid" Grid.Row="1" Margin="0,14,0,0" AutoGenerateColumns="False" IsReadOnly="True"><DataGrid.Columns><DataGridTextColumn Header="Datei" Binding="{Binding Name}" Width="*"/><DataGridTextColumn Header="Größe" Binding="{Binding Size}" Width="120"/><DataGridTextColumn Header="Geändert" Binding="{Binding Modified}" Width="190"/><DataGridTextColumn Header="Prüfung" Binding="{Binding Verification}" Width="130"/></DataGrid.Columns></DataGrid></Grid></TabItem>
    <TabItem><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><StackPanel Orientation="Horizontal"><Button x:Name="ReleaseButton" Content="Ausgewählte Datei freigeben" Background="#C85A4A" Foreground="White"/><TextBlock Text="Freigaben benötigen Zielpfad und Begründung." VerticalAlignment="Center" Foreground="#60717B" Margin="14,0"/></StackPanel><DataGrid x:Name="QuarantineGrid" Grid.Row="1" Margin="0,14,0,0" AutoGenerateColumns="False" IsReadOnly="True"><DataGrid.Columns><DataGridTextColumn Header="Objekt-ID" Binding="{Binding Id}" Width="220"/><DataGridTextColumn Header="Quelle" Binding="{Binding Source}" Width="*"/><DataGridTextColumn Header="Größe" Binding="{Binding Size}" Width="100"/><DataGridTextColumn Header="Status" Binding="{Binding State}" Width="110"/></DataGrid.Columns></DataGrid></Grid></TabItem>
    <TabItem><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel><TextBlock Text="Windows-Sicherheit" FontSize="18" FontWeight="SemiBold"/><TextBlock Text="Neustartpflichtige Änderungen werden vorbereitet und nach dem nächsten Login erneut geprüft." Foreground="#60717B" Margin="0,4,0,16"/>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Speicherintegrität (HVCI)" FontWeight="SemiBold"/><TextBlock x:Name="HvciDetail" Text="-" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="HvciToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Credential Guard" FontWeight="SemiBold"/><TextBlock x:Name="CredentialDetail" Text="-" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="CredentialToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}" Margin="0,0,0,10"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Windows-Firewall-Baseline" FontWeight="SemiBold"/><TextBlock Text="Inbound blockieren, Outbound erlauben, vorherigen Zustand sichern" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="FirewallToggle" Grid.Column="1"/></Grid></Border>
     <Border Style="{StaticResource Card}"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="Microsoft-Defender-Auditbaseline" FontWeight="SemiBold"/><TextBlock Text="ASR, Netzwerkschutz und Ordnerschutz zunächst nur protokollieren" Foreground="#60717B"/></StackPanel><ToggleButton x:Name="DefenderToggle" Grid.Column="1"/></Grid></Border>
    </StackPanel></ScrollViewer></TabItem>
   </TabControl>
   <Border Grid.Row="2" Background="#E7EDF0"><TextBlock x:Name="StatusMessage" Text="Bereit" VerticalAlignment="Center" Margin="24,0" Foreground="#455761"/></Border>
  </Grid>
 </Grid>
</Window>

```

## File: `AI_Shield_Private_Desktop/ui/private_security_settings.ps1`  
- Path: `AI_Shield_Private_Desktop/ui/private_security_settings.ps1`  
- Size: 4594 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
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

```

## File: `AI_Shield_Private_Desktop/ui/start_private_ui.ps1`  
- Path: `AI_Shield_Private_Desktop/ui/start_private_ui.ps1`  
- Size: 13859 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([switch]$ResumeAfterReboot)

$ErrorActionPreference="Stop"
$script:UiScriptPath=$PSCommandPath
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    $arguments=@("-NoProfile","-ExecutionPolicy","Bypass","-STA","-File",('"'+$PSCommandPath+'"'))
    if($ResumeAfterReboot){$arguments+="-ResumeAfterReboot"}
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
    exit 0
}

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml,System.Windows.Forms
. (Join-Path $PSScriptRoot "..\private_common.ps1")
$root=Get-AIShieldPrivateRoot
$stateRoot=Join-Path $env:ProgramData "AIShield\private-desktop"
$uiStatePath=Join-Path $stateRoot "ui-settings.json"
$resumeTask="AIShieldPrivateUIResume"
$script:refreshing=$false

function Show-Error([string]$Message){[Windows.MessageBox]::Show($Message,"AI Shield",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Error)|Out-Null}
function Set-Message([string]$Message){$StatusMessage.Text=$Message}
function Read-UiState {
    if(Test-Path -LiteralPath $uiStatePath){$state=Get-Content $uiStatePath -Raw|ConvertFrom-Json;if($state.schema-eq"AIShieldPrivateUiSettings/1"){return $state}}
    return [pscustomobject]@{schema="AIShieldPrivateUiSettings/1";harden_downloads=$false;strict_browser=$false;block_unsolicited_inbound=$false}
}
function Write-UiState($State){New-Item -ItemType Directory -Force $stateRoot|Out-Null;$temporary="$uiStatePath.$PID.tmp";[IO.File]::WriteAllText($temporary,($State|ConvertTo-Json -Depth 3),[Text.UTF8Encoding]::new($false));Move-Item $temporary $uiStatePath -Force}
function Register-ResumeTask {
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -ExecutionPolicy Bypass -STA -File `"$script:UiScriptPath`" -ResumeAfterReboot")
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $principalTask=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $resumeTask -Action $action -Trigger $trigger -Principal $principalTask -Force|Out-Null
}
function Apply-ProtectionState {
    $state=Read-UiState;$args=@("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $PSScriptRoot "..\start_private_desktop.ps1"))
    if($state.harden_downloads){$args+="-HardenDownloads"};if($state.strict_browser){$args+="-StrictBrowser"};if($state.block_unsolicited_inbound){$args+="-BlockUnsolicitedInbound"}
    & powershell.exe @args|Out-Null;if($LASTEXITCODE-ne0){throw "Die signierte Schutz-Policy konnte nicht aktiviert werden."}
}
function Get-Audits {
    $directory=Join-Path $env:ProgramData "AIShield\audit";if(-not(Test-Path -LiteralPath $directory)){return @()}
    return @(Get-ChildItem -LiteralPath $directory -Filter *.bin -File|Sort-Object LastWriteTime -Descending|ForEach-Object{[pscustomobject]@{Name=$_.Name;Path=$_.FullName;Size=("{0:N1} KiB"-f($_.Length/1KB));Modified=$_.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss");Verification="Nicht geprüft"}})
}
function Get-Quarantine {
    $journal=Join-Path $env:ProgramData "AIShield\quarantine\journal.jsonl";if(-not(Test-Path -LiteralPath $journal)){return @()}
    $latest=[ordered]@{};Get-Content -LiteralPath $journal -ErrorAction SilentlyContinue|ForEach-Object{try{$row=$_|ConvertFrom-Json;if($row.id){$latest[[string]$row.id]=$row}}catch{}}
    $restore=Join-Path $env:ProgramData "AIShield\quarantine\restore.jsonl";if(Test-Path $restore){Get-Content $restore|ForEach-Object{try{$r=$_|ConvertFrom-Json;if($latest.Contains([string]$r.id)){$latest[[string]$r.id]|Add-Member NoteProperty state "released" -Force}}catch{}}}
    return @($latest.Values|Where-Object{$_.state-in@("committed","released")}|ForEach-Object{[pscustomobject]@{Id=[string]$_.id;Source=[string]$_.source;Size=$(if($_.size){("{0:N1} KiB"-f([double]$_.size/1KB))}else{"-"});State=[string]$_.state}})
}
function Read-Reason {
    $dialog=[Windows.Window]::new();$dialog.Title="Begründung der Freigabe";$dialog.Width=440;$dialog.Height=210;$dialog.WindowStartupLocation="CenterOwner";$dialog.Owner=$window;$dialog.ResizeMode="NoResize"
    $panel=[Windows.Controls.StackPanel]::new();$panel.Margin=20;$label=[Windows.Controls.TextBlock]::new();$label.Text="Warum soll diese Datei aus der Quarantäne freigegeben werden?";$label.TextWrapping="Wrap";$box=[Windows.Controls.TextBox]::new();$box.Margin="0,12,0,16";$box.Height=54;$box.TextWrapping="Wrap";$buttons=[Windows.Controls.StackPanel]::new();$buttons.Orientation="Horizontal";$buttons.HorizontalAlignment="Right";$ok=[Windows.Controls.Button]::new();$ok.Content="Freigeben";$ok.IsDefault=$true;$cancel=[Windows.Controls.Button]::new();$cancel.Content="Abbrechen";$cancel.IsCancel=$true;$cancel.Margin="10,0,0,0";$ok.Add_Click({if($box.Text.Trim().Length-lt3){Show-Error "Bitte mindestens drei Zeichen als Begründung eingeben.";return};$dialog.DialogResult=$true});$buttons.Children.Add($ok)|Out-Null;$buttons.Children.Add($cancel)|Out-Null;$panel.Children.Add($label)|Out-Null;$panel.Children.Add($box)|Out-Null;$panel.Children.Add($buttons)|Out-Null;$dialog.Content=$panel;if($dialog.ShowDialog()){return $box.Text.Trim()};return $null
}
function Refresh-All {
    $script:refreshing=$true
    try{
        $services=@(Get-Service AIShieldCore,AIShieldBroker,AIShieldWfp,AIShieldMiniFilter,AIShieldProcessGuard -ErrorAction SilentlyContinue|ForEach-Object{[pscustomobject]@{Name=$_.Name;Status=[string]$_.Status;StartType=[string]$_.StartType}})
        $running=@($services|Where-Object { $_.Status -eq "Running" }).Count;$protected=$running-eq5
        $ProtectionState.Text=$(if($protected){"AKTIV"}else{"EINGESCHRÄNKT"});$ProtectionState.Foreground=[Windows.Media.BrushConverter]::new().ConvertFromString($(if($protected){"#138A72"}else{"#C85A4A"}));$ComponentState.Text="$running / 5";$SidebarState.Text=$(if($protected){"Geschützt"}else{"Prüfung erforderlich"});$ServiceGrid.ItemsSource=$services
        $CoreToggle.IsChecked=$protected
        $uiState=Read-UiState;$DownloadsToggle.IsChecked=[bool]$uiState.harden_downloads;$BrowserToggle.IsChecked=[bool]$uiState.strict_browser;$InboundToggle.IsChecked=[bool]$uiState.block_unsolicited_inbound
        $audits=Get-Audits;$AuditGrid.ItemsSource=$audits;$AuditState.Text=$(if($audits.Count){$audits[0].Modified}else{"Keine Audits"})
        $QuarantineGrid.ItemsSource=Get-Quarantine
        $security=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_security_settings.ps1") -Action status|ConvertFrom-Json)
        $HvciToggle.IsChecked=[bool]($security.hvci_configured-or$security.hvci_running);$CredentialToggle.IsChecked=[bool]($security.credential_guard_configured-or$security.credential_guard_running);$HvciDetail.Text=$(if($security.hvci_running-and$security.hvci_configured){"Aktiv"}elseif($security.hvci_configured){"Vorbereitet, Neustart erforderlich"}elseif($security.hvci_running){"Noch aktiv, Neustart zum Deaktivieren erforderlich"}else{"Nicht aktiv"});$CredentialDetail.Text=$(if($security.credential_guard_running-and$security.credential_guard_configured){"Aktiv"}elseif($security.credential_guard_configured){"Vorbereitet, Neustart erforderlich"}elseif($security.credential_guard_running){"Noch aktiv, Neustart zum Deaktivieren erforderlich"}else{"Nicht aktiv"})
        $FirewallToggle.IsChecked=Test-Path (Join-Path $env:ProgramData "AIShield\firewall\state.json");$DefenderToggle.IsChecked=Test-Path (Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json")
        $RestartButton.Visibility=$(if($security.restart_required){[Windows.Visibility]::Visible}else{[Windows.Visibility]::Collapsed});Set-Message ("Aktualisiert um "+(Get-Date).ToString("HH:mm:ss"))
    }catch{Set-Message "Status konnte nicht vollständig geladen werden";Show-Error $_.Exception.Message}finally{$script:refreshing=$false}
}

$reader=[System.Xml.XmlNodeReader]::new(([xml](Get-Content (Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.xaml") -Raw)))
$window=[Windows.Markup.XamlReader]::Load($reader)
foreach($name in @("Pages","PageTitle","StatusMessage","SidebarState","ProtectionState","ComponentState","AuditState","ServiceGrid","AuditGrid","QuarantineGrid","RefreshButton","RestartButton","CoreToggle","DownloadsToggle","BrowserToggle","InboundToggle","HvciToggle","CredentialToggle","FirewallToggle","DefenderToggle","HvciDetail","CredentialDetail","VerifyAuditButton","ExportAuditButton","ReleaseButton","NavDashboard","NavProtection","NavAudit","NavQuarantine","NavSystem")){Set-Variable -Name $name -Value $window.FindName($name) -Scope Script}
$nav=@(@($NavDashboard,0,"Übersicht"),@($NavProtection,1,"Schutzfunktionen"),@($NavAudit,2,"Audit"),@($NavQuarantine,3,"Quarantäne"),@($NavSystem,4,"Windows-Sicherheit"));foreach($item in $nav){$button=$item[0];$index=$item[1];$title=$item[2];$button.Add_Click({$Pages.SelectedIndex=$index;$PageTitle.Text=$title}.GetNewClosure())}
$RefreshButton.Add_Click({Refresh-All})
$CoreToggle.Add_Click({if($script:refreshing){return};try{if($CoreToggle.IsChecked){Apply-ProtectionState}else{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "..\stop_private_desktop.ps1")|Out-Null};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
foreach($entry in @(@($DownloadsToggle,"harden_downloads"),@($BrowserToggle,"strict_browser"),@($InboundToggle,"block_unsolicited_inbound"))){$toggle=$entry[0];$property=$entry[1];$toggle.Add_Click({if($script:refreshing){return};try{$state=Read-UiState;$state.$property=[bool]$toggle.IsChecked;Write-UiState $state;Apply-ProtectionState;Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}}.GetNewClosure())}
foreach($entry in @(@($HvciToggle,"hvci"),@($CredentialToggle,"credential_guard"))){$toggle=$entry[0];$setting=$entry[1];$toggle.Add_Click({if($script:refreshing){return};try{$enabled=([bool]$toggle.IsChecked).ToString().ToLowerInvariant();$result=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_security_settings.ps1") -Action set -Setting $setting -Enabled $enabled|ConvertFrom-Json);if($LASTEXITCODE-ne0){throw "Windows-Sicherheitseinstellung wurde nicht geändert."};if($result.restart_required){Register-ResumeTask};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}}.GetNewClosure())}
$FirewallToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\firewall\firewall_baseline.ps1";$action=$(if($FirewallToggle.IsChecked){"apply"}else{"rollback"});& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action $action -ConfirmSystemChange|Out-Null;if($LASTEXITCODE-ne0){throw "Firewalländerung fehlgeschlagen."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$DefenderToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\security\defender_audit_baseline.ps1";$action=$(if($DefenderToggle.IsChecked){"apply-audit"}else{"rollback"});& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action $action -ConfirmSystemChange|Out-Null;if($LASTEXITCODE-ne0){throw "Defenderänderung fehlgeschlagen."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$VerifyAuditButton.Add_Click({$selected=$AuditGrid.SelectedItem;if($null-eq$selected){Set-Message "Bitte zuerst ein Audit auswählen";return};$output=(& (Join-Path $root "build_vs\Release\ai_shield_diag.exe") audit-verify $selected.Path 2>&1)-join" ";$selected.Verification=$(if($LASTEXITCODE-eq0){"Gültig"}else{"Fehler"});$AuditGrid.Items.Refresh();Set-Message $output})
$ExportAuditButton.Add_Click({$dialog=[Windows.Forms.FolderBrowserDialog]::new();$dialog.Description="Zielordner für Auditexport wählen";if($dialog.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){try{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\admin\ai_shield_admin.ps1") -Action audit-export -OutputDirectory $dialog.SelectedPath|Out-Null;if($LASTEXITCODE-ne0){throw "Auditexport fehlgeschlagen."};Set-Message "Auditexport abgeschlossen"}catch{Show-Error $_.Exception.Message}};$dialog.Dispose()})
$ReleaseButton.Add_Click({$selected=$QuarantineGrid.SelectedItem;if($null-eq$selected-or$selected.State-ne"committed"){Set-Message "Bitte eine aktive Quarantänedatei auswählen";return};$save=[Windows.Forms.SaveFileDialog]::new();$save.Title="Ziel für freigegebene Datei";$save.FileName=[IO.Path]::GetFileName($selected.Source);if($save.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){$reason=Read-Reason;if($reason){try{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\admin\ai_shield_admin.ps1") -Action quarantine-release -ObjectId $selected.Id -Destination $save.FileName -Reason $reason|Out-Null;if($LASTEXITCODE-ne0){throw "Freigabe fehlgeschlagen."};Set-Message "Datei wurde freigegeben und protokolliert";Refresh-All}catch{Show-Error $_.Exception.Message}}};$save.Dispose()})
$RestartButton.Add_Click({if([Windows.MessageBox]::Show("Windows jetzt neu starten? Die AI-Shield-Oberfläche öffnet sich nach der Anmeldung automatisch erneut.","Neustart erforderlich",[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Question)-eq[Windows.MessageBoxResult]::Yes){Register-ResumeTask;Restart-Computer -Force}})
if($ResumeAfterReboot){Unregister-ScheduledTask -TaskName $resumeTask -Confirm:$false -ErrorAction SilentlyContinue;$window.Add_Loaded({Set-Message "Neustart abgeschlossen. Einstellungen wurden neu eingelesen."})}
$window.Add_Loaded({Refresh-All});$window.ShowDialog()|Out-Null

```

## File: `AI_Shield_Private_Desktop/ui/verify_ui_contract.ps1`  
- Path: `AI_Shield_Private_Desktop/ui/verify_ui_contract.ps1`  
- Size: 2326 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([switch]$RenderPreview)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$xamlPath = Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.xaml"
$scriptPath = Join-Path $PSScriptRoot "start_private_ui.ps1"
[xml]$xaml = Get-Content -LiteralPath $xamlPath -Raw
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$required = @(
    "Pages", "PageTitle", "StatusMessage", "SidebarState", "ProtectionState",
    "ComponentState", "AuditState", "ServiceGrid", "AuditGrid", "QuarantineGrid",
    "RefreshButton", "RestartButton", "CoreToggle", "DownloadsToggle", "BrowserToggle",
    "InboundToggle", "HvciToggle", "CredentialToggle", "FirewallToggle", "DefenderToggle",
    "HvciDetail", "CredentialDetail", "VerifyAuditButton", "ExportAuditButton", "ReleaseButton",
    "NavDashboard", "NavProtection", "NavAudit", "NavQuarantine", "NavSystem"
)
$missing = @($required | Where-Object { $null -eq $window.FindName($_) })
if ($missing.Count -gt 0) { throw "Missing UI controls: $($missing -join ', ')" }
$scriptText = Get-Content -LiteralPath $scriptPath -Raw
$unreferenced = @($required | Where-Object { $scriptText -notmatch ('\$' + [regex]::Escape($_) + '\b') })
if ($unreferenced.Count -gt 0) { throw "Controls without event/status binding: $($unreferenced -join ', ')" }
if ($window.FindName("Pages").Items.Count -ne 5) { throw "The UI must expose exactly five primary views." }

if ($RenderPreview) {
    $content = $window.Content
    $size = [Windows.Size]::new(1180, 760)
    $content.Measure($size)
    $content.Arrange([Windows.Rect]::new(0, 0, 1180, 760))
    $content.UpdateLayout()
    $bitmap = [Windows.Media.Imaging.RenderTargetBitmap]::new(
        1180, 760, 96, 96, [Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($content)
    $encoder = [Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $preview = Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.preview.png"
    $stream = [IO.File]::Create($preview)
    try { $encoder.Save($stream) } finally { $stream.Dispose() }
    Write-Output "preview=$preview"
}
Write-Output "AI Shield private desktop UI contract: PASS ($($required.Count) controls, 5 views)"

```

## File: `AI_Shield_Private_Desktop/uninstall_private_desktop.ps1`  
- Path: `AI_Shield_Private_Desktop/uninstall_private_desktop.ps1`  
- Size: 3069 Bytes  
- Modified: 2026-07-13 12:00:00 UTC

```powershell
param([switch]$PurgeSecurityData)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
if (-not (Test-AIShieldAdministrator)) {
    $forward = @()
    if ($PurgeSecurityData) { $forward += "-PurgeSecurityData" }
    Start-AIShieldElevated $PSCommandPath $forward
    exit 0
}
$root = Get-AIShieldPrivateRoot
Unregister-ScheduledTask -TaskName "AIShieldPrivateUIResume" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\AI Shield") `
    -Recurse -Force -ErrorAction SilentlyContinue
$markerPath = Join-Path $env:ProgramData "AIShield\private-desktop\install.json"
$marker = if (Test-Path -LiteralPath $markerPath) {
    Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
} else { $null }
if ($null -ne $marker -and $marker.schema -ne "AIShieldPrivateDesktopInstall/1") {
    throw "Private desktop installation state is invalid; automatic baseline rollback was stopped."
}
$firewallState = Join-Path $env:ProgramData "AIShield\firewall\state.json"
if ($null -ne $marker -and $marker.firewall_transaction_owned -eq $true -and
    (Test-Path -LiteralPath $firewallState)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\firewall\firewall_baseline.ps1") `
        -Action rollback -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Windows Firewall rollback failed; uninstall stopped." }
}
$defenderState = Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json"
if ($null -ne $marker -and $marker.defender_transaction_owned -eq $true -and
    (Test-Path -LiteralPath $defenderState)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\security\defender_audit_baseline.ps1") `
        -Action rollback -ConfirmSystemChange
    if ($LASTEXITCODE -ne 0) { throw "Microsoft Defender rollback failed; uninstall stopped." }
}
$arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
    (Join-Path $root "platform\windows\installer\uninstall_product.ps1"),
    "-Confirmation", "UNINSTALL-AI-SHIELD")
if ($PurgeSecurityData) { $arguments += "-PurgeSecurityData" }
& powershell.exe @arguments
if ($LASTEXITCODE -ne 0) { throw "AI Shield product uninstall failed." }
if ($null -ne $marker -and [string]$marker.certificate_thumbprint -match '^[A-Fa-f0-9]{40}$') {
    if ($marker.publisher_certificate_owned -eq $true) {
        Remove-Item -LiteralPath `
            "Cert:\LocalMachine\TrustedPublisher\$($marker.certificate_thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
    if ($marker.root_certificate_owned -eq $true) {
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($marker.certificate_thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
}
if (-not $PurgeSecurityData) {
    Remove-Item -LiteralPath (Split-Path $markerPath -Parent) -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output "AI Shield Private Desktop was removed."

```

