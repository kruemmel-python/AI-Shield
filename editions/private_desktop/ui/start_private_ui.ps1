param([switch]$ResumeAfterReboot)

$ErrorActionPreference="Stop"
$script:UiScriptPath=$PSCommandPath
$uiRuntimeRoot=Join-Path $env:LocalAppData "AIShield"
$uiInstancePath=Join-Path $uiRuntimeRoot "private-ui.instance.json"
$uiSignalPath=Join-Path $uiRuntimeRoot "private-ui.show.signal"
$uiLifecyclePath=Join-Path $uiRuntimeRoot "private-ui.lifecycle.log"
function Write-UiLifecycle([string]$Event){New-Item -ItemType Directory -Force -Path $uiRuntimeRoot|Out-Null;if((Test-Path $uiLifecyclePath)-and(Get-Item $uiLifecyclePath).Length-gt128KB){Move-Item $uiLifecyclePath "$uiLifecyclePath.previous" -Force};Add-Content -LiteralPath $uiLifecyclePath -Value ("{0} pid={1} event={2}"-f[DateTime]::UtcNow.ToString("o"),$PID,$Event) -Encoding UTF8}
function Signal-ExistingUi {
    if(-not(Test-Path -LiteralPath $uiInstancePath)){return $false}
    try {
        $instance=Get-Content -LiteralPath $uiInstancePath -Raw|ConvertFrom-Json
        if($instance.schema-ne"AIShieldPrivateUiInstance/1"){throw "invalid schema"}
        $process=Get-Process -Id ([int]$instance.pid) -ErrorAction Stop
        if($process.StartTime.ToUniversalTime().Ticks-ne[long]$instance.start_ticks){throw "stale process"}
        New-Item -ItemType Directory -Force -Path $uiRuntimeRoot|Out-Null
        [IO.File]::WriteAllText($uiSignalPath,[Guid]::NewGuid().ToString("N"),[Text.UTF8Encoding]::new($false))
        return $true
    } catch {
        Remove-Item -LiteralPath $uiInstancePath,$uiSignalPath -Force -ErrorAction SilentlyContinue
        return $false
    }
}
if(Signal-ExistingUi){exit 0}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    $arguments=@("-NoProfile","-WindowStyle","Hidden","-ExecutionPolicy","Bypass","-STA","-File",('"'+$PSCommandPath+'"'))
    if($ResumeAfterReboot){$arguments+="-ResumeAfterReboot"}
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
    exit 0
}

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml,System.Windows.Forms
New-Item -ItemType Directory -Force -Path $uiRuntimeRoot|Out-Null
$currentProcess=Get-Process -Id $PID
$instance=[ordered]@{schema="AIShieldPrivateUiInstance/1";pid=$PID;start_ticks=$currentProcess.StartTime.ToUniversalTime().Ticks}
[IO.File]::WriteAllText($uiInstancePath,($instance|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
Remove-Item -LiteralPath $uiSignalPath -Force -ErrorAction SilentlyContinue
Write-UiLifecycle "instance-registered"
. (Join-Path $PSScriptRoot "..\private_common.ps1")
$root=Get-AIShieldPrivateRoot
$stateRoot=Join-Path $env:ProgramData "AIShield\private-desktop"
$uiStatePath=Join-Path $stateRoot "ui-settings.json"
$resumeTask="AIShieldPrivateUIResume"
$script:refreshing=$false
$script:knownQuarantineIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:allowUiExit=$false

function Show-Error([string]$Message){[Windows.MessageBox]::Show($Message,"AI Shield",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Error)|Out-Null}
function Set-Message([string]$Message){$StatusMessage.Text=$Message}
function Get-TrayStatus {
    $manager=Join-Path $PSScriptRoot "..\tray\manage_tray_agent.ps1"
    if(-not(Test-Path -LiteralPath $manager)){return [pscustomobject]@{registered=$false;running=$false}}
    return (& powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $manager -Action status|ConvertFrom-Json)
}
function Read-UiState {
    if(Test-Path -LiteralPath $uiStatePath){$state=Get-Content $uiStatePath -Raw|ConvertFrom-Json;if($state.schema-eq"AIShieldPrivateUiSettings/2"){return $state}}
    return [pscustomobject]@{schema="AIShieldPrivateUiSettings/2";harden_downloads=$true;strict_browser=$false;block_unsolicited_inbound=$false}
}
function Write-UiState($State){New-Item -ItemType Directory -Force $stateRoot|Out-Null;$temporary="$uiStatePath.$PID.tmp";[IO.File]::WriteAllText($temporary,($State|ConvertTo-Json -Depth 3),[Text.UTF8Encoding]::new($false));Move-Item $temporary $uiStatePath -Force}
function Register-ResumeTask {
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument ("-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File `"$script:UiScriptPath`" -ResumeAfterReboot")
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $principalTask=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $resumeTask -Action $action -Trigger $trigger -Principal $principalTask -Force|Out-Null
}
function Get-BrowserSensorStatus {
    $script = Join-Path $root "platform\windows\browser_extension\install_browser_sensor.ps1"
    return (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action status | ConvertFrom-Json)
}
function Open-BrowserSensorSetup([ValidateSet("edge","chrome")][string]$Browser) {
    $status = Get-BrowserSensorStatus
    if (-not $status.ready) { throw "Den Browsersensor zuerst mit dem Schalter aktivieren." }
    [Windows.Clipboard]::SetText([string]$status.extension_directory)
    $candidates = if ($Browser -eq "edge") { @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"),
        (Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe"))
    } else { @(
        (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"),
        (Join-Path $env:LocalAppData "Google\Chrome\Application\chrome.exe")) }
    $executable = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $executable) { throw "Der ausgewählte Browser wurde nicht gefunden." }
    $url = if ($Browser -eq "edge") { "edge://extensions" } else { "chrome://extensions" }
    Start-Process -FilePath $executable -ArgumentList $url
    [Windows.MessageBox]::Show(
        "Aktiviere einmalig den Entwicklermodus und wähle 'Entpackte Erweiterung laden'. Navigiere in den folgenden Ordner, markiere keine Datei und bestätige unten mit 'Ordner auswählen':`n`n$($status.extension_directory)`n`nErwartete Erweiterungs-ID: $($status.extension_id)",
        "AI Shield Browsersensor", [Windows.MessageBoxButton]::OK, [Windows.MessageBoxImage]::Information) | Out-Null
}
function Apply-ProtectionState {
    $state=Read-UiState;$args=@("-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $PSScriptRoot "..\start_private_desktop.ps1"))
    if($state.harden_downloads){$args+="-HardenDownloads"};if($state.strict_browser){$args+="-StrictBrowser"};if($state.block_unsolicited_inbound){$args+="-BlockUnsolicitedInbound"}
    & powershell.exe @args|Out-Null;if($LASTEXITCODE-ne0){throw "Die signierte Schutz-Policy konnte nicht aktiviert werden."}
}
function Get-ContentPolicyBroker {
    $service=Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
    if($null-eq$service){throw "AIShieldBroker ist nicht installiert."}
    $path=([regex]::Match($service.PathName,'^"?([^\"]+?\.exe)"?(?:\s|$)')).Groups[1].Value
    if(-not(Test-Path -LiteralPath $path)){throw "AIShieldBroker-Binärdatei wurde nicht gefunden."}
    return $path
}
function Get-ContentPolicy {
    $broker=Get-ContentPolicyBroker
    $value=& $broker content-policy-status
    if($LASTEXITCODE-ne0){throw "Dateityp-Richtlinie konnte nicht gelesen werden."}
    return ($value|ConvertFrom-Json)
}
function Set-ContentPolicy {
    $mask=0
    if($DocumentsToggle.IsChecked){$mask=$mask-bor 1};if($ArchivesToggle.IsChecked){$mask=$mask-bor 2}
    if($ImagesToggle.IsChecked){$mask=$mask-bor 4};if($AudioToggle.IsChecked){$mask=$mask-bor 8}
    if($VideoToggle.IsChecked){$mask=$mask-bor 16};if($WebFilesToggle.IsChecked){$mask=$mask-bor 32}
    if($ProgramsToggle.IsChecked){$mask=$mask-bor 64};if($WindowsScriptsToggle.IsChecked){$mask=$mask-bor 128}
    if($DeveloperScriptsToggle.IsChecked){$mask=$mask-bor 256};if($LaunchersToggle.IsChecked){$mask=$mask-bor 512}
    $fail=$(if($ScanFailureToggle.IsChecked){1}else{0})
    $release=$(if($ReleaseRequiredToggle.IsChecked){1}else{0})
    $broker=Get-ContentPolicyBroker
    & $broker content-policy-set $mask $fail $release|Out-Null
    if($LASTEXITCODE-ne0){throw "Dateityp-Richtlinie konnte nicht DPAPI-geschützt gespeichert werden."}
}
function Get-CurrentProcessNames {
    $names=@{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|ForEach-Object{
        if($null-ne$_.ProcessId-and-not[string]::IsNullOrWhiteSpace([string]$_.Name)){
            $names[[string]$_.ProcessId]=[string]$_.Name
        }
    }
    return $names
}
function Get-Audits {
    $directory=Join-Path $env:ProgramData "AIShield\audit";if(-not(Test-Path -LiteralPath $directory)){return @()}
    return @(Get-ChildItem -LiteralPath $directory -Filter *.bin -File|Sort-Object LastWriteTime -Descending|ForEach-Object{[pscustomobject]@{Name=$_.Name;Path=$_.FullName;Size=("{0:N1} KiB"-f($_.Length/1KB));Modified=$_.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss");Verification="Nicht geprüft"}})
}
function Show-AuditViewer($Selected) {
    if($null-eq$Selected){Set-Message "Bitte zuerst ein Audit auswählen";return}
    $diag=Join-Path $root "build_vs\Release\ai_shield_diag.exe"
    $raw=(& $diag audit-dump-json $Selected.Path 2>&1)-join""
    if($LASTEXITCODE-ne0){$Selected.Verification="Fehler";$AuditGrid.Items.Refresh();throw "Audit ist beschädigt oder nicht lesbar."}
    $decoded=$raw|ConvertFrom-Json
    $Selected.Verification="Gültig";$AuditGrid.Items.Refresh()
    $processNames=Get-CurrentProcessNames
    $rows=@($decoded.records|ForEach-Object{
        $processId=[string]$_.process_id
        $processName=$(if($processNames.ContainsKey($processId)){$processNames[$processId]}else{"Nicht mehr aktiv"})
        [pscustomobject]@{
        Sequence=[string]$_.sequence;Runtime=("{0:N3} s"-f([double]$_.monotonic_ns/1000000000));
        Status=$(if($_.disposition-eq"blocked"){"Blockiert"}else{"Beobachtet"});Reason=("0x{0:X8}"-f[uint32]$_.reason_mask);
        ProcessName=$processName;Process=$processId;Parent=[string]$_.parent_process_id;Flow=[string]$_.flow_id;File=[string]$_.file_id;
        Volume=[string]$_.volume_id;Provenance=[string]$_.provenance_id;Policy=[string]$_.policy_version;Model=[string]$_.model_version;
        Evidence=[string]$_.evidence_hash}})
    $viewerReader=[System.Xml.XmlNodeReader]::new(([xml](Get-Content (Join-Path $PSScriptRoot "AIShield.AuditViewer.xaml") -Raw)))
    $viewer=[Windows.Markup.XamlReader]::Load($viewerReader);$viewer.Owner=$window
    $viewerGrid=$viewer.FindName("ViewerGrid");$viewerSummary=$viewer.FindName("ViewerSummary");$viewerCount=$viewer.FindName("ViewerCount");$viewerFilter=$viewer.FindName("ViewerFilter");$viewerClose=$viewer.FindName("ViewerCloseButton")
    $viewerSummary.Text="$($Selected.Name) · Integrität gültig · $($decoded.record_count) Datensätze"
    $viewerGrid.ItemsSource=$rows;$viewerCount.Text="$($rows.Count) Datensätze"
    $viewerFilter.Add_TextChanged({$term=$viewerFilter.Text.Trim();$filtered=$(if([string]::IsNullOrWhiteSpace($term)){$rows}else{@($rows|Where-Object{(($_.PSObject.Properties.Value)-join' ') -like "*$term*"})});$viewerGrid.ItemsSource=@($filtered);$viewerCount.Text="$(@($filtered).Count) Datensätze"})
    $viewerClose.Add_Click({$viewer.Close()});$viewer.ShowDialog()|Out-Null
}
function Get-Quarantine {
    $journal=Join-Path $env:ProgramData "AIShield\quarantine\journal.jsonl";if(-not(Test-Path -LiteralPath $journal)){return @()}
    $latest=[ordered]@{};Get-Content -LiteralPath $journal -ErrorAction SilentlyContinue|ForEach-Object{try{$row=$_|ConvertFrom-Json;if($row.id){$latest[[string]$row.id]=$row}}catch{}}
    $restore=Join-Path $env:ProgramData "AIShield\quarantine\restore.jsonl";if(Test-Path $restore){Get-Content $restore|ForEach-Object{try{$r=$_|ConvertFrom-Json;if($latest.Contains([string]$r.id)){$latest[[string]$r.id]|Add-Member NoteProperty state "released" -Force}}catch{}}}
    return @($latest.Values|Where-Object{$_.state-in@("committed","released")}|ForEach-Object{
        $classification=switch([string]$_.classification){"pending_user_release"{"Wartet auf Freigabe"};"malware_detected"{"Schadsoftware erkannt"};"suspicious_file_structure"{"Verdächtige Dateistruktur"};"parser_risk_scan_unavailable"{"Prüfung nicht möglich"};"external_untrusted_executable"{"Nicht vertrauenswürdige Ausführung"};default{[string]$_.classification}}
        [pscustomobject]@{Id=[string]$_.id;Source=[string]$_.source;Size=$(if($_.size){("{0:N1} KiB"-f([double]$_.size/1KB))}else{"-"});State=[string]$_.state;Classification=$classification}})
}
function Initialize-QuarantineNotifications {
    foreach($item in @(Get-Quarantine)){if($item.State-eq"committed"){$null=$script:knownQuarantineIds.Add($item.Id)}}
}
function Update-QuarantineNotifications {
    $items=@(Get-Quarantine);$QuarantineGrid.ItemsSource=$items
    $new=@($items|Where-Object{$_.State-eq"committed"-and$script:knownQuarantineIds.Add($_.Id)})
    if($new.Count-eq0){return}
    $names=@($new|Select-Object -First 3|ForEach-Object{[IO.Path]::GetFileName($_.Source)})-join"`n"
    $suffix=$(if($new.Count-gt3){"`n... und $($new.Count-3) weitere"}else{""})
    [Windows.MessageBox]::Show("AI Shield hat $($new.Count) neuen Download gesichert. Die Datei kann erst nach Prüfung und begründeter Freigabe auf der Seite 'Quarantäne' geöffnet werden.`n`n$names$suffix","Download gesichert",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Warning)|Out-Null
    Set-Message "$($new.Count) Download(s) warten auf Freigabe"
}
function Invoke-Recovery([string]$Action, [string]$IncidentId = '', [string]$BackupRoot = '', [switch]$ConfirmRestore) {
    $scriptPath = Join-Path $root "platform\windows\ransomware\ransomware_recovery.ps1"
    if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Das Wiederherstellungsmodul ist nicht installiert." }
    $parameters = @{ Action = $Action }
    if ($IncidentId) { $parameters.IncidentId = $IncidentId }
    if ($BackupRoot) { $parameters.BackupRoot = $BackupRoot }
    if ($ConfirmRestore) { $parameters.ConfirmRestore = $true }
    $json = (& $scriptPath @parameters) -join "`n"
    if ([string]::IsNullOrWhiteSpace($json)) { return $null }
    return $json | ConvertFrom-Json
}
function Get-RecoveryIncidents {
    $records = Invoke-Recovery 'incidents'
    if ($null -eq $records) { return @() }
    return @($records | ForEach-Object {
        [pscustomobject]@{
            Id = [string]$_.incident_id
            Created = ([DateTime]$_.created_utc).ToLocalTime().ToString('dd.MM.yyyy HH:mm')
            State = $(if ($_.state -eq 'confirmed') { 'Bestätigt' } else { 'Verdächtig' })
            Score = [string]$_.score
            Changed = @($_.changed).Count
            Deleted = @($_.deleted).Count
            RestoreState = $(if ($_.restore_state -eq 'completed') { 'Abgeschlossen' } else { 'Nicht gestartet' })
        }
    })
}
function Update-RecoveryStatus {
    $status = Invoke-Recovery 'status'
    $used = '{0:N1} MiB' -f ([double]$status.vault_bytes / 1MB)
    $snapshot = if ([string]::IsNullOrWhiteSpace([string]$status.latest_snapshot)) { 'keine Baseline' } else { [string]$status.latest_snapshot }
    $RecoveryStatus.Text = "Versionsspeicher: $used · Letzte Baseline: $snapshot"
    $IncidentGrid.ItemsSource = Get-RecoveryIncidents
}
function Initialize-RecoveryBaselineIfRequired {
    $pending = Join-Path $env:ProgramData "AIShield\recovery-baseline.pending"
    $status = Invoke-Recovery 'status'
    if ([string]::IsNullOrWhiteSpace([string]$status.latest_snapshot)) {
        Set-Message "Erste Recovery-Baseline wird erstellt ..."
        $snapshot = Invoke-Recovery 'initialize'
        if (-not $snapshot.snapshot_id) { throw "Die erste Recovery-Baseline konnte nicht erstellt werden." }
    }
    Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
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
        $trayStatus=Get-TrayStatus;$TrayToggle.IsChecked=[bool]$trayStatus.registered
        $TrayDetail.Text=$(if($trayStatus.running){"Aktiv; startet automatisch bei jeder Windows-Anmeldung"}elseif($trayStatus.registered){"Registriert; wird bei der nächsten Anmeldung gestartet"}else{"Nicht für den automatischen Start registriert"})
        $uiState=Read-UiState;$DownloadsToggle.IsChecked=[bool]$uiState.harden_downloads;$BrowserToggle.IsChecked=[bool]$uiState.strict_browser;$InboundToggle.IsChecked=[bool]$uiState.block_unsolicited_inbound
        $contentPolicy=Get-ContentPolicy;$mask=[int]$contentPolicy.enabled_categories
        $DocumentsToggle.IsChecked=($mask-band 1)-ne0;$ArchivesToggle.IsChecked=($mask-band 2)-ne0;$ImagesToggle.IsChecked=($mask-band 4)-ne0
        $AudioToggle.IsChecked=($mask-band 8)-ne0;$VideoToggle.IsChecked=($mask-band 16)-ne0;$WebFilesToggle.IsChecked=($mask-band 32)-ne0
        $ProgramsToggle.IsChecked=($mask-band 64)-ne0;$WindowsScriptsToggle.IsChecked=($mask-band 128)-ne0
        $DeveloperScriptsToggle.IsChecked=($mask-band 256)-ne0;$LaunchersToggle.IsChecked=($mask-band 512)-ne0
        $ScanFailureToggle.IsChecked=[bool]$contentPolicy.fail_closed
        $ReleaseRequiredToggle.IsChecked=[bool]$contentPolicy.release_required
        $browserStatus=Get-BrowserSensorStatus;$BrowserSensorToggle.IsChecked=[bool]$browserStatus.ready
        $BrowserSensorDetail.Text=$(if(-not$browserStatus.ready){"Nicht installiert"}elseif($browserStatus.connected){"Verbunden; letztes Browserereignis: "+([DateTime]$browserStatus.last_event_utc).ToLocalTime().ToString("dd.MM.yyyy HH:mm")}elseif($browserStatus.edge_loaded-or$browserStatus.chrome_loaded){"Erweiterung geladen, aber Native Host noch nicht verbunden; auf 'Neu laden' klicken"}else{"Host installiert; Ordner selbst auswählen, nicht manifest.json"})
        $EdgeSetupButton.IsEnabled=[bool]$browserStatus.ready;$ChromeSetupButton.IsEnabled=[bool]$browserStatus.ready
        $audits=Get-Audits;$AuditGrid.ItemsSource=$audits;$AuditState.Text=$(if($audits.Count){$audits[0].Modified}else{"Keine Audits"})
        $QuarantineGrid.ItemsSource=Get-Quarantine
        Update-RecoveryStatus
        $security=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_security_settings.ps1") -Action status|ConvertFrom-Json)
        $kernelHardware=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\security\kernel_hardware_hardening.ps1") -Action status|ConvertFrom-Json)
        $KernelHardwareToggle.IsChecked=[bool]$kernelHardware.transaction
        $KernelHardwareDetail.Text=$(if($kernelHardware.hardware_rooted_chain){"Hardwareverwurzelte Kette aktiv; HVCI, TPM und Secure Boot wirksam"}elseif(-not$kernelHardware.secure_boot){"Teilaktiv: HVCI/Blockliste verfügbar; Secure Boot und Produktionssignatur fehlen"}else{"Teilaktiv; TPM, DMA, Secure Launch oder Neustartstatus prüfen"})
        $HvciToggle.IsChecked=[bool]($security.hvci_configured-or$security.hvci_running);$CredentialToggle.IsChecked=[bool]($security.credential_guard_configured-or$security.credential_guard_running);$HvciDetail.Text=$(if($security.hvci_running-and$security.hvci_configured){"Aktiv"}elseif($security.hvci_configured){"Vorbereitet, Neustart erforderlich"}elseif($security.hvci_running){"Noch aktiv, Neustart zum Deaktivieren erforderlich"}else{"Nicht aktiv"});$CredentialDetail.Text=$(if($security.credential_guard_running-and$security.credential_guard_configured){"Aktiv"}elseif($security.credential_guard_configured){"Vorbereitet, Neustart erforderlich"}elseif($security.credential_guard_running){"Noch aktiv, Neustart zum Deaktivieren erforderlich"}else{"Nicht aktiv"})
        $HvciToggle.IsEnabled=-not[bool]$kernelHardware.transaction
        $FirewallToggle.IsChecked=Test-Path (Join-Path $env:ProgramData "AIShield\firewall\state.json");$DefenderToggle.IsChecked=Test-Path (Join-Path $env:ProgramData "AIShield\hardening\defender-audit-backup.json")
        $RestartButton.Visibility=$(if($security.restart_required-or$kernelHardware.restart_required){[Windows.Visibility]::Visible}else{[Windows.Visibility]::Collapsed});Set-Message ("Aktualisiert um "+(Get-Date).ToString("HH:mm:ss"))
    }catch{Set-Message "Status konnte nicht vollständig geladen werden";Show-Error $_.Exception.Message}finally{$script:refreshing=$false}
}

Write-UiLifecycle "xaml-load-start"
$reader=[System.Xml.XmlNodeReader]::new(([xml](Get-Content (Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.xaml") -Raw)))
$window=[Windows.Markup.XamlReader]::Load($reader)
Write-UiLifecycle "xaml-load-complete"
foreach($name in @("Pages","PageTitle","StatusMessage","SidebarState","ProtectionState","ComponentState","AuditState","ServiceGrid","AuditGrid","QuarantineGrid","RecoveryStatus","IncidentGrid","SnapshotButton","BackupButton","DetectRansomwareButton","RestorePlanButton","RestoreIncidentButton","RefreshButton","RestartButton","TrayToggle","TrayDetail","CoreToggle","DownloadsToggle","DocumentsToggle","ArchivesToggle","ImagesToggle","AudioToggle","VideoToggle","WebFilesToggle","ProgramsToggle","WindowsScriptsToggle","DeveloperScriptsToggle","LaunchersToggle","ReleaseRequiredToggle","ScanFailureToggle","BrowserToggle","InboundToggle","BrowserSensorToggle","BrowserSensorDetail","EdgeSetupButton","ChromeSetupButton","KernelHardwareToggle","KernelHardwareDetail","BitLockerButton","HvciToggle","CredentialToggle","FirewallToggle","DefenderToggle","HvciDetail","CredentialDetail","ViewAuditButton","OpenAuditFileButton","VerifyAuditButton","ExportAuditButton","ReleaseButton","NavDashboard","NavProtection","NavAudit","NavQuarantine","NavRecovery","NavSystem")){Set-Variable -Name $name -Value $window.FindName($name) -Scope Script}
$nav=@(@($NavDashboard,0,"Übersicht"),@($NavProtection,1,"Schutzfunktionen"),@($NavAudit,2,"Audit"),@($NavQuarantine,3,"Quarantäne"),@($NavRecovery,4,"Wiederherstellung"),@($NavSystem,5,"Windows-Sicherheit"));foreach($item in $nav){$button=$item[0];$index=$item[1];$title=$item[2];$button.Add_Click({$Pages.SelectedIndex=$index;$PageTitle.Text=$title}.GetNewClosure())}
$RefreshButton.Add_Click({Refresh-All})
$TrayToggle.Add_Click({if($script:refreshing){return};try{$manager=Join-Path $PSScriptRoot "..\tray\manage_tray_agent.ps1";$action=$(if($TrayToggle.IsChecked){"install"}else{"uninstall"});& powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $manager -Action $action|Out-Null;if($LASTEXITCODE-ne0){throw "Tray-Agent konnte nicht geändert werden."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$CoreToggle.Add_Click({if($script:refreshing){return};try{if($CoreToggle.IsChecked){Apply-ProtectionState}else{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "..\stop_private_desktop.ps1")|Out-Null};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
foreach($entry in @(@($DownloadsToggle,"harden_downloads"),@($BrowserToggle,"strict_browser"),@($InboundToggle,"block_unsolicited_inbound"))){$toggle=$entry[0];$property=$entry[1];$toggle.Add_Click({if($script:refreshing){return};try{$state=Read-UiState;$state.$property=[bool]$toggle.IsChecked;Write-UiState $state;Apply-ProtectionState;Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}}.GetNewClosure())}
foreach($toggle in @($DocumentsToggle,$ArchivesToggle,$ImagesToggle,$AudioToggle,$VideoToggle,$WebFilesToggle,$ProgramsToggle,$WindowsScriptsToggle,$DeveloperScriptsToggle,$LaunchersToggle,$ReleaseRequiredToggle,$ScanFailureToggle)){$toggle.Add_Click({if($script:refreshing){return};try{Set-ContentPolicy;Set-Message "Dateityp-Richtlinie wurde aktiviert"}catch{Show-Error $_.Exception.Message;Refresh-All}})}
$BrowserSensorToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\browser_extension\install_browser_sensor.ps1";$action=$(if($BrowserSensorToggle.IsChecked){"install"}else{"uninstall"});$arguments=@("-NoProfile","-ExecutionPolicy","Bypass","-File",$script,"-Action",$action,"-ConfirmSystemChange");if($action-eq"install"){$certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $root "driver_package\Release\ai_shield_testsigning.cer"));$arguments+=@("-PublisherThumbprint",$certificate.Thumbprint)};& powershell.exe @arguments|Out-Null;if($LASTEXITCODE-ne0){throw "Browsersensor konnte nicht geändert werden."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$EdgeSetupButton.Add_Click({try{Open-BrowserSensorSetup "edge"}catch{Show-Error $_.Exception.Message}})
$ChromeSetupButton.Add_Click({try{Open-BrowserSensorSetup "chrome"}catch{Show-Error $_.Exception.Message}})
$KernelHardwareToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\security\kernel_hardware_hardening.ps1";$action=$(if($KernelHardwareToggle.IsChecked){"apply"}else{"rollback"});$result=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action $action -ConfirmSystemChange|ConvertFrom-Json);if($LASTEXITCODE-ne0){throw "Kernel-/Hardware-Härtung konnte nicht geändert werden."};if($result.restart_required){Register-ResumeTask};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$BitLockerButton.Add_Click({try{[Windows.MessageBox]::Show("BitLocker erst aktivieren, nachdem der Wiederherstellungsschlüssel extern gesichert und geprüft wurde.","BitLocker-Sicherheit",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Warning)|Out-Null;Start-Process "ms-settings:deviceencryption"}catch{Show-Error $_.Exception.Message}})
foreach($entry in @(@($HvciToggle,"hvci"),@($CredentialToggle,"credential_guard"))){$toggle=$entry[0];$setting=$entry[1];$toggle.Add_Click({if($script:refreshing){return};try{$enabled=([bool]$toggle.IsChecked).ToString().ToLowerInvariant();$result=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "private_security_settings.ps1") -Action set -Setting $setting -Enabled $enabled|ConvertFrom-Json);if($LASTEXITCODE-ne0){throw "Windows-Sicherheitseinstellung wurde nicht geändert."};if($result.restart_required){Register-ResumeTask};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}}.GetNewClosure())}
$FirewallToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\firewall\firewall_baseline.ps1";$action=$(if($FirewallToggle.IsChecked){"apply"}else{"rollback"});& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action $action -ConfirmSystemChange|Out-Null;if($LASTEXITCODE-ne0){throw "Firewalländerung fehlgeschlagen."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$DefenderToggle.Add_Click({if($script:refreshing){return};try{$script=Join-Path $root "platform\windows\security\defender_audit_baseline.ps1";$action=$(if($DefenderToggle.IsChecked){"apply-audit"}else{"rollback"});& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Action $action -ConfirmSystemChange|Out-Null;if($LASTEXITCODE-ne0){throw "Defenderänderung fehlgeschlagen."};Refresh-All}catch{Show-Error $_.Exception.Message;Refresh-All}})
$ViewAuditButton.Add_Click({try{Show-AuditViewer $AuditGrid.SelectedItem}catch{Show-Error $_.Exception.Message}})
$OpenAuditFileButton.Add_Click({$dialog=[Windows.Forms.OpenFileDialog]::new();$dialog.Title="Exportierte AI-Shield-Auditdatei öffnen";$dialog.Filter="AI-Shield Audit (*.bin)|*.bin";$dialog.Multiselect=$false;if($dialog.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){try{Show-AuditViewer ([pscustomobject]@{Name=[IO.Path]::GetFileName($dialog.FileName);Path=$dialog.FileName;Verification="Nicht geprüft"})}catch{Show-Error $_.Exception.Message}};$dialog.Dispose()})
$VerifyAuditButton.Add_Click({$selected=$AuditGrid.SelectedItem;if($null-eq$selected){Set-Message "Bitte zuerst ein Audit auswählen";return};$output=(& (Join-Path $root "build_vs\Release\ai_shield_diag.exe") audit-verify $selected.Path 2>&1)-join" ";$selected.Verification=$(if($LASTEXITCODE-eq0){"Gültig"}else{"Fehler"});$AuditGrid.Items.Refresh();Set-Message $output})
$ExportAuditButton.Add_Click({$dialog=[Windows.Forms.FolderBrowserDialog]::new();$dialog.Description="Zielordner für Auditexport wählen";if($dialog.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){try{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\admin\ai_shield_admin.ps1") -Action audit-export -OutputDirectory $dialog.SelectedPath|Out-Null;if($LASTEXITCODE-ne0){throw "Auditexport fehlgeschlagen."};Set-Message "Auditexport abgeschlossen"}catch{Show-Error $_.Exception.Message}};$dialog.Dispose()})
$ReleaseButton.Add_Click({$selected=$QuarantineGrid.SelectedItem;if($null-eq$selected-or$selected.State-ne"committed"){Set-Message "Bitte eine aktive Quarantänedatei auswählen";return};$save=[Windows.Forms.SaveFileDialog]::new();$save.Title="Ziel für freigegebene Datei";$save.FileName=[IO.Path]::GetFileName($selected.Source);if($save.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){$reason=Read-Reason;if($reason){try{& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "platform\windows\admin\ai_shield_admin.ps1") -Action quarantine-release -ObjectId $selected.Id -Destination $save.FileName -Reason $reason|Out-Null;if($LASTEXITCODE-ne0){throw "Freigabe fehlgeschlagen."};Set-Message "Datei wurde freigegeben und protokolliert";Refresh-All}catch{Show-Error $_.Exception.Message}}};$save.Dispose()})
$SnapshotButton.Add_Click({try{Set-Message "Baseline wird gesichert ...";$result=Invoke-Recovery 'snapshot';Set-Message "$(@($result.records).Count) Dateien wurden versioniert";Update-RecoveryStatus}catch{Show-Error $_.Exception.Message}})
$BackupButton.Add_Click({$dialog=[Windows.Forms.FolderBrowserDialog]::new();$dialog.Description="Externes oder Netzlaufwerk für die Recovery-Sicherung wählen";if($dialog.ShowDialog()-eq[Windows.Forms.DialogResult]::OK){try{Set-Message "Externe Sicherung wird erstellt ...";$result=Invoke-Recovery -Action 'backup' -BackupRoot $dialog.SelectedPath;Set-Message "$($result.files) Dateien wurden extern gesichert"}catch{Show-Error $_.Exception.Message}};$dialog.Dispose()})
$DetectRansomwareButton.Add_Click({try{Set-Message "Geschützte Dateien werden geprüft ...";$result=Invoke-Recovery 'detect';if($result.kind-eq'incident'){[Windows.MessageBox]::Show("AI Shield hat einen $($result.state)-Vorfall mit Risikowert $($result.score) erkannt. Prüfe den Wiederherstellungsplan, bevor Dateien zurückgespielt werden.","Ransomware-Warnung",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Warning)|Out-Null}else{Set-Message "Keine kritische Veränderungsserie erkannt (Risiko $($result.score))"};Update-RecoveryStatus}catch{Show-Error $_.Exception.Message}})
$RestorePlanButton.Add_Click({try{$selected=$IncidentGrid.SelectedItem;if($null-eq$selected){Set-Message "Bitte zuerst einen Vorfall auswählen";return};$plan=Invoke-Recovery 'restore-plan' $selected.Id;[Windows.MessageBox]::Show("Wiederherstellbare Dateien: $(@($plan.items).Count)`nFehlende Versionen: $(@($plan.missing).Count)`n`nEs wurden noch keine Dateien verändert.","Wiederherstellungsplan",[Windows.MessageBoxButton]::OK,[Windows.MessageBoxImage]::Information)|Out-Null}catch{Show-Error $_.Exception.Message}})
$RestoreIncidentButton.Add_Click({try{$selected=$IncidentGrid.SelectedItem;if($null-eq$selected){Set-Message "Bitte zuerst einen Vorfall auswählen";return};$plan=Invoke-Recovery 'restore-plan' $selected.Id;if(@($plan.items).Count-eq0){throw "Für diesen Vorfall sind keine verifizierten Versionen verfügbar."};$answer=[Windows.MessageBox]::Show("$(@($plan.items).Count) Dateien auf den Stand vor dem Vorfall zurücksetzen? Bestehende geänderte Dateien werden im Konfliktspeicher aufbewahrt.","Wiederherstellung bestätigen",[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Warning);if($answer-eq[Windows.MessageBoxResult]::Yes){$result=Invoke-Recovery 'restore' $selected.Id -ConfirmRestore;Set-Message "$($result.restored) Dateien wurden hashverifiziert wiederhergestellt";Update-RecoveryStatus}}catch{Show-Error $_.Exception.Message}})
$RestartButton.Add_Click({if([Windows.MessageBox]::Show("Windows jetzt neu starten? Die AI-Shield-Oberfläche öffnet sich nach der Anmeldung automatisch erneut.","Neustart erforderlich",[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Question)-eq[Windows.MessageBoxResult]::Yes){Register-ResumeTask;Restart-Computer -Force}})
if($ResumeAfterReboot){Unregister-ScheduledTask -TaskName $resumeTask -Confirm:$false -ErrorAction SilentlyContinue;$window.Add_Loaded({Set-Message "Neustart abgeschlossen. Einstellungen wurden neu eingelesen."})}
$quarantineTimer=[Windows.Threading.DispatcherTimer]::new();$quarantineTimer.Interval=[TimeSpan]::FromSeconds(2);$quarantineTimer.Add_Tick({try{Update-QuarantineNotifications}catch{Set-Message "Quarantänestatus konnte nicht aktualisiert werden"}})
$uiSignalTimer=[Windows.Threading.DispatcherTimer]::new();$uiSignalTimer.Interval=[TimeSpan]::FromMilliseconds(350);$uiSignalTimer.Add_Tick({if(Test-Path -LiteralPath $uiSignalPath){Remove-Item -LiteralPath $uiSignalPath -Force -ErrorAction SilentlyContinue;$window.ShowInTaskbar=$true;$window.Show();$window.WindowState=[Windows.WindowState]::Normal;$window.Activate()|Out-Null;Refresh-All}})
$window.Add_StateChanged({if($window.WindowState-eq[Windows.WindowState]::Minimized){$window.Dispatcher.BeginInvoke([Action]{$window.ShowInTaskbar=$false;$window.Hide()})|Out-Null}})
$window.Add_Closing({param($sender,$eventArgs)Write-UiLifecycle "closing-allow-$script:allowUiExit";if(-not$script:allowUiExit){$eventArgs.Cancel=$true;$sender.Dispatcher.BeginInvoke([Action]{$sender.ShowInTaskbar=$false;$sender.Hide()})|Out-Null}})
$sessionEndingHandler=[Microsoft.Win32.SessionEndingEventHandler]{param($sender,$eventArgs)Write-UiLifecycle "session-ending";$script:allowUiExit=$true;$window.Dispatcher.BeginInvoke([Action]{$window.Close()})|Out-Null}
Write-UiLifecycle "session-handler-start"
[Microsoft.Win32.SystemEvents]::add_SessionEnding($sessionEndingHandler)
Write-UiLifecycle "session-handler-complete"
$window.Add_Loaded({try{Initialize-RecoveryBaselineIfRequired;Refresh-All;Initialize-QuarantineNotifications;$quarantineTimer.Start()}catch{Show-Error $_.Exception.Message}})
$window.Add_Loaded({Write-UiLifecycle "loaded";$uiSignalTimer.Start()})
$window.Add_Closed({Write-UiLifecycle "closed";$quarantineTimer.Stop();$uiSignalTimer.Stop();[Microsoft.Win32.SystemEvents]::remove_SessionEnding($sessionEndingHandler);Remove-Item -LiteralPath $uiInstancePath,$uiSignalPath -Force -ErrorAction SilentlyContinue;$window.Dispatcher.InvokeShutdown()})
Write-UiLifecycle "dispatcher-start"
$window.Show()
[Windows.Threading.Dispatcher]::Run()
Write-UiLifecycle "dispatcher-return"
