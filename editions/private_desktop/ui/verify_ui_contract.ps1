param([switch]$RenderPreview)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$xamlPath = Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.xaml"
$scriptPath = Join-Path $PSScriptRoot "start_private_ui.ps1"
$viewModelPath = Join-Path $PSScriptRoot "quarantine_view_model.ps1"
$viewerPath = Join-Path $PSScriptRoot "AIShield.AuditViewer.xaml"
. $viewModelPath
[xml]$xaml = Get-Content -LiteralPath $xamlPath -Raw
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$required = @(
    "Pages", "PageTitle", "StatusMessage", "SidebarState", "ProtectionState",
    "ComponentState", "AuditState", "ServiceGrid", "AuditGrid", "QuarantineGrid",
    "RecoveryStatus", "IncidentGrid", "SnapshotButton", "BackupButton", "DetectRansomwareButton", "RestorePlanButton", "RestoreIncidentButton",
    "RefreshButton", "RestartButton", "TrayToggle", "TrayDetail", "CoreToggle", "DownloadsToggle",
    "DocumentsToggle", "ArchivesToggle", "ImagesToggle", "AudioToggle", "VideoToggle", "WebFilesToggle",
    "ProgramsToggle", "WindowsScriptsToggle", "DeveloperScriptsToggle", "LaunchersToggle", "UnknownToggle", "ReleaseRequiredToggle", "ScanFailureToggle", "BrowserToggle",
    "InboundToggle", "BrowserSensorToggle", "BrowserSensorDetail", "EdgeSetupButton", "ChromeSetupButton",
    "KernelHardwareToggle", "KernelHardwareDetail", "BitLockerButton",
    "HvciToggle", "CredentialToggle", "FirewallToggle", "DefenderToggle",
    "HvciDetail", "CredentialDetail", "ViewAuditButton", "OpenAuditFileButton", "VerifyAuditButton", "ExportAuditButton", "ReleaseButton",
    "NavDashboard", "NavProtection", "NavAudit", "NavQuarantine", "NavRecovery", "NavSystem"
)
$missing = @($required | Where-Object { $null -eq $window.FindName($_) })
if ($missing.Count -gt 0) { throw "Missing UI controls: $($missing -join ', ')" }
$scriptText = Get-Content -LiteralPath $scriptPath -Raw
if ($scriptText -notmatch '-WindowStyle["'']*,?["'']*Hidden' -and $scriptText -notmatch '-WindowStyle\s+Hidden') {
    throw "The elevated UI host must start with a hidden console window."
}
$unreferenced = @($required | Where-Object { $scriptText -notmatch ('\$' + [regex]::Escape($_) + '\b') })
if ($unreferenced.Count -gt 0) { throw "Controls without event/status binding: $($unreferenced -join ', ')" }
if ($window.FindName("Pages").Items.Count -ne 6) { throw "The UI must expose exactly six primary views." }
[xml]$viewerXaml=Get-Content -LiteralPath $viewerPath -Raw
$viewer=[Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($viewerXaml))
foreach($name in @("ViewerSummary","ViewerCloseButton","ViewerFilter","ViewerCount","ViewerGrid")){if($null-eq$viewer.FindName($name)){throw "Missing audit viewer control: $name"}}
$viewerHeaders=@($viewer.FindName("ViewerGrid").Columns|ForEach-Object{[string]$_.Header})
foreach($header in @("Name","PID","Parent-PID")){if($viewerHeaders-notcontains$header){throw "Missing audit viewer column: $header"}}
if($scriptText-notmatch'Get-CurrentProcessNames'-or$scriptText-notmatch'ProcessName='){throw "Audit viewer process-name resolution is not bound."}
if ($scriptText -notmatch '\$parameters\s*=\s*@\{\s*Action\s*=\s*\$Action\s*\}' -or
    $scriptText -match '\$arguments\s*=\s*@\(''-Action''') {
    throw "Recovery actions must use named hashtable splatting."
}
foreach ($pattern in @('AIShieldPrivateUiInstance/1', 'private-ui.show.signal', 'Add_StateChanged', 'Add_Closing', 'ShowInTaskbar=\$false')) {
    if ($scriptText -notmatch $pattern) { throw "Close-to-tray contract is missing: $pattern" }
}
if ($scriptText -notmatch '\[Windows\.Threading\.Dispatcher\]::Run\(\)' -or $scriptText -match '\$window\.ShowDialog\(\)') {
    throw "Close-to-tray requires a persistent non-modal WPF dispatcher."
}
if ($scriptText -notmatch '&\s*\$broker\s+quarantine-restore' -or
    $scriptText -match 'powershell\.exe[^\r\n]+quarantine-release') {
    throw "Quarantine release must call the signed broker directly without exposing the destination to a script host."
}
if ($window.FindName("QuarantineGrid").GroupStyle.Count -ne 1) {
    throw "Quarantine entries must use exactly one expandable operation grouping."
}
$quarantineHeaders = @($window.FindName("QuarantineGrid").Columns | ForEach-Object { [string]$_.Header })
foreach ($header in @("Datei", "Quelle", "Größe", "Grund", "Status")) {
    if ($quarantineHeaders -notcontains $header) { throw "Missing quarantine column: $header" }
}
foreach ($pattern in @(
        'ConvertTo-AIShieldQuarantineViewItems',
        'PropertyGroupDescription',
        'Download- oder Installationsvorgang',
        'Bereich „Quarantäne“')) {
    if ($scriptText -notmatch $pattern) { throw "Quarantine operation UI contract is missing: $pattern" }
}
$sampleItems = @(1..11 | ForEach-Object {
    $name = @("README.md", "LICENSE.txt", "manifest.txt")[$_ - 1]
    if ([string]::IsNullOrWhiteSpace($name)) { $name = "payload-$_.dat" }
    [pscustomobject]@{
        Id = ("{0:x64}" -f $_)
        Source = "\\?\GLOBALROOT\Device\HarddiskVolume3\Users\test\.cache\codex-runtimes\codex-runtime-install-S0oO6J\payload\$name"
        Size = "1,0 KiB"
        State = "committed"
        Classification = "Wartet auf Freigabe"
    }
})
$groupedItems = @(ConvertTo-AIShieldQuarantineViewItems -Items $sampleItems)
if ($groupedItems.Count -ne 11 -or @($groupedItems.GroupKey | Select-Object -Unique).Count -ne 1) {
    throw "Codex runtime quarantine files were not grouped into one operation."
}
$firstGroupItem = $groupedItems[0]
if ($firstGroupItem.GroupTitle -ne "Codex Runtime Installation" -or
    $firstGroupItem.GroupSource -ne "codex-runtime-install-S0oO6J" -or
    $firstGroupItem.GroupCount -ne 11 -or
    $firstGroupItem.GroupStatus -ne "Prüfung/Freigabe erforderlich" -or
    $firstGroupItem.Name -ne "README.md") {
    throw "Codex runtime quarantine group metadata is incomplete."
}

if ($RenderPreview) {
    $previewView = [Windows.Data.CollectionViewSource]::GetDefaultView($groupedItems)
    [void]$previewView.GroupDescriptions.Add(
        [Windows.Data.PropertyGroupDescription]::new("GroupKey"))
    $window.FindName("QuarantineGrid").ItemsSource = $previewView
    $window.FindName("Pages").SelectedIndex = 3
    $window.FindName("PageTitle").Text = "Quarantäne"
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
Write-Output "AI Shield private desktop UI contract: PASS ($($required.Count) controls, 6 views, quarantine grouping)"
