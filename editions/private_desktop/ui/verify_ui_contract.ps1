param([switch]$RenderPreview)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$xamlPath = Join-Path $PSScriptRoot "AIShield.PrivateDesktop.UI.xaml"
$scriptPath = Join-Path $PSScriptRoot "start_private_ui.ps1"
$viewerPath = Join-Path $PSScriptRoot "AIShield.AuditViewer.xaml"
[xml]$xaml = Get-Content -LiteralPath $xamlPath -Raw
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$required = @(
    "Pages", "PageTitle", "StatusMessage", "SidebarState", "ProtectionState",
    "ComponentState", "AuditState", "ServiceGrid", "AuditGrid", "QuarantineGrid",
    "RecoveryStatus", "IncidentGrid", "SnapshotButton", "BackupButton", "DetectRansomwareButton", "RestorePlanButton", "RestoreIncidentButton",
    "RefreshButton", "RestartButton", "CoreToggle", "DownloadsToggle",
    "DocumentsToggle", "ArchivesToggle", "ImagesToggle", "AudioToggle", "VideoToggle", "WebFilesToggle", "ScanFailureToggle", "BrowserToggle",
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
Write-Output "AI Shield private desktop UI contract: PASS ($($required.Count) controls, 6 views)"
