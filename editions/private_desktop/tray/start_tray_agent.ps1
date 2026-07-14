param([switch]$ShowStartupStatus)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms,System.Drawing

$createdNew = $false
$mutex = [Threading.Mutex]::new($true, "Local\AIShieldPrivateTray", [ref]$createdNew)
if (-not $createdNew) {
    $mutex.Dispose()
    exit 0
}

$services = @("AIShieldCore", "AIShieldBroker", "AIShieldWfp", "AIShieldMiniFilter", "AIShieldProcessGuard")
$editionRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$uiLauncher = Join-Path $editionRoot "AI_Shield_UI.cmd"
$startScript = Join-Path $editionRoot "start_private_desktop.ps1"
$settingsPath = Join-Path $env:ProgramData "AIShield\private-desktop\ui-settings.json"
$script:lastState = ""

function Get-AIShieldTrayState {
    $states = foreach ($name in $services) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        [pscustomobject]@{ Name = $name; Running = $null -ne $service -and $service.Status -eq "Running" }
    }
    $running = @($states | Where-Object Running).Count
    $level = if ($running -eq $services.Count) { "protected" } elseif ($running -eq 0) { "stopped" } else { "degraded" }
    [pscustomobject]@{ Level = $level; Running = $running; Total = $services.Count; Services = @($states) }
}

function Open-AIShieldUi {
    if (-not (Test-Path -LiteralPath $uiLauncher -PathType Leaf)) {
        [Windows.Forms.MessageBox]::Show("Die AI-Shield-Oberfläche wurde nicht gefunden.", "AI Shield",
            [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }
    Start-Process -FilePath $uiLauncher
}

function Restart-AIShieldProtection {
    if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) { return }
    $arguments = @("-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", ('"' + $startScript + '"'))
    try {
        if (Test-Path -LiteralPath $settingsPath) {
            $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
            if ($settings.harden_downloads) { $arguments += "-HardenDownloads" }
            if ($settings.strict_browser) { $arguments += "-StrictBrowser" }
            if ($settings.block_unsolicited_inbound) { $arguments += "-BlockUnsolicitedInbound" }
        } else {
            $arguments += "-HardenDownloads"
        }
        Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments | Out-Null
    } catch {
        [Windows.Forms.MessageBox]::Show($_.Exception.Message, "AI Shield",
            [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

$notify = [Windows.Forms.NotifyIcon]::new()
$notify.Visible = $true
$notify.Text = "AI Shield wird gestartet"
$menu = [Windows.Forms.ContextMenuStrip]::new()
$openItem = $menu.Items.Add("AI Shield öffnen")
$statusItem = $menu.Items.Add("Status wird geladen")
$statusItem.Enabled = $false
$menu.Items.Add([Windows.Forms.ToolStripSeparator]::new()) | Out-Null
$restartItem = $menu.Items.Add("Schutzdienste neu starten")
$refreshItem = $menu.Items.Add("Status aktualisieren")
$servicesItem = $menu.Items.Add("Windows-Dienste öffnen")
$menu.Items.Add([Windows.Forms.ToolStripSeparator]::new()) | Out-Null
$exitItem = $menu.Items.Add("Tray-Agent beenden")
$notify.ContextMenuStrip = $menu

function Update-AIShieldTrayStatus {
    $state = Get-AIShieldTrayState
    switch ($state.Level) {
        "protected" { $notify.Icon = [Drawing.SystemIcons]::Information; $label = "Geschützt" }
        "degraded" { $notify.Icon = [Drawing.SystemIcons]::Warning; $label = "Eingeschränkt" }
        default { $notify.Icon = [Drawing.SystemIcons]::Error; $label = "Schutz nicht aktiv" }
    }
    $notify.Text = "AI Shield: $label ($($state.Running)/$($state.Total))"
    $statusItem.Text = "$label - $($state.Running) von $($state.Total) Komponenten aktiv"
    if ($script:lastState -and $script:lastState -ne $state.Level) {
        $notify.BalloonTipTitle = "AI Shield"
        $notify.BalloonTipText = $statusItem.Text
        $notify.BalloonTipIcon = if ($state.Level -eq "protected") {
            [Windows.Forms.ToolTipIcon]::Info
        } else { [Windows.Forms.ToolTipIcon]::Warning }
        $notify.ShowBalloonTip(5000)
    }
    $script:lastState = $state.Level
}

$openItem.Add_Click({ Open-AIShieldUi })
$restartItem.Add_Click({ Restart-AIShieldProtection })
$refreshItem.Add_Click({ Update-AIShieldTrayStatus })
$servicesItem.Add_Click({ Start-Process services.msc })
$notify.Add_DoubleClick({ Open-AIShieldUi })
$exitItem.Add_Click({ [Windows.Forms.Application]::ExitThread() })

$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 5000
$timer.Add_Tick({ Update-AIShieldTrayStatus })

try {
    Update-AIShieldTrayStatus
    if ($ShowStartupStatus) {
        $notify.BalloonTipTitle = "AI Shield"
        $notify.BalloonTipText = $statusItem.Text
        $notify.BalloonTipIcon = [Windows.Forms.ToolTipIcon]::Info
        $notify.ShowBalloonTip(4000)
    }
    $timer.Start()
    [Windows.Forms.Application]::Run()
} finally {
    $timer.Stop()
    $timer.Dispose()
    $notify.Visible = $false
    $notify.Dispose()
    $menu.Dispose()
    if ($createdNew) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
