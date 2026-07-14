param([switch]$Elevated)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$installRoot = Join-Path $env:ProgramFiles "AI_Shield_Private_Desktop"

if (-not $Elevated) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'), "-Elevated")
    $process = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        $manager = Join-Path $installRoot "tray\manage_tray_agent.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager -Action start
        Start-Process -FilePath (Join-Path $installRoot "AI_Shield_UI.cmd")
    }
    exit $process.ExitCode
}

if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
    throw "AI Shield Private Desktop is not installed at $installRoot"
}

$installedUiScript = Join-Path $installRoot "ui\start_private_ui.ps1"
$uiPattern = [regex]::Escape([IO.Path]::GetFullPath($installedUiScript))
Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { [string]$_.CommandLine -match $uiPattern } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$copies = @(
    @("editions\private_desktop\tray\start_tray_agent.ps1", "tray\start_tray_agent.ps1"),
    @("editions\private_desktop\tray\manage_tray_agent.ps1", "tray\manage_tray_agent.ps1"),
    @("editions\private_desktop\ui\AIShield.PrivateDesktop.UI.xaml", "ui\AIShield.PrivateDesktop.UI.xaml"),
    @("editions\private_desktop\ui\start_private_ui.ps1", "ui\start_private_ui.ps1")
)

foreach ($copy in $copies) {
    $source = Join-Path $repo $copy[0]
    $destination = Join-Path $installRoot $copy[1]
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing source file: $source" }
    New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

$manager = Join-Path $installRoot "tray\manage_tray_agent.ps1"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager -Action uninstall
if ($LASTEXITCODE -ne 0) { throw "Previous tray agent could not be stopped." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager -Action install -NoImmediateStart
if ($LASTEXITCODE -ne 0) { throw "Installed tray agent could not be registered." }
Write-Output (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manager -Action status)
