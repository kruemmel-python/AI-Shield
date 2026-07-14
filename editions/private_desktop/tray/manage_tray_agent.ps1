param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "uninstall", "status", "start")]
    [string]$Action,
    [switch]$NoImmediateStart
)

$ErrorActionPreference = "Stop"
$runKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "AIShieldPrivateTray"
$agent = Join-Path $PSScriptRoot "start_tray_agent.ps1"
$powershell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$command = '"{0}" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File "{1}"' -f $powershell, $agent

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-TrayAgent {
    $escaped = [regex]::Escape([IO.Path]::GetFullPath($agent))
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.CommandLine -match $escaped } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($Action -eq "status") {
    $registered = $false
    $configured = $null
    if (Test-Path -LiteralPath $runKey) {
        try {
            $configured = Get-ItemPropertyValue -LiteralPath $runKey -Name $valueName -ErrorAction Stop
        } catch [Management.Automation.PSArgumentException] {
            $configured = $null
        }
        $registered = -not [string]::IsNullOrWhiteSpace([string]$configured)
    }
    $escaped = [regex]::Escape([IO.Path]::GetFullPath($agent))
    $running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { [string]$_.CommandLine -match $escaped }).Count -gt 0
    [ordered]@{ schema="AIShieldTrayStatus/1"; registered=$registered; running=$running; command=$configured; agent=$agent } |
        ConvertTo-Json -Compress
    exit 0
}

if ($Action -eq "start") {
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw "Tray agent is missing: $agent" }
    Start-Process -FilePath $powershell -WindowStyle Hidden -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-STA", "-File", ('"' + $agent + '"')) | Out-Null
    exit 0
}

if (-not (Test-Administrator)) { throw "Tray autostart changes require administrator rights." }
if ($Action -eq "install") {
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw "Tray agent is missing: $agent" }
    New-Item -Path $runKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $runKey -Name $valueName -Type String -Value $command
    if (-not $NoImmediateStart -and -not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        & $PSCommandPath -Action start
    }
    Write-Output "AI Shield tray autostart installed."
    exit 0
}

Stop-TrayAgent
Remove-ItemProperty -LiteralPath $runKey -Name $valueName -ErrorAction SilentlyContinue
Write-Output "AI Shield tray autostart removed. Protection services remain unaffected."
