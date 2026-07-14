param(
    [ValidateSet("install", "uninstall")]
    [string]$Action = "install"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$brokerSource = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$scannerSource = Join-Path $repo "build_vs\Release\ai_shield_integrations.exe"
$installRoot = Join-Path $env:ProgramFiles "AIShield\bin"
$broker = Join-Path $installRoot "ai_shield_broker.exe"
$scanner = Join-Path $installRoot "ai_shield_integrations.exe"
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

if (-not (Test-Path -LiteralPath $brokerSource) -or -not (Test-Path -LiteralPath $scannerSource)) {
    throw "Broker or isolated content scanner executable is missing."
}

Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
& icacls.exe (Join-Path $env:ProgramFiles "AIShield") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure AI Shield installation directory." }
Copy-Item -LiteralPath $brokerSource -Destination $broker -Force
Copy-Item -LiteralPath $scannerSource -Destination $scanner -Force
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
