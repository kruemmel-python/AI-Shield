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
