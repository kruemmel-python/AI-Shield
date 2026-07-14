param([switch]$Elevated)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$log = Join-Path $repo "build_vs\private-ui-start-error.log"
$ui = Join-Path $env:ProgramFiles "AI_Shield_Private_Desktop\ui\start_private_ui.ps1"

if (-not $Elevated) {
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-STA", "-File", ('"' + $PSCommandPath + '"'), "-Elevated")
    Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments | Out-Null
    exit 0
}

try {
    & $ui
} catch {
    $_ | Format-List * -Force | Out-File -LiteralPath $log -Encoding UTF8
    exit 1
}
