$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'))
    exit 0
}

$archive = Join-Path $PSScriptRoot "prebuilt\AI_Shield_Private_Desktop.zip"
$manifestPath = Join-Path $PSScriptRoot "FULL_PACKAGE_MANIFEST.json"
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw "Embedded desktop package is missing." }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Full package manifest is missing." }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$entry = $manifest.files | Where-Object { $_.path -eq "prebuilt/AI_Shield_Private_Desktop.zip" }
if ($null -eq $entry) { throw "Desktop package is not covered by the full package manifest." }
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actual -ne $entry.sha256) { throw "Embedded desktop package hash mismatch." }

$target = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AI_Shield_Private_Desktop"))
$expected = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\AI_Shield_Private_Desktop'
if ($target -ne $expected) { throw "Installation target validation failed." }
if (Test-Path -LiteralPath $target) {
    throw "An extracted desktop package already exists at $target. Run its Deinstallieren.cmd first, then remove that directory."
}
Expand-Archive -LiteralPath $archive -DestinationPath $env:ProgramFiles
$installer = Join-Path $target "install_private_desktop.ps1"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Extracted installer is missing." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
if ($LASTEXITCODE -ne 0) { throw "Desktop installation failed with exit code $LASTEXITCODE." }
