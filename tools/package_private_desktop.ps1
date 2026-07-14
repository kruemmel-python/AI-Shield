param(
    [string]$Output = "AI_Shield_Private_Desktop.zip",
    [string]$DriverPackageDirectory = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$edition = Join-Path $repo "editions\private_desktop"
$driverPackage = if ([string]::IsNullOrWhiteSpace($DriverPackageDirectory)) {
    Join-Path $repo "driver_package\Release"
} elseif ([IO.Path]::IsPathRooted($DriverPackageDirectory)) {
    [IO.Path]::GetFullPath($DriverPackageDirectory)
} else { [IO.Path]::GetFullPath((Join-Path $repo $DriverPackageDirectory)) }
$outputPath = if ([IO.Path]::IsPathRooted($Output)) { [IO.Path]::GetFullPath($Output) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $Output))
}
$staging = Join-Path ([IO.Path]::GetTempPath()) ("AI_Shield_Private_" + [Guid]::NewGuid().ToString("N"))
$root = Join-Path $staging "AI_Shield_Private_Desktop"
$contract = Get-Content -LiteralPath (Join-Path $edition "RELEASE_CONTRACT.json") -Raw | ConvertFrom-Json
$releaseEpoch = [DateTime]::Parse([string]$contract.release_epoch_utc).ToUniversalTime()

$editionFiles = @(
    "edition.json", "RELEASE_CONTRACT.json", "README.md", "SOFTWAREBEWERTUNG_PRIVAT.md", "QUALIFIKATIONSSTATUS.md", "Installieren.cmd",
    "Schutz_starten.cmd", "Schutz_beenden.cmd", "Status_anzeigen.cmd", "Deinstallieren.cmd",
    "AI_Shield_UI.cmd", "ui\README.md", "ui\AIShield.PrivateDesktop.UI.xaml", "ui\AIShield.AuditViewer.xaml", "ui\start_private_ui.ps1",
    "ui\private_security_settings.ps1", "ui\verify_ui_contract.ps1",
    "private_common.ps1", "install_private_desktop.ps1", "msi_product_action.ps1", "start_private_desktop.ps1",
    "stop_private_desktop.ps1", "status_private_desktop.ps1", "private_posture.ps1",
    "uninstall_private_desktop.ps1"
)
$binaries = @("ai_shield_driverctl.exe", "ai_shield_kernelctl.exe", "ai_shield_broker.exe", "ai_shield_diag.exe",
    "ai_shield_service.exe", "ai_shield_integrations.exe", "ai_shield_browser_host.exe")
$driverFiles = @("ai_shield_minifilter.inf", "ai_shield_process_guard.inf", "ai_shield_wfp.inf",
    "ai_shield_testsigning.cer", "AIShieldMiniFilter.sys", "AIShieldProcessGuard.sys", "AIShieldWfp.sys")
$scripts = @(
    "platform\windows\protect_system.ps1", "platform\windows\stop_ai_shield.ps1",
    "platform\windows\policy\ai_shield_policy.ps1",
    "platform\windows\installer\install_drivers.ps1",
    "platform\windows\installer\uninstall_drivers.ps1",
    "platform\windows\installer\install_broker.ps1",
    "platform\windows\installer\install_core_service.ps1",
    "platform\windows\installer\uninstall_product.ps1",
    "platform\windows\admin\ai_shield_admin.ps1",
    "platform\windows\ransomware\ransomware_recovery.ps1",
    "platform\windows\browser_extension\install_browser_sensor.ps1",
    "platform\windows\browser_extension\manifest.json",
    "platform\windows\browser_extension\service_worker.js",
    "platform\windows\security\system_security_posture.ps1",
    "platform\windows\security\kernel_hardware_hardening.ps1",
    "platform\windows\security\defender_audit_baseline.ps1",
    "platform\windows\firewall\firewall_baseline.ps1",
    "docs\KERNEL_HARDWARE_SCHUTZ_DE.md"
)
$imageFiles = @(
    "Audit_viewer.png", "Audit.png", "quarantäne.png", "schutzfunktionen_1.png",
    "schutzfunktionen_2.png", "uebersicht.png", "windows_sicherheit.png"
)

function Copy-RequiredFile([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Required file is missing: $Source" }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    foreach ($name in $editionFiles) {
        Copy-RequiredFile (Join-Path $edition $name) (Join-Path $root $name)
    }
    foreach ($name in $binaries) {
        Copy-RequiredFile (Join-Path $repo "build_vs\Release\$name") `
            (Join-Path $root "build_vs\Release\$name")
    }
    foreach ($name in $driverFiles) {
        Copy-RequiredFile (Join-Path $driverPackage $name) `
            (Join-Path $root "driver_package\Release\$name")
    }
    foreach($name in @("AIShieldMiniFilter.sys","AIShieldProcessGuard.sys","AIShieldWfp.sys")){
        $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $driverPackage $name)
        if($signature.Status-ne"Valid"){throw "Consumer driver signature is not valid: $name ($($signature.Status))"}
    }
    foreach ($name in $scripts) {
        Copy-RequiredFile (Join-Path $repo $name) (Join-Path $root $name)
    }
    $docsRoot = Join-Path $repo "docs"
    foreach ($file in (Get-ChildItem -LiteralPath $docsRoot -Recurse -File)) {
        $relative = $file.FullName.Substring($docsRoot.Length + 1)
        Copy-RequiredFile $file.FullName (Join-Path $root "docs\$relative")
    }
    foreach ($name in $imageFiles) {
        Copy-RequiredFile (Join-Path $edition $name) (Join-Path $root "editions\private_desktop\$name")
    }
    $manifest = Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    }
    [IO.File]::WriteAllText((Join-Path $root "PACKAGE_MANIFEST.json"),
        (([ordered]@{ schema="AIShieldPrivatePackage/1"; created_utc=$releaseEpoch.ToString("o");
            edition="private-desktop"; release=$contract.release; files=@($manifest) }) | ConvertTo-Json -Depth 5),
        [Text.UTF8Encoding]::new($false))
    Get-ChildItem -LiteralPath $root -Recurse -Force | ForEach-Object { $_.LastWriteTimeUtc = $releaseEpoch }
    (Get-Item -LiteralPath $root).LastWriteTimeUtc = $releaseEpoch
    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($outputPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($root.Length + 1).Replace('\','/')
            $entry = $archive.CreateEntry("AI_Shield_Private_Desktop/$relative",
                [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new($releaseEpoch)
            $input = $file.OpenRead()
            $outputStream = $entry.Open()
            try { $input.CopyTo($outputStream) } finally { $outputStream.Dispose(); $input.Dispose() }
        }
    } finally {
        $archive.Dispose()
    }
    $hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
    Write-Output "created $outputPath"
    Write-Output "sha256=$hash"
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
