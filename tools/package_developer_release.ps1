param([string]$Output = "AI_Shield_Developer_ABI2.zip")

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$repoPrefix = $repo.TrimEnd('\') + '\'
$outputPath = [IO.Path]::GetFullPath((Join-Path $repo $Output))
$staging = Join-Path ([IO.Path]::GetTempPath()) ("AI_Shield_Developer_" + [Guid]::NewGuid().ToString("N"))
$root = Join-Path $staging "AI_Shield"
$contract = Get-Content -LiteralPath (Join-Path $repo "editions\private_desktop\RELEASE_CONTRACT.json") -Raw | ConvertFrom-Json
$releaseEpoch = [DateTime]::Parse([string]$contract.release_epoch_utc).ToUniversalTime()
$topFiles = @(
    "CMakeLists.txt", "README.md", "AI_Shield_Start.cmd", "AI_Shield_Start_Demo.cmd",
    "AI_Shield_Stop.cmd", "AI_Shield_Update_Drivers.cmd", "AI_Shield_Protect_System.cmd",
    "AI_Shield_Protect_System_Strict.cmd",
    "AI_Shield_Sicherheitsstatus.cmd",
    "AI_Shield_Defender_Auditmodus.cmd", "AI_Shield_Defender_Rollback.cmd",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.docx",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.extracted.txt",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.md", "planfortsetzung.txt", "Softwarebewertung.md"
)
$topDirectories = @("include", "src", "tests", "tools", "platform", "kernel", "docs", "editions")
$excludedSegments = @(".git", ".vs", "x64", "Debug", "Release", "build", "build_vs")
$excludedExtensions = @(".sys", ".cat", ".cer", ".pfx", ".pvk", ".zip", ".obj", ".pdb", ".ilk", ".tlog")

function Test-IncludedPath([string]$RelativePath) {
    if ($RelativePath.Replace('\','/') -in @("docs/AI_Shield.md", "docs/AI-Shield-CodeDump.md",
            "docs/AI_Shield_Developer_Full.md")) { return $false }
    foreach ($segment in ($RelativePath -split '[\\/]')) {
        if ($excludedSegments -contains $segment) { return $false }
    }
    return $excludedExtensions -notcontains [IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
}

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    foreach ($name in $topFiles) {
        $source = Join-Path $repo $name
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $root }
    }
    foreach ($directory in $topDirectories) {
        Get-ChildItem -LiteralPath (Join-Path $repo $directory) -Recurse -File | ForEach-Object {
            if (-not $_.FullName.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Source escaped repository root: $($_.FullName)"
            }
            $relative = $_.FullName.Substring($repoPrefix.Length)
            if (-not (Test-IncludedPath $relative)) { return }
            $destination = Join-Path $root $relative
            New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destination
        }
    }
    Get-ChildItem -LiteralPath $root -Recurse -Force | ForEach-Object { $_.LastWriteTimeUtc = $releaseEpoch }
    (Get-Item -LiteralPath $root).LastWriteTimeUtc = $releaseEpoch
    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($outputPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($root.Length + 1).Replace('\','/')
            $entry = $archive.CreateEntry("AI_Shield/$relative", [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new($releaseEpoch)
            $input = $file.OpenRead(); $outputStream = $entry.Open()
            try { $input.CopyTo($outputStream) } finally { $outputStream.Dispose(); $input.Dispose() }
        }
    } finally { $archive.Dispose() }
    $archive = Get-Item -LiteralPath $outputPath
    Write-Output ("created {0} ({1} bytes)" -f $archive.FullName, $archive.Length)
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
