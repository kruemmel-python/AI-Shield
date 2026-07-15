param(
    [string]$Output = "AI_Shield_Developer_Full.zip",
    [string]$ConsumerPackage = "AI_Shield_Private_Desktop.zip",
    [string]$MsiPackage = "dist\msi\AI_Shield_Private_Desktop.msi"
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$repoPrefix = $repo.TrimEnd('\') + '\'
$outputPath = if ([IO.Path]::IsPathRooted($Output)) { [IO.Path]::GetFullPath($Output) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $Output))
}
$consumerPath = if ([IO.Path]::IsPathRooted($ConsumerPackage)) {
    [IO.Path]::GetFullPath($ConsumerPackage)
} else { [IO.Path]::GetFullPath((Join-Path $repo $ConsumerPackage)) }
$msiPath = if ([IO.Path]::IsPathRooted($MsiPackage)) {
    [IO.Path]::GetFullPath($MsiPackage)
} else { [IO.Path]::GetFullPath((Join-Path $repo $MsiPackage)) }
$contract = Get-Content -LiteralPath (Join-Path $repo "editions\private_desktop\RELEASE_CONTRACT.json") `
    -Raw | ConvertFrom-Json
$releaseEpoch = [DateTime]::Parse([string]$contract.release_epoch_utc).ToUniversalTime()
$staging = Join-Path ([IO.Path]::GetTempPath()) ("AI_Shield_Developer_Full_" + [Guid]::NewGuid().ToString("N"))
$root = Join-Path $staging "AI_Shield_Developer_Full"
$support = Join-Path $repo "editions\private_desktop\developer_full"
$topFiles = @(
    "CMakeLists.txt", "README.md", "AI_Shield_Start.cmd", "AI_Shield_Start_Demo.cmd",
    "AI_Shield_Stop.cmd", "AI_Shield_Update_Drivers.cmd", "AI_Shield_Protect_System.cmd",
    "AI_Shield_Protect_System_Strict.cmd", "AI_Shield_Sicherheitsstatus.cmd",
    "AI_Shield_Defender_Auditmodus.cmd", "AI_Shield_Defender_Rollback.cmd",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.docx",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.extracted.txt",
    "AI_Shield_Vollstaendiger_Entwicklungsplan.md", "planfortsetzung.txt", "Softwarebewertung.md"
)
$topDirectories = @("include", "src", "tests", "tools", "platform", "kernel", "docs", "editions")
$excludedSegments = @(".git", ".vs", "x64", "Debug", "Release", "build", "build_vs", "runtime")
$excludedExtensions = @(".sys", ".cat", ".cer", ".pfx", ".pvk", ".zip", ".obj", ".pdb", ".ilk", ".tlog")

function Test-IncludedPath([string]$RelativePath) {
    if ($RelativePath.Replace('\','/') -in @("docs/AI_Shield.md", "docs/AI-Shield-CodeDump.md",
            "docs/AI_Shield_Developer_Full.md")) { return $false }
    foreach ($segment in ($RelativePath -split '[\\/]')) {
        if ($excludedSegments -contains $segment) { return $false }
    }
    return $excludedExtensions -notcontains [IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
}
function Copy-Required([string]$Source, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "Required file is missing: $Source" }
    New-Item -ItemType Directory -Force -Path (Split-Path $Destination -Parent) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}
function Set-ReleaseTimestamp([IO.FileSystemInfo]$Item, [DateTime]$Timestamp) {
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        try {
            $Item.LastWriteTimeUtc = $Timestamp
            return
        } catch [IO.IOException] {
            if ($attempt -eq 39) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    foreach ($name in $topFiles) {
        $source = Join-Path $repo $name
        if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination $root }
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
    foreach ($name in @("README_DE.md", "Build_All_Release.cmd", "Build_All_Release.ps1",
            "Install_Precompiled_Desktop.cmd", "Install_Precompiled_Desktop.ps1")) {
        Copy-Required (Join-Path $support $name) (Join-Path $root $name)
    }
    Copy-Required $consumerPath (Join-Path $root "prebuilt\AI_Shield_Private_Desktop.zip")
    Copy-Required $msiPath (Join-Path $root "prebuilt\AI_Shield_Private_Desktop.msi")

    $manifestFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{ path=$_.FullName.Substring($root.Length + 1).Replace('\','/'); bytes=$_.Length;
            sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $manifest = [ordered]@{ schema="AIShieldDeveloperFullPackage/1"; release=$contract.release;
        created_utc=$releaseEpoch.ToString("o"); files=$manifestFiles }
    [IO.File]::WriteAllText((Join-Path $root "FULL_PACKAGE_MANIFEST.json"),
        ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    $stagedItems = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
    $stagedItems | Where-Object { -not $_.PSIsContainer } |
        ForEach-Object { Set-ReleaseTimestamp $_ $releaseEpoch }
    $stagedItems | Where-Object PSIsContainer | Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object { Set-ReleaseTimestamp $_ $releaseEpoch }
    Set-ReleaseTimestamp (Get-Item -LiteralPath $root) $releaseEpoch

    if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($outputPath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
            $relative = $file.FullName.Substring($root.Length + 1).Replace('\','/')
            $entry = $archive.CreateEntry("AI_Shield_Developer_Full/$relative",
                [IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new($releaseEpoch)
            $input = $file.OpenRead(); $outputStream = $entry.Open()
            try { $input.CopyTo($outputStream) } finally { $outputStream.Dispose(); $input.Dispose() }
        }
    } finally { $archive.Dispose() }
    Write-Output "created $outputPath"
    Write-Output "sha256=$((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash)"
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
