param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$PackageDirectory = "",
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$msbuildCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
)
$msbuild = $msbuildCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msbuild) {
    throw "MSBuild.exe not found. Install Visual Studio Build Tools with WDK integration."
}

$projects = @(
    "platform\windows\wfp\driver\AIShieldWfp.vcxproj",
    "platform\windows\minifilter\driver\AIShieldMiniFilter.vcxproj",
    "platform\windows\process_guard\driver\AIShieldProcessGuard.vcxproj"
)

foreach ($project in $projects) {
    $target = if ($Rebuild) { "/t:Rebuild" } else { "/t:Build" }
    & $msbuild (Join-Path $repo $project) $target /m /p:Configuration=$Configuration /p:Platform=$Platform /p:SpectreMitigation=false /p:SignMode=Off
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

$defaultPackage = Join-Path $repo "driver_package\$Configuration"
$package = if ([string]::IsNullOrWhiteSpace($PackageDirectory)) { $defaultPackage } else {
    if ([IO.Path]::IsPathRooted($PackageDirectory)) { [IO.Path]::GetFullPath($PackageDirectory) }
    else { [IO.Path]::GetFullPath((Join-Path $repo $PackageDirectory)) }
}
New-Item -ItemType Directory -Force -Path $package | Out-Null

$sysFiles = Get-ChildItem -Path (Join-Path $repo "platform\windows") -Recurse -Filter *.sys |
    Where-Object { $_.FullName -match "\\$Platform\\$Configuration\\" -or $_.FullName -match "\\$Configuration\\$Platform\\" }

$serviceNames = @{
    "AIShieldWfp.sys" = "AIShieldWfp"
    "AIShieldMiniFilter.sys" = "AIShieldMiniFilter"
    "AIShieldProcessGuard.sys" = "AIShieldProcessGuard"
}

foreach ($sys in $sysFiles) {
    $destination = Join-Path $package $sys.Name
    $service = Get-Service -Name $serviceNames[$sys.Name] -ErrorAction SilentlyContinue
    $isInstalledPackage = [IO.Path]::GetFullPath($package) -eq [IO.Path]::GetFullPath($defaultPackage)
    if ($isInstalledPackage -and $service -and $service.Status -eq "Running" -and (Test-Path -LiteralPath $destination)) {
        Write-Output "package retained while driver is running: $($sys.Name)"
        continue
    }
    $sameContent = (Test-Path -LiteralPath $destination) -and
        ((Get-FileHash -Algorithm SHA256 -LiteralPath $sys.FullName).Hash -eq
         (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash)
    if ($sameContent) {
        Write-Output "package current: $($sys.Name)"
    } else {
        Copy-Item -LiteralPath $sys.FullName -Destination $destination -Force
        Write-Output "package updated: $($sys.Name)"
    }
}

$infFiles = Get-ChildItem -Path (Join-Path $repo "platform\windows\installer") -Filter *.inf
foreach ($inf in $infFiles) {
    Copy-Item -LiteralPath $inf.FullName -Destination (Join-Path $package $inf.Name) -Force
}
Write-Output "driver package: $package"
