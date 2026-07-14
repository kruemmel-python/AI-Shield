param(
    [string]$CMakeExe = "C:\Program Files\CMake\bin\cmake.exe",
    [string]$CTestExe = "C:\Program Files\CMake\bin\ctest.exe"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
foreach ($tool in @($CMakeExe, $CTestExe)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required build tool is missing: $tool" }
}
& $CMakeExe -S $root -B (Join-Path $root "build_vs") -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
& $CMakeExe --build (Join-Path $root "build_vs") --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "Release build failed." }
& $CTestExe --test-dir (Join-Path $root "build_vs") -C Release --output-on-failure
if ($LASTEXITCODE -ne 0) { throw "Release tests failed." }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
    (Join-Path $root "platform\windows\build_drivers.ps1") -Configuration Release `
    -PackageDirectory (Join-Path $root "driver_package\Release") -Rebuild
if ($LASTEXITCODE -ne 0) { throw "WDK driver build failed." }
Write-Output "AI Shield user-mode binaries and Windows drivers built successfully."
