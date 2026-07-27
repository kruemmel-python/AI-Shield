param([string]$OutputPath = "runtime\rc15-regressions.log")

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$output = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $OutputPath))
}
New-Item -ItemType Directory -Force -Path (Split-Path $output -Parent) | Out-Null

try {
    $ctest = "C:\Program Files\CMake\bin\ctest.exe"
    & $ctest --test-dir (Join-Path $repo "build_vs") -C Release --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "Release CTest failed." }

    & $ctest --test-dir (Join-Path $repo "build_vs_debug") -C Debug --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "Debug CTest failed." }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tests\windows_enterprise_contract.ps1") -RepositoryRoot $repo
    if ($LASTEXITCODE -ne 0) { throw "Enterprise contract regression failed." }

    "rc15_regressions=PASS" | Tee-Object -FilePath $output
    exit 0
} catch {
    "rc15_regressions=FAIL error=$($_.Exception.Message)" | Tee-Object -FilePath $output
    Write-Error $_
    exit 1
}
