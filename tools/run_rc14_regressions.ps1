param([string]$OutputPath = "runtime\rc14-regressions.log")

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$output = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else {
    [IO.Path]::GetFullPath((Join-Path $repo $OutputPath))
}
New-Item -ItemType Directory -Force -Path (Split-Path $output -Parent) | Out-Null
try {
    $content = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tests\windows_content_policy_bypass.ps1") -TimeoutSeconds 30 2>&1
    $content | Tee-Object -FilePath $output
    if ($LASTEXITCODE -ne 0) { throw "Content-policy bypass regression failed." }
    $process = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $repo "tests\windows_process_guard_rules.ps1") 2>&1
    $process | Tee-Object -FilePath $output -Append
    if ($LASTEXITCODE -ne 0) { throw "ProcessGuard false-positive regression failed." }
    "rc14_regressions=PASS" | Tee-Object -FilePath $output -Append
    exit 0
} catch {
    "rc14_regressions=FAIL error=$($_.Exception.Message)" | Tee-Object -FilePath $output -Append
    Write-Error $_
    exit 1
}
