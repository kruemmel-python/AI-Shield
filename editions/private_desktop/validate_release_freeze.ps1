param([string]$OutputPath = "")

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$contractPath = Join-Path $PSScriptRoot "RELEASE_CONTRACT.json"
$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
if ($contract.schema -ne "AIShieldPrivateReleaseContract/1") { throw "Unknown release contract schema." }
if ($contract.kernel_abi -ne "1.2" -or [int]$contract.kernel_abi_freeze_revision -ne 3 -or
    $contract.internal_abi -ne "2.0" -or [int]$contract.policy_schema -ne 1) {
    throw "Release contract version tuple is invalid."
}
$checks = foreach ($artifact in $contract.artifacts) {
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') {
        throw "Release contract path escapes the repository: $relative"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $repo $relative))
    $prefix = $repo.TrimEnd('\') + '\'
    if (-not $path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release contract path escapes the repository: $relative"
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Frozen artifact is missing: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    [ordered]@{ path=$relative.Replace('\','/'); expected=[string]$artifact.sha256;
        actual=$actual; passed=($actual -eq [string]$artifact.sha256) }
}
$failed = @($checks | Where-Object { -not $_.passed })
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repo "runtime\private-release\freeze-validation.json"
}
$report = [ordered]@{ schema="AIShieldPrivateFreezeValidation/1";
    release=$contract.release; generated_utc=[DateTime]::UtcNow.ToString("o");
    passed=($failed.Count -eq 0); artifacts=@($checks) }
New-Item -ItemType Directory -Force -Path (Split-Path ([IO.Path]::GetFullPath($OutputPath)) -Parent) | Out-Null
[IO.File]::WriteAllText($OutputPath, ($report | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Write-Output "private_release_freeze=$($report.passed) release=$($contract.release)"
Write-Output "report=$OutputPath"
if ($failed.Count) { throw "Private release contract changed: $($failed.path -join ', ')" }
