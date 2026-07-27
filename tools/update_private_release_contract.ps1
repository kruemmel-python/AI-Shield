param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+-rc\.\d+$')]
    [string]$Release,

    [Parameter(Mandatory)]
    [DateTime]$ReleaseEpochUtc
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$contractPath = Join-Path $repo "editions\private_desktop\RELEASE_CONTRACT.json"
$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json

$required = @(
    "include/ai_shield/enterprise_command.hpp",
    "include/ai_shield/enterprise_policy.hpp",
    "include/ai_shield/enterprise_rbac.hpp",
    "include/ai_shield/enterprise_trust.hpp",
    "include/ai_shield/fleet_telemetry.hpp",
    "src/enterprise_command.cpp",
    "src/enterprise_policy.cpp",
    "src/enterprise_rbac.cpp",
    "src/enterprise_trust.cpp",
    "src/fleet_telemetry.cpp",
    "platform/windows/enterprise/enterprise_enrollment.ps1",
    "platform/windows/enterprise/enterprise_envelope_signature.ps1",
    "docs/ENTERPRISE_CONTROL_PLANE_DE.md",
    "docs/RC15_RELEASE_NACHWEIS_DE.md",
    "tests/enterprise/main.cpp",
    "tests/windows_enterprise_contract.ps1",
    "tools/run_rc15_regressions.ps1",
    "tools/update_private_release_contract.ps1"
)

$paths = [Collections.Generic.List[string]]::new()
foreach ($artifact in $contract.artifacts) {
    $path = ([string]$artifact.path).Replace('\', '/')
    if ($path -ne "tools/run_rc14_regressions.ps1" -and -not $paths.Contains($path)) {
        $paths.Add($path)
    }
}
foreach ($path in $required) {
    if (-not $paths.Contains($path)) { $paths.Add($path) }
}

$artifacts = foreach ($relative in $paths) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|/)\.\.(/|$)') {
        throw "Release artifact escapes repository: $relative"
    }
    $full = [IO.Path]::GetFullPath((Join-Path $repo $relative))
    if (-not $full.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Release artifact is missing or outside repository: $relative"
    }
    [ordered]@{
        path = $relative
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    }
}

$contract.release = $Release
$contract.release_epoch_utc = $ReleaseEpochUtc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$contract.artifacts = @($artifacts)
[IO.File]::WriteAllText(
    $contractPath,
    ($contract | ConvertTo-Json -Depth 8),
    [Text.UTF8Encoding]::new($false))

Write-Output "updated=$contractPath"
Write-Output "release=$Release"
Write-Output "artifacts=$($artifacts.Count)"
