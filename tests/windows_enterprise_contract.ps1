param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $RepositoryRoot "platform\windows\enterprise\enterprise_enrollment.ps1"
$commandHeader = Join-Path $RepositoryRoot "include\ai_shield\enterprise_command.hpp"
$policySource = Join-Path $RepositoryRoot "src\enterprise_policy.cpp"
$signatureScript = Join-Path $RepositoryRoot `
    "platform\windows\enterprise\enterprise_envelope_signature.ps1"

foreach ($path in @($scriptPath, $commandHeader, $policySource, $signatureScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing enterprise contract file: $path"
    }
}

$script = Get-Content -LiteralPath $scriptPath -Raw
$commands = Get-Content -LiteralPath $commandHeader -Raw
$policy = Get-Content -LiteralPath $policySource -Raw
$signature = Get-Content -LiteralPath $signatureScript -Raw

foreach ($required in @(
    "DataProtectionScope]::LocalMachine",
    "Cert:\LocalMachine\My",
    "1.3.6.1.5.5.7.3.2",
    "PinnedSpkiSha256",
    "SetAccessRuleProtection",
    "https"
)) {
    if ($script -notmatch [regex]::Escape($required)) {
        throw "Enterprise enrollment contract is missing: $required"
    }
}

foreach ($forbidden in @("Invoke-Expression", "cmd.exe", "EncodedCommand", "DownloadString")) {
    if ($script -match [regex]::Escape($forbidden) -or
        $signature -match [regex]::Escape($forbidden) -or
        $commands -match [regex]::Escape($forbidden)) {
        throw "Forbidden remote execution primitive found: $forbidden"
    }
}

foreach ($required in @(
    "SignedCms",
    "CheckSignature",
    "X509RevocationMode]::Online",
    "EntireChain",
    "TrustedCertificateSha256",
    "SignerInfos.Count -ne 1"
)) {
    if ($signature -notmatch [regex]::Escape($required)) {
        throw "Enterprise CMS verification contract is missing: $required"
    }
}

foreach ($required in @(
    "isolate_network",
    "quarantine_file",
    "start_approved_restore",
    "rotate_device_certificate",
    "ReplayGuard"
)) {
    if ($commands -notmatch [regex]::Escape($required)) {
        throw "Typed response command missing: $required"
    }
}

foreach ($required in @("downgrade_attempt", "require_dual_control", "maximum_break_glass_lease_ns")) {
    if ($policy -notmatch [regex]::Escape($required)) {
        throw "Enterprise policy guard missing: $required"
    }
}

Write-Output "windows_enterprise_contract passed"
