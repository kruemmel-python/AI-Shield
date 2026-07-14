param([string]$OutputPath = "")

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "private_common.ps1")
$root = Get-AIShieldPrivateRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $env:ProgramData "AIShield\private-desktop\security-posture.json"
}
$temporary = Join-Path $env:TEMP ("ai-shield-posture-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "platform\windows\security\system_security_posture.ps1") -OutputPath $temporary
    if ($LASTEXITCODE -ne 0) { throw "Base security posture collection failed." }
    $base = Get-Content -LiteralPath $temporary -Raw | ConvertFrom-Json
    $excluded = @("pinned_wef_forwarding", "wdac_audit_policy",
        "powershell_privacy_forwarding")
    $checks = @($base.checks | Where-Object { $_.id -notin $excluded })
    foreach ($check in $checks) {
        if ($check.id -eq "defender_cloud_reporting") {
            $check.remediation = "Enable Defender cloud-delivered protection after reviewing local privacy settings."
        }
        if ($check.id -eq "powershell_script_block_logging") {
            $check.remediation = "Enable local PowerShell Script Block Logging and protect the Windows event log."
        }
        if ($check.id -eq "powershell_module_logging") {
            $check.remediation = "Enable selected local PowerShell Module Logging."
        }
    }
    $report = [ordered]@{
        schema = "AIShieldPrivateDesktopPosture/1"
        generated_utc = [DateTime]::UtcNow.ToString("o")
        computer = $env:COMPUTERNAME
        critical_failures = @($checks | Where-Object { $_.severity -eq "critical" -and -not $_.passed }).Count
        passed = @($checks | Where-Object passed).Count
        total = $checks.Count
        checks = $checks
    }
    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    [IO.File]::WriteAllText($OutputPath, ($report | ConvertTo-Json -Depth 7), [Text.UTF8Encoding]::new($false))
    $digest = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText("$OutputPath.sha256", "$digest  $([IO.Path]::GetFileName($OutputPath))`r`n",
        [Text.ASCIIEncoding]::new())
    Write-Output ("private desktop posture: passed={0}/{1} critical_failures={2}" -f `
        $report.passed, $report.total, $report.critical_failures)
    Write-Output "report: $OutputPath"
} finally {
    Remove-Item -LiteralPath $temporary, "$temporary.sha256" -Force -ErrorAction SilentlyContinue
}
