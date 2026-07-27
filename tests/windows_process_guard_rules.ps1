$ErrorActionPreference = "Continue"
$run = [Guid]::NewGuid().ToString("N")
$settingsPath = Join-Path $env:ProgramData "AIShield\private-desktop\ui-settings.json"
$expectDownloadBlock = $true
if (Test-Path -LiteralPath $settingsPath) {
    $expectDownloadBlock = [bool](Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json).harden_downloads
}

$service = Get-CimInstance Win32_Service -Filter "Name='AIShieldBroker'"
$broker = if ($service) { ([regex]::Match($service.PathName, '^"?([^\"]+?\.exe)"?(?:\s|$)')).Groups[1].Value } else { $null }
$contentPolicy = if ($broker -and (Test-Path -LiteralPath $broker)) {
    & $broker content-policy-status | ConvertFrom-Json
} else { $null }
$windowsScriptBit = 128

$tempExe = Join-Path $env:TEMP "ai-shield-temp-execution-test-$run.exe"
$downloadScript = Join-Path $env:USERPROFILE "Downloads\ai-shield-interpreter-test-$run.ps1"
$downloadBatch = Join-Path $env:USERPROFILE "Downloads\ai-shield-interpreter-test-$run.bat"
$tempBlocked = $false
$scriptBlocked = $false
$benignUrlAllowed = $true
$downloadInterpreterBlocked = $false
$downloadBatchBlocked = $false
try {
    Copy-Item "$env:SystemRoot\System32\whoami.exe" $tempExe -Force
    try { & $tempExe | Out-Null; $tempBlocked = -not $? } catch { $tempBlocked = $true }

    $payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output ai-shield-risky-command-test"))
    try { & powershell.exe -NoProfile -EncodedCommand $payload | Out-Null; $scriptBlocked = -not $? } catch { $scriptBlocked = $true }
    try { & powershell.exe -NoProfile -Command "Write-Output 'https://example.invalid/package'" | Out-Null; $benignUrlAllowed = $? } catch { $benignUrlAllowed = $false }

    if ($contentPolicy) {
        $testMask = [int]$contentPolicy.enabled_categories -band (-bnot $windowsScriptBit)
        & $broker content-policy-set $testMask ([int][bool]$contentPolicy.fail_closed) `
            ([int][bool]$contentPolicy.release_required) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not isolate ProcessGuard from content scanning." }
    }
    Set-Content -LiteralPath $downloadScript -Value "Write-Output ai-shield-download-interpreter-test"
    try { & powershell.exe -NoProfile -File $downloadScript | Out-Null; $downloadInterpreterBlocked = -not $? } catch { $downloadInterpreterBlocked = $true }
    Set-Content -LiteralPath $downloadBatch -Value "@echo ai-shield-download-batch-test"
    try { & cmd.exe /d /c $downloadBatch | Out-Null; $downloadBatchBlocked = -not $? } catch { $downloadBatchBlocked = $true }
} finally {
    if ($contentPolicy) {
        & $broker content-policy-set ([int]$contentPolicy.enabled_categories) `
            ([int][bool]$contentPolicy.fail_closed) ([int][bool]$contentPolicy.release_required) | Out-Null
    }
    Remove-Item $tempExe,$downloadScript,$downloadBatch -Force -ErrorAction SilentlyContinue
}

$downloadPolicyCorrect = if ($expectDownloadBlock) {
    $downloadInterpreterBlocked -and $downloadBatchBlocked
} else {
    -not $downloadInterpreterBlocked -and -not $downloadBatchBlocked
}
$result = "temp_execution_blocked=$tempBlocked`r`nrisky_script_blocked=$scriptBlocked`r`n" +
    "benign_url_allowed=$benignUrlAllowed`r`ndownload_block_expected=$expectDownloadBlock`r`n" +
    "download_interpreter_blocked=$downloadInterpreterBlocked`r`ndownload_batch_blocked=$downloadBatchBlocked`r`n" +
    "download_policy_correct=$downloadPolicyCorrect"
$result | Set-Content "D:\AI_Shield\runtime\process_guard_rules.log"
Write-Output $result
if (-not $tempBlocked -or -not $scriptBlocked -or -not $benignUrlAllowed -or -not $downloadPolicyCorrect) { exit 2 }
