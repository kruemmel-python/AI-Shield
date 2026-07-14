$ErrorActionPreference="Continue"
$tempExe=Join-Path $env:TEMP "ai-shield-temp-execution-test.exe"
Copy-Item "$env:SystemRoot\System32\whoami.exe" $tempExe -Force
$tempBlocked=$false
try { & $tempExe | Out-Null; $tempBlocked=-not $? } catch { $tempBlocked=$true }
Remove-Item $tempExe -Force -ErrorAction SilentlyContinue

$payload=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output ai-shield-risky-command-test"))
$scriptBlocked=$false
try { & powershell.exe -NoProfile -EncodedCommand $payload | Out-Null; $scriptBlocked=-not $? } catch { $scriptBlocked=$true }

$downloadScript=Join-Path $env:USERPROFILE "Downloads\ai-shield-interpreter-test.ps1"
Set-Content -LiteralPath $downloadScript -Value "Write-Output ai-shield-download-interpreter-test"
$downloadInterpreterBlocked=$false
try { & powershell.exe -NoProfile -File $downloadScript | Out-Null; $downloadInterpreterBlocked=-not $? } catch { $downloadInterpreterBlocked=$true }
Remove-Item $downloadScript -Force -ErrorAction SilentlyContinue

$result="temp_execution_blocked=$tempBlocked`r`nrisky_script_blocked=$scriptBlocked`r`ndownload_interpreter_blocked=$downloadInterpreterBlocked"
$result|Set-Content "D:\AI_Shield\runtime\process_guard_rules.log"
Write-Output $result
if(-not $tempBlocked -or -not $scriptBlocked -or -not $downloadInterpreterBlocked){exit 2}
