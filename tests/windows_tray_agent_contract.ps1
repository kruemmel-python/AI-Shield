$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
$agent = Join-Path $repo "editions\private_desktop\tray\start_tray_agent.ps1"
$manager = Join-Path $repo "editions\private_desktop\tray\manage_tray_agent.ps1"

foreach ($path in @($agent, $manager)) {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { throw "PowerShell parser errors in $path`: $($errors.Message -join '; ')" }
}
$agentText = Get-Content -LiteralPath $agent -Raw
$managerText = Get-Content -LiteralPath $manager -Raw
foreach ($service in @("AIShieldCore", "AIShieldBroker", "AIShieldWfp", "AIShieldMiniFilter", "AIShieldProcessGuard")) {
    if ($agentText -notmatch [regex]::Escape($service)) { throw "Tray agent does not monitor $service." }
}
foreach ($required in @("NotifyIcon", "Local\AIShieldPrivateTray", "AI Shield öffnen", "Tray-Agent beenden")) {
    if ($agentText -notmatch [regex]::Escape($required)) { throw "Tray contract is missing: $required" }
}
if ($managerText -notmatch 'CurrentVersion\\Run' -or $managerText -notmatch 'AIShieldPrivateTray') {
    throw "Tray manager does not register the machine-wide logon autostart."
}
$security = [Security.AccessControl.EventWaitHandleSecurity]::new()
$sid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::WorldSid, $null)
$rights = [Security.AccessControl.EventWaitHandleRights]::Modify -bor
    [Security.AccessControl.EventWaitHandleRights]::Synchronize
$rule = [Security.AccessControl.EventWaitHandleAccessRule]::new(
    $sid, $rights, [Security.AccessControl.AccessControlType]::Allow)
$security.AddAccessRule($rule)
$created = $false
$event = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::AutoReset,
    "Local\AIShieldPrivateUiContract-$PID", [ref]$created, $security)
try {
    $event.Set() | Out-Null
    if (-not $event.WaitOne(0)) { throw "The UI activation event did not preserve its signal." }
} finally { $event.Dispose() }
Write-Output "AI Shield tray agent contract: PASS"
