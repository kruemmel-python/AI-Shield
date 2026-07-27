param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"
$filterPath = Join-Path $RepositoryRoot "platform\windows\minifilter\driver\ai_shield_minifilter.c"
$brokerPath = Join-Path $RepositoryRoot "tools\ai_shield_broker\main.cpp"
$protocolPath = Join-Path $RepositoryRoot "platform\windows\common\ai_shield_driver_protocol.h"
$filter = Get-Content -LiteralPath $filterPath -Raw
$broker = Get-Content -LiteralPath $brokerPath -Raw
$protocol = Get-Content -LiteralPath $protocolPath -Raw

if ($filter -notmatch '-250LL\s*\*\s*10LL\s*\*\s*1000LL') {
    throw "Minifilter handoff deadline is not fixed at 250 ms."
}
if ($filter -match '-30LL\s*\*\s*10LL\s*\*\s*1000LL\s*\*\s*1000LL') {
    throw "Legacy 30-second synchronous analysis timeout is present."
}
if ($filter -match 'RTL_CONSTANT_STRING\(L"\\\\AppData\\\\Local\\\\Temp\\\\"\)') {
    throw "Generic AppData Temp gating would stall normal desktop processes."
}
if ($broker -match 'add_root\(profile\s*/\s*L"AppData"\s*/\s*L"Local"\s*/\s*L"Temp"') {
    throw "Broker must not classify arbitrary files from the user Temp directory."
}
if ($broker -notmatch 'transient_download_path' -or
    $broker -notmatch 'content_category_disabled' -or
    $broker -notmatch 'policy_\s*=\s*load_content_policy\(\)') {
    throw "Content-policy bypass and transient download handling are incomplete."
}
if ([regex]::Matches($broker, 'downloads_root\s*&&\s*!executable\s*&&\s*!parser_risk_extension').Count -ne 1) {
    throw "The recovery scan would strand disabled download categories in kernel PENDING state."
}
if ($filter -notmatch 'AI_SHIELD_EVENT_FILE_RENAME[\s\S]{0,400}AI_SHIELD_FILE_PENDING') {
    throw "A browser final-name rename must invalidate the temporary download verdict."
}
foreach ($required in @(
    'analysis_worker_',
    'queue_condition_',
    'reply.reply.Verdict = AI_SHIELD_FILE_PENDING',
    'quarantine.classify_pending'
)) {
    if ($broker -notmatch [regex]::Escape($required)) {
        throw "Broker latency contract is missing: $required"
    }
}
if ($broker -notmatch 'void\s+analysis_loop' -or $broker -notmatch 'void\s+receive_loop') {
    throw "Minifilter receive and analysis paths are not separated."
}
if ($protocol -notmatch 'AI_SHIELD_IOCTL_ADMIN_FILE_VERDICT' -or
    $filter -notmatch 'AI_SHIELD_IOCTL_ADMIN_FILE_VERDICT' -or
    $broker -notmatch 'submit_admin_file_verdict') {
    throw "Transactional administrator quarantine release is not connected end to end."
}

Write-Output "AI Shield minifilter latency contract: PASS"
