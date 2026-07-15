$ErrorActionPreference="Stop"
$repo=Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$header=Join-Path $repo "platform\windows\common\ai_shield_driver_protocol.h"
$text=Get-Content -LiteralPath $header -Raw
$expectedSchema="AI_SHIELD_ABI_1_2|POLICY:32:0,4,8,12,16,20,24,28|STATUS:56:0,4,8,12,16,24,32,40,48|EVENT:72:0,4,8,12,16,24,32,40,48,52,56,60,64,68"
$bytes=[Text.Encoding]::ASCII.GetBytes($expectedSchema)
$sha=[Security.Cryptography.SHA256]::Create()
try{$fingerprint=($sha.ComputeHash($bytes)|ForEach-Object{$_.ToString("x2")})-join ""}finally{$sha.Dispose()}
if($text -notmatch '#define AI_SHIELD_PROTOCOL_VERSION 0x00010002U'){throw "Frozen protocol version changed."}
if($text -notmatch '#define AI_SHIELD_ABI_FREEZE_REVISION 3U'){throw "ABI freeze revision changed."}
if($text -notmatch [regex]::Escape('#define AI_SHIELD_ABI_SCHEMA_SHA256 "'+$fingerprint+'"')){throw "ABI schema fingerprint mismatch."}
$required=@(
    "sizeof(AI_SHIELD_DRIVER_POLICY) == 32U",
    "sizeof(AI_SHIELD_DRIVER_STATUS) == 56U",
    "sizeof(AI_SHIELD_DRIVER_EVENT) == 72U",
    "FIELD_OFFSET(AI_SHIELD_DRIVER_EVENT, Sequence) == 16U",
    "FIELD_OFFSET(AI_SHIELD_DRIVER_EVENT, Flags) == 64U"
)
foreach($assertion in $required){if(-not $text.Contains($assertion)){throw "ABI invariant missing: $assertion"}}
$manifest=[ordered]@{schema="AIShieldDriverABI/1.2";protocol_version="0x00010002";freeze_revision=3;
    packing=8;policy_size=32;status_size=56;event_size=72;schema_sha256=$fingerprint;canonical_schema=$expectedSchema}
$output=Join-Path $repo "runtime\verification\ABI_MANIFEST.json"
New-Item -ItemType Directory -Force (Split-Path $output -Parent)|Out-Null
[IO.File]::WriteAllText($output,($manifest|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
Write-Output "abi_freeze=valid fingerprint=$fingerprint"
Write-Output "manifest=$output"
