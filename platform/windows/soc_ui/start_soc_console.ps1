param([ValidateRange(1024,65535)][int]$Port = 18443, [ValidateRange(0,1000000)][int]$MaxRequests = 0)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SOC console requires an elevated PowerShell."
}
$tokenBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
$random.GetBytes($tokenBytes)
$random.Dispose()
$token = [Convert]::ToBase64String($tokenBytes)
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"

function Send-Response($Response, [int]$Status, [string]$ContentType, [byte[]]$Body) {
    $Response.StatusCode = $Status
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $Body.Length
    $Response.OutputStream.Write($Body, 0, $Body.Length)
    $Response.Close()
}
function Json-Bytes($Value) { return [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 6 -Compress)) }

Write-Output "AI Shield SOC console: http://127.0.0.1:$Port/"
try {
    $requestCount = 0
    while ($listener.IsListening -and ($MaxRequests -eq 0 -or $requestCount -lt $MaxRequests)) {
        $context = $listener.GetContext()
        $requestCount++
        $request = $context.Request
        $response = $context.Response
        if (-not [Net.IPAddress]::IsLoopback($request.RemoteEndPoint.Address)) {
            Send-Response $response 403 "text/plain" ([Text.Encoding]::UTF8.GetBytes("loopback only")); continue
        }
        if ($request.HttpMethod -eq "GET" -and $request.Url.AbsolutePath -eq "/") {
            $html = (Get-Content (Join-Path $PSScriptRoot "index.html") -Raw).Replace("__AI_SHIELD_CSRF__", $token)
            Send-Response $response 200 "text/html; charset=utf-8" ([Text.Encoding]::UTF8.GetBytes($html)); continue
        }
        if ($request.HttpMethod -eq "GET" -and $request.Url.AbsolutePath -in @("/style.css","/app.js")) {
            $file = Join-Path $PSScriptRoot $request.Url.AbsolutePath.TrimStart('/')
            $type = if ($file.EndsWith(".css")) { "text/css" } else { "text/javascript" }
            Send-Response $response 200 $type ([IO.File]::ReadAllBytes($file)); continue
        }
        if ($request.Headers["X-AI-Shield-CSRF"] -ne $token) {
            Send-Response $response 403 "text/plain" ([Text.Encoding]::UTF8.GetBytes("invalid token")); continue
        }
        if ($request.HttpMethod -eq "GET" -and $request.Url.AbsolutePath -eq "/api/status") {
            $health = Get-Content (Join-Path $env:ProgramData "AIShield\health.json") -Raw | ConvertFrom-Json
            $runtimeText = (& $broker runtime-status 2>&1) -join " "
            $runtimeMatch = [regex]::Match($runtimeText, 'generation=(\d+) policy=(\d+) model=(\d+)')
            $services = Get-Service AIShieldCore,AIShieldBroker,AIShieldWfp,AIShieldMiniFilter,AIShieldProcessGuard |
                ForEach-Object { [ordered]@{name=$_.Name;status=[string]$_.Status;start=[string]$_.StartType} }
            Send-Response $response 200 "application/json" (Json-Bytes ([ordered]@{health=$health;runtime=[ordered]@{
                generation=[uint64]$runtimeMatch.Groups[1].Value;policy=[uint64]$runtimeMatch.Groups[2].Value;
                model=[uint64]$runtimeMatch.Groups[3].Value};services=$services})); continue
        }
        if ($request.HttpMethod -eq "POST" -and $request.Url.AbsolutePath -eq "/api/safe-reset") {
            & sc.exe control AIShieldCore 128 | Out-Null
            Send-Response $response 200 "application/json" (Json-Bytes ([ordered]@{ok=$true})); continue
        }
        if ($request.HttpMethod -eq "POST" -and $request.Url.AbsolutePath -eq "/api/quarantine-release") {
            if ($request.ContentLength64 -lt 1 -or $request.ContentLength64 -gt 8192) {
                Send-Response $response 400 "text/plain" ([Text.Encoding]::UTF8.GetBytes("invalid body")); continue
            }
            $reader = [IO.StreamReader]::new($request.InputStream, [Text.Encoding]::UTF8, $false, 8192, $false)
            $body = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Dispose()
            if ($body.object_id -notmatch '^[A-Fa-f0-9]{64}$' -or $body.reason.Length -lt 3) {
                Send-Response $response 400 "text/plain" ([Text.Encoding]::UTF8.GetBytes("invalid release")); continue
            }
            & $broker quarantine-restore $body.object_id $body.destination $body.reason
            if ($LASTEXITCODE -ne 0) { Send-Response $response 409 "text/plain" ([Text.Encoding]::UTF8.GetBytes("release failed")); continue }
            Send-Response $response 200 "application/json" (Json-Bytes ([ordered]@{ok=$true})); continue
        }
        Send-Response $response 404 "text/plain" ([Text.Encoding]::UTF8.GetBytes("not found"))
    }
} finally {
    $listener.Stop()
    $listener.Close()
    [Array]::Clear($tokenBytes, 0, $tokenBytes.Length)
}
