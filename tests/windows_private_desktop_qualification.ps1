param(
    [ValidateRange(5, 86400)][int]$DurationSeconds = 30,
    [ValidateRange(1, 1048576)][int]$PayloadBytes = 4096,
    [ValidateRange(64, 4096)][int]$MaximumServiceWorkingSetMiB = 512,
    [ValidateRange(1, 100)][int]$MaximumAverageCpuPercent = 25,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$runId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $repo "runtime\private-release\qualification-$runId.json"
}
$checks = [Collections.Generic.List[object]]::new()

function Add-Check([string]$Name, [string]$Status, [string]$Evidence) {
    $checks.Add([ordered]@{name=$Name;status=$Status;evidence=$Evidence})
    Write-Output "[$($Status.ToUpperInvariant())] $Name - $Evidence"
}

function Read-KernelStatus {
    $previousErrorAction=$ErrorActionPreference
    $ErrorActionPreference="Continue"
    try {
        $text = (& $driverctl status 2>&1) -join "`n"
        $running = ([regex]::Matches($text, "state=4 win32_exit=0")).Count
        $kernelText = (& (Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe") status 2>&1) -join "`n"
    } finally {
        $ErrorActionPreference=$previousErrorAction
    }
    $processBlocked = [regex]::Match($kernelText, "process_guard[^\r\n]*blocked=(\d+)")
    return [ordered]@{driver_text=$text;kernel_text=$kernelText;running=$running;
        process_blocked=$(if($processBlocked.Success){[uint64]$processBlocked.Groups[1].Value}else{$null})}
}

function Read-ServiceMetrics {
    $rows = foreach ($name in @("AIShieldBroker","AIShieldCore")) {
        $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($null -eq $service -or [uint32]$service.ProcessId -eq 0) { continue }
        $cimProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" -ErrorAction SilentlyContinue
        if ($null -ne $cimProcess) {
            [ordered]@{name=$name;pid=[uint32]$service.ProcessId;
                cpu_ms=([double]$cimProcess.KernelModeTime+[double]$cimProcess.UserModeTime)/10000.0;
                working_set=[uint64]$cimProcess.WorkingSetSize;
                read_bytes=[uint64]$cimProcess.ReadTransferCount;
                write_bytes=[uint64]$cimProcess.WriteTransferCount}
        }
    }
    return @($rows)
}

function Invoke-LoopbackLoad {
    $addresses = @([Net.IPAddress]::Loopback,[Net.IPAddress]::IPv6Loopback)
    $pairs=@()
    try {
        $payload = [byte[]]::new($PayloadBytes)
        $random=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$random.GetBytes($payload)}finally{$random.Dispose()}
        foreach($address in $addresses){
            $listener=[Net.Sockets.TcpListener]::new($address,0);$listener.Start()
            $accept=$listener.AcceptTcpClientAsync()
            $client=[Net.Sockets.TcpClient]::new($address.AddressFamily)
            $connect=$client.ConnectAsync($address,([Net.IPEndPoint]$listener.LocalEndpoint).Port)
            if(-not$connect.Wait(2000)-or-not$accept.Wait(2000)){
                $client.Dispose();$listener.Stop();throw "dual-stack loopback setup deadline exceeded"
            }
            $server=$accept.Result;$server.ReceiveTimeout=2000;$client.SendTimeout=2000
            $pairs+=[pscustomobject]@{listener=$listener;client=$client;server=$server;
                family=$(if($address.AddressFamily-eq[Net.Sockets.AddressFamily]::InterNetwork){'ipv4'}else{'ipv6'})}
        }
        $deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds)
        $transfers=0L;$bytes=0L;$failures=0L;$latencyTotal=0.0
        while ([DateTime]::UtcNow -lt $deadline) {
            foreach ($pair in $pairs) {
                $stopwatch=[Diagnostics.Stopwatch]::StartNew()
                try {
                    $pair.client.GetStream().Write($payload,0,$payload.Length)
                    $received=[byte[]]::new($payload.Length)
                    $offset=0
                    while($offset-lt$received.Length){$read=$pair.server.GetStream().Read($received,$offset,$received.Length-$offset);if($read-le0){break};$offset+=$read}
                    if($offset-ne$payload.Length){$failures++}else{$transfers++;$bytes+=$offset;$latencyTotal+=$stopwatch.Elapsed.TotalMilliseconds}
                } catch {$failures++};$stopwatch.Stop()
            }
        }
        return [ordered]@{connections=$pairs.Count;transfers=$transfers;bytes=$bytes;failures=$failures;
            average_latency_ms=$(if($transfers){[math]::Round($latencyTotal/$transfers,3)}else{0});
            families=@($pairs.family)}
    } finally {
        foreach($pair in $pairs){$pair.client.Dispose();$pair.server.Dispose();$pair.listener.Stop()}
    }
}

function Get-CompatibilityInventory {
    $uninstallRoots=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $apps=@(Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue | Where-Object DisplayName |
        Select-Object -ExpandProperty DisplayName -Unique)
    $patterns=[ordered]@{browsers='Chrome|Firefox|Edge|Brave|Opera';vpn='VPN|WireGuard|OpenVPN|Tailscale|NordVPN';
        games='Steam|Epic Games|GOG|Xbox';installers='Windows Installer|App Installer|WinGet';
        scripting='PowerShell|Python|Node.js|Git'}
    $result=[ordered]@{}
    foreach($key in $patterns.Keys){$result[$key]=@($apps|Where-Object{$_-match$patterns[$key]}|Sort-Object)}
    $result.network_adapters=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' |
        Select-Object Name,InterfaceDescription,LinkSpeed)
    return $result
}

$before = Read-KernelStatus
Add-Check "three-kernel-drivers" $(if($before.running-eq3){"pass"}else{"fail"}) `
    ($before.driver_text -replace "`r?`n","; ")
$services = @(Get-Service AIShieldBroker,AIShieldCore -ErrorAction SilentlyContinue)
$runningServices=@($services|Where-Object { $_.Status -eq [ServiceProcess.ServiceControllerStatus]::Running }).Count
Add-Check "local-services" $(if($runningServices-eq2){"pass"}else{"fail"}) "running=$runningServices/2"

$safeCommands=@(
    [ordered]@{name='cmd-echo';file="$env:SystemRoot\System32\cmd.exe";arguments=@('/d','/c','echo AI-Shield-safe-command')},
    [ordered]@{name='powershell-literal';file="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";arguments=@('-NoProfile','-NonInteractive','-Command','Write-Output AI-Shield-safe-command')},
    [ordered]@{name='where-system';file="$env:SystemRoot\System32\where.exe";arguments=@('cmd.exe')}
)
foreach($command in $safeCommands){
    $process=Start-Process -FilePath $command.file -ArgumentList $command.arguments -Wait -PassThru -WindowStyle Hidden
    Add-Check "safe-process-$($command.name)" $(if($process.ExitCode-eq0){"pass"}else{"fail"}) "exit=$($process.ExitCode)"
}

$safeFiles=@()
try {
    foreach($extension in @('txt','json')){
        $path=Join-Path ([IO.Path]::GetTempPath()) "ai-shield-safe-$runId.$extension"
        $base=[IO.File]::Open($path,[IO.FileMode]::Create,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
        try {
            $content=[Text.UTF8Encoding]::new($false).GetBytes("AI Shield benign compatibility corpus")
            $base.Write($content,0,$content.Length)
            $base.Flush($true)
            Set-Content -LiteralPath ($path+':Zone.Identifier') `
                -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
        } finally { $base.Dispose() }
        $safeFiles+=$path
    }
    Start-Sleep -Seconds 7
    $remaining=@($safeFiles|Where-Object{Test-Path -LiteralPath $_}).Count
    Add-Check "benign-local-types" $(if($remaining-eq$safeFiles.Count){"pass"}else{"fail"}) `
        "remaining=$remaining/$($safeFiles.Count)"
} finally {
    foreach($path in $safeFiles){Remove-Item -LiteralPath $path,($path+':Zone.Identifier') -Force -ErrorAction SilentlyContinue}
}

$metricBefore=Read-ServiceMetrics
$load=Invoke-LoopbackLoad
$metricAfter=Read-ServiceMetrics
Add-Check "dual-stack-loopback-load" $(if($load.connections-gt0-and$load.failures-eq0-and$load.families.Count-eq2){"pass"}else{"fail"}) `
    ($load|ConvertTo-Json -Compress)
$resourceRows=@()
foreach($end in $metricAfter){
    $start=$metricBefore|Where-Object { $_.name -eq $end.name }|Select-Object -First 1
    if($null-eq$start){continue}
    $cpuPercent=[math]::Round((($end.cpu_ms-$start.cpu_ms)/($DurationSeconds*1000*[Environment]::ProcessorCount))*100,3)
    $resourceRows+=[ordered]@{name=$end.name;average_cpu_percent=$cpuPercent;
        working_set_mib=[math]::Round($end.working_set/1MB,2);
        read_delta=[uint64]($end.read_bytes-$start.read_bytes);write_delta=[uint64]($end.write_bytes-$start.write_bytes)}
}
$resourcePass=$resourceRows.Count-eq2-and@($resourceRows|Where-Object{$_.average_cpu_percent-gt$MaximumAverageCpuPercent-or$_.working_set_mib-gt$MaximumServiceWorkingSetMiB}).Count-eq0
Add-Check "service-resource-budget" $(if($resourcePass){"pass"}else{"fail"}) ($resourceRows|ConvertTo-Json -Compress)

$after=Read-KernelStatus
$blockedDelta=if($null-ne$before.process_blocked-and$null-ne$after.process_blocked){$after.process_blocked-$before.process_blocked}else{$null}
Add-Check "safe-corpus-false-blocks" $(if($blockedDelta-eq0){"pass"}elseif($null-eq$blockedDelta){"inconclusive"}else{"fail"}) `
    "process_guard_blocked_delta=$blockedDelta"
$inventory=Get-CompatibilityInventory
$coveredCategories=@($inventory.GetEnumerator()|Where-Object{$_.Key-ne'network_adapters'-and@($_.Value).Count-gt0}).Count
Add-Check "installed-application-inventory" $(if($coveredCategories-ge3){"pass"}else{"inconclusive"}) "categories=$coveredCategories/5"

$failed=@($checks|Where-Object { $_.status -eq 'fail' }).Count
$inconclusive=@($checks|Where-Object { $_.status -eq 'inconclusive' }).Count
$report=[ordered]@{schema="AIShieldPrivateQualification/1";run_id=$runId;
    started_utc=$runId;completed_utc=[DateTime]::UtcNow.ToString('o');duration_seconds=$DurationSeconds;
    passed=($failed-eq0);failed=$failed;inconclusive=$inconclusive;checks=$checks;
    load=$load;resources=$resourceRows;compatibility_inventory=$inventory;
    limitation="Inventory is not an interactive compatibility or independent penetration test."}
New-Item -ItemType Directory -Force -Path (Split-Path ([IO.Path]::GetFullPath($OutputPath)) -Parent)|Out-Null
[IO.File]::WriteAllText($OutputPath,($report|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output "result=$OutputPath"
if($failed){exit 2}
