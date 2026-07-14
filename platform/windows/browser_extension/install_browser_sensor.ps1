param(
    [ValidateSet("status","install","uninstall")][string]$Action = "status",
    [ValidatePattern('^[a-p]{32}$')][string]$ExtensionId = "kpllglchmdickojejioghahfcipmeofl",
    [ValidatePattern('^$|^[A-Fa-f0-9]{40}$')][string]$PublisherThumbprint = "",
    [string]$UpdateUrl = "",
    [switch]$ConfirmSystemChange
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$sourceHost = Join-Path $repo "build_vs\Release\ai_shield_browser_host.exe"
$sourceExtension = $PSScriptRoot
$root = Join-Path $env:ProgramFiles "AIShield\browser"
$hostPath = Join-Path $root "ai_shield_browser_host.exe"
$extensionPath = Join-Path $root "extension"
$nativeManifestPath = Join-Path $root "de.ai_shield.browser.json"
$statePath = Join-Path $root "install-state.json"
$nativeKeys = @(
    "HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\de.ai_shield.browser",
    "HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\de.ai_shield.browser"
)
$policyKeys = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
)

function Get-DefaultValue([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Item -LiteralPath $Path).GetValue("")
}
function Test-ExtensionLoaded([string]$UserDataRoot) {
    if (-not (Test-Path -LiteralPath $UserDataRoot -PathType Container)) { return $false }
    $profiles = Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" }
    foreach ($profile in $profiles) {
        foreach ($name in @("Preferences", "Secure Preferences")) {
            $path = Join-Path $profile.FullName $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            try {
                if ((Get-Content -LiteralPath $path -Raw -ErrorAction Stop).Contains($ExtensionId)) { return $true }
            } catch {}
        }
    }
    return $false
}
function Get-Status {
    $signature = if (Test-Path -LiteralPath $hostPath) { Get-AuthenticodeSignature $hostPath } else { $null }
    $chromeRegistered = (Get-DefaultValue $nativeKeys[0]) -eq $nativeManifestPath
    $edgeRegistered = (Get-DefaultValue $nativeKeys[1]) -eq $nativeManifestPath
    $extensionStaged = (Test-Path -LiteralPath (Join-Path $extensionPath "manifest.json")) -and
        (Test-Path -LiteralPath (Join-Path $extensionPath "service_worker.js"))
    $chromePolicy = if (Test-Path $policyKeys[0]) { (Get-ItemProperty $policyKeys[0] -Name AIShield -ErrorAction SilentlyContinue).AIShield } else { $null }
    $edgePolicy = if (Test-Path $policyKeys[1]) { (Get-ItemProperty $policyKeys[1] -Name AIShield -ErrorAction SilentlyContinue).AIShield } else { $null }
    $lastEvent = try {
        Get-WinEvent -FilterHashtable @{LogName="Application";ProviderName="AIShieldBrowser";Id=2001} `
            -MaxEvents 1 -ErrorAction Stop
    } catch { $null }
    $edgeLoaded = Test-ExtensionLoaded (Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data")
    $chromeLoaded = Test-ExtensionLoaded (Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data")
    $connected = $null -ne $lastEvent -and ($edgeLoaded -or $chromeLoaded)
    [ordered]@{
        schema="AIShieldBrowserSensorStatus/1"; extension_id=$ExtensionId;
        host_installed=(Test-Path -LiteralPath $hostPath);
        host_signature_valid=($null -ne $signature -and $signature.Status -eq "Valid");
        publisher_thumbprint=$(if($null -ne $signature -and $null -ne $signature.SignerCertificate){$signature.SignerCertificate.Thumbprint}else{""});
        extension_staged=$extensionStaged; extension_directory=$extensionPath;
        chrome_registered=$chromeRegistered; edge_registered=$edgeRegistered;
        chrome_managed=([string]$chromePolicy -like "$ExtensionId;*");
        edge_managed=([string]$edgePolicy -like "$ExtensionId;*");
        chrome_loaded=$chromeLoaded; edge_loaded=$edgeLoaded; connected=$connected;
        last_event_utc=$(if($null -ne $lastEvent){$lastEvent.TimeCreated.ToUniversalTime().ToString("o")}else{$null});
        ready=($extensionStaged -and $chromeRegistered -and $edgeRegistered -and
            $null -ne $signature -and $signature.Status -eq "Valid")
    }
}

if ($Action -eq "status") { Get-Status | ConvertTo-Json -Compress; exit 0 }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    -not $ConfirmSystemChange) { throw "Elevated execution and -ConfirmSystemChange are required." }

if ($Action -eq "uninstall") {
    Stop-Process -Name "ai_shield_browser_host" -Force -ErrorAction SilentlyContinue
    foreach ($key in $nativeKeys) {
        if ((Get-DefaultValue $key) -eq $nativeManifestPath) { Remove-Item -LiteralPath $key -Recurse -Force }
    }
    foreach ($key in $policyKeys) {
        $value = if (Test-Path $key) { (Get-ItemProperty $key -Name AIShield -ErrorAction SilentlyContinue).AIShield } else { $null }
        if ([string]$value -like "$ExtensionId;*") { Remove-ItemProperty $key -Name AIShield -Force }
    }
    Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\AIShieldBrowser" `
        -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    Write-Output "browser sensor removed"
    exit 0
}

foreach ($required in @($sourceHost, (Join-Path $sourceExtension "manifest.json"),
        (Join-Path $sourceExtension "service_worker.js"))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required browser sensor file is missing: $required" }
}
$signature = Get-AuthenticodeSignature -LiteralPath $sourceHost
if ($signature.Status -ne "Valid" -or $null -eq $signature.SignerCertificate) {
    throw "Browser host requires a valid Authenticode signature."
}
if (-not [string]::IsNullOrWhiteSpace($PublisherThumbprint) -and
    $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint.ToUpperInvariant()) {
    throw "Browser host signature does not match the pinned publisher."
}
if (-not [string]::IsNullOrWhiteSpace($UpdateUrl) -and
    (-not [Uri]::IsWellFormedUriString($UpdateUrl,[UriKind]::Absolute) -or
     -not $UpdateUrl.StartsWith("https://",[StringComparison]::OrdinalIgnoreCase))) {
    throw "UpdateUrl must be an absolute HTTPS URL."
}

New-Item -ItemType Directory -Force -Path $extensionPath | Out-Null
Stop-Process -Name "ai_shield_browser_host" -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $sourceHost -Destination $hostPath -Force
Copy-Item -LiteralPath (Join-Path $sourceExtension "manifest.json") -Destination $extensionPath -Force
Copy-Item -LiteralPath (Join-Path $sourceExtension "service_worker.js") -Destination $extensionPath -Force
if ((Get-FileHash $sourceHost -Algorithm SHA256).Hash -ne (Get-FileHash $hostPath -Algorithm SHA256).Hash) {
    throw "Browser host copy verification failed."
}
& icacls.exe (Join-Path $env:ProgramFiles "AIShield") /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not secure browser host directory." }

$nativeManifest = [ordered]@{name="de.ai_shield.browser";description="AI Shield browser metadata sensor";
    path=$hostPath;type="stdio";allowed_origins=@("chrome-extension://$ExtensionId/")}
[IO.File]::WriteAllText($nativeManifestPath, ($nativeManifest | ConvertTo-Json -Depth 4),
    [Text.UTF8Encoding]::new($false))
foreach ($key in $nativeKeys) { New-Item -Path $key -Force | Out-Null; Set-Item -Path $key -Value $nativeManifestPath }
if (-not [string]::IsNullOrWhiteSpace($UpdateUrl)) {
    foreach ($key in $policyKeys) {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name AIShield -Value "$ExtensionId;$UpdateUrl" -PropertyType String -Force | Out-Null
    }
}
$eventSource = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\AIShieldBrowser"
New-Item -Path $eventSource -Force | Out-Null
New-ItemProperty -Path $eventSource -Name EventMessageFile -Value "$env:SystemRoot\System32\EventCreate.exe" `
    -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $eventSource -Name TypesSupported -Value 7 -PropertyType DWord -Force | Out-Null
$state = [ordered]@{schema="AIShieldBrowserSensorInstall/1";installed_utc=[DateTime]::UtcNow.ToString("o");
    extension_id=$ExtensionId;publisher_thumbprint=$signature.SignerCertificate.Thumbprint;update_url=$UpdateUrl}
[IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json -Depth 3), [Text.UTF8Encoding]::new($false))
Get-Status | ConvertTo-Json -Compress
