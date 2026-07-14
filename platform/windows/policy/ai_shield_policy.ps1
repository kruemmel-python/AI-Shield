param(
    [ValidateSet("initialize", "sign", "apply", "recover", "status")]
    [string]$Action,
    [string]$InputFile,
    [string]$OutputFile
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$kernelctl = Join-Path $repo "build_vs\Release\ai_shield_kernelctl.exe"
$driverctl = Join-Path $repo "build_vs\Release\ai_shield_driverctl.exe"
$broker = Join-Path $repo "build_vs\Release\ai_shield_broker.exe"
$stateDir = Join-Path $env:ProgramData "AIShield\policy"
$pinFile = Join-Path $stateDir "signer.thumbprint"
$currentFile = Join-Path $stateDir "current.aipolicy"
$previousFile = Join-Path $stateDir "previous.aipolicy"
$stagedFile = Join-Path $stateDir "staged.aipolicy"
$stateFile = Join-Path $stateDir "state.json"
$certificateSubject = "CN=AI Shield Local Policy Signing"

function Confirm-Administrator {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Policy management requires an elevated PowerShell."
    }
}

function Write-AtomicText([string]$Path, [string]$Text) {
    $temporary = "$Path.tmp"
    [IO.File]::WriteAllText($temporary, $Text, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-PinnedCertificate([bool]$RequirePrivateKey) {
    if (-not (Test-Path -LiteralPath $pinFile)) { throw "Policy signer pin is missing." }
    $thumbprint = (Get-Content -LiteralPath $pinFile -Raw).Trim()
    if ($thumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw "Policy signer pin is malformed." }
    $certificate = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop
    if ($RequirePrivateKey -and -not $certificate.HasPrivateKey) { throw "Policy signing private key is unavailable." }
    return $certificate
}

function Get-PayloadBytes($Policy) {
    $ordered = [ordered]@{
        schema = [uint32]1
        security_version = [uint64]$Policy.security_version
        mode = [string]$Policy.mode
        block_inbound_port = [uint32]$Policy.block_inbound_port
        redirect_outbound_port = [uint32]$Policy.redirect_outbound_port
        proxy_port = [uint32]$Policy.proxy_port
        block_quarantine_execution = [bool]$Policy.block_quarantine_execution
        block_user_temp_execution = [bool]$Policy.block_user_temp_execution
        block_download_execution = [bool]$Policy.block_download_execution
        block_risky_script_command = [bool]$Policy.block_risky_script_command
        block_office_child_process = [bool]$Policy.block_office_child_process
        system_network_guard = [bool]$Policy.system_network_guard
        block_unsolicited_inbound = [bool]$Policy.block_unsolicited_inbound
        block_browser_non_web = [bool]$Policy.block_browser_non_web
    }
    if ($ordered.security_version -eq 0) { throw "security_version must be greater than zero." }
    if ($ordered.mode -notin @("audit", "enforce")) { throw "mode must be audit or enforce." }
    foreach ($port in @($ordered.block_inbound_port, $ordered.redirect_outbound_port, $ordered.proxy_port)) {
        if ($port -gt 65535) { throw "Policy port is outside the valid range." }
    }
    if (($ordered.redirect_outbound_port -eq 0) -ne ($ordered.proxy_port -eq 0)) {
        throw "Redirect and proxy ports must be configured together."
    }
    if ($ordered.redirect_outbound_port -ne 0 -and $ordered.redirect_outbound_port -eq $ordered.proxy_port) {
        throw "Redirect and proxy ports must differ."
    }
    return [Text.Encoding]::UTF8.GetBytes(($ordered | ConvertTo-Json -Compress))
}

function New-SignedEnvelope($Policy, [string]$Destination) {
    $certificate = Get-PinnedCertificate $true
    $payload = Get-PayloadBytes $Policy
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        $signature = $rsa.SignData($payload, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pss)
    } finally {
        $rsa.Dispose()
    }
    $envelope = [ordered]@{
        format = "AIShieldPolicy/1"
        signer = $certificate.Thumbprint
        payload = [Convert]::ToBase64String($payload)
        signature = [Convert]::ToBase64String($signature)
    }
    Write-AtomicText $Destination ($envelope | ConvertTo-Json -Compress)
}

function Read-VerifiedPolicy([string]$Path) {
    $envelope = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($envelope.format -ne "AIShieldPolicy/1") { throw "Unsupported policy envelope." }
    $certificate = Get-PinnedCertificate $false
    if ($envelope.signer -ne $certificate.Thumbprint) { throw "Policy signer does not match the pinned certificate." }
    $payload = [Convert]::FromBase64String([string]$envelope.payload)
    $signature = [Convert]::FromBase64String([string]$envelope.signature)
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    try {
        $valid = $rsa.VerifyData($payload, $signature, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pss)
    } finally {
        $rsa.Dispose()
    }
    if (-not $valid) { throw "Policy signature verification failed." }
    $policy = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
    [void](Get-PayloadBytes $policy)
    return $policy
}

function Test-VerifiedPolicy([string]$Path) {
    trap { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    [void](Read-VerifiedPolicy $Path)
    return $true
}

function Get-PolicyState {
    if (-not (Test-Path -LiteralPath $stateFile)) {
        return [ordered]@{ security_version = [uint64]0; recovery_required = $false; last_result = "uninitialized" }
    }
    return Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
}

function Set-PolicyState([uint64]$SecurityVersion, [bool]$RecoveryRequired, [string]$Result) {
    $state = [ordered]@{
        security_version = $SecurityVersion
        model_version = [uint64]1
        recovery_required = $RecoveryRequired
        last_result = $Result
        updated_utc = [DateTime]::UtcNow.ToString("o")
    }
    Write-AtomicText $stateFile ($state | ConvertTo-Json -Compress)
    if ($SecurityVersion -gt 0) {
        if (-not (Test-Path -LiteralPath $broker)) { throw "Telemetry broker is unavailable for runtime synchronization." }
        & $broker runtime-sync $SecurityVersion 1
        if ($LASTEXITCODE -ne 0) { throw "Authenticated runtime synchronization failed." }
    }
}

function Invoke-KernelPolicy($Policy) {
    if ($Policy.mode -eq "audit") {
        & $kernelctl audit
    } else {
        $arguments = @("enforce", "--confirm-enforcement")
        if ([uint32]$Policy.block_inbound_port -ne 0) { $arguments += @("--block-inbound", $Policy.block_inbound_port) }
        if ([uint32]$Policy.redirect_outbound_port -ne 0) {
            $gatewayPidFile = Join-Path $repo "runtime\ai_shield_prototype.pid"
            if (-not (Test-Path -LiteralPath $gatewayPidFile)) { throw "Gateway PID state is missing for redirect enforcement." }
            $gatewayPid = [uint32](Get-Content -LiteralPath $gatewayPidFile -Raw)
            $arguments += @("--redirect-port", $Policy.redirect_outbound_port, "--proxy-port", $Policy.proxy_port,
                "--exempt-pid", $gatewayPid)
        }
        if ([bool]$Policy.block_quarantine_execution) { $arguments += "--block-quarantine-execution" }
        if ([bool]$Policy.block_user_temp_execution) { $arguments += "--block-user-temp-execution" }
        if ([bool]$Policy.block_download_execution) { $arguments += "--block-download-execution" }
        if ([bool]$Policy.block_risky_script_command) { $arguments += "--block-risky-script-command" }
        if ([bool]$Policy.block_office_child_process) { $arguments += "--block-office-child-process" }
        if ([bool]$Policy.system_network_guard) { $arguments += "--system-network-guard" }
        if ([bool]$Policy.block_unsolicited_inbound) { $arguments += "--block-unsolicited-inbound" }
        if ([bool]$Policy.block_browser_non_web) { $arguments += "--block-browser-non-web" }
        & $kernelctl @arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "Kernel rejected the policy." }
    $driverStatus = (& $driverctl status 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or ([regex]::Matches($driverStatus, "state=4 win32_exit=0")).Count -ne 3) {
        throw "Driver health check failed after policy application."
    }
}

function Restore-ActivePolicy {
    $recoveryFile = if (Test-VerifiedPolicy $currentFile) { $currentFile }
        elseif (Test-VerifiedPolicy $previousFile) { $previousFile }
        else { $null }
    if (-not $recoveryFile) {
        & $kernelctl audit
        Set-PolicyState 0 $true "recovery-audit"
        return
    }
    $recovered = Read-VerifiedPolicy $recoveryFile
    Invoke-KernelPolicy $recovered
    if ($recoveryFile -ne $currentFile) { Copy-Item -LiteralPath $recoveryFile -Destination $currentFile -Force }
    Set-PolicyState ([uint64]$recovered.security_version) $false "rolled-back"
}

Confirm-Administrator

if ($Action -eq "initialize") {
    New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
    & icacls.exe $stateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not secure policy state directory." }
    if (Test-Path -LiteralPath $pinFile) {
        if (-not (Test-Path -LiteralPath $currentFile) -or -not (Test-Path -LiteralPath $stateFile)) {
            throw "Policy initialization is incomplete; recovery requires an administrator."
        }
        $existingPolicy = Read-VerifiedPolicy $currentFile
        $existingState = Get-PolicyState
        if ([uint64]$existingPolicy.security_version -ne [uint64]$existingState.security_version) {
            throw "Policy state and signed active policy disagree."
        }
        Write-Output "policy already initialized security_version=$($existingPolicy.security_version)"
        exit 0
    }
    $certificate = New-SelfSignedCertificate -Type Custom -Subject $certificateSubject -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyUsage DigitalSignature `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(5)
    Write-AtomicText $pinFile $certificate.Thumbprint
    $default = [ordered]@{ security_version = [uint64]1; mode = "audit"; block_inbound_port = 0;
        redirect_outbound_port = 0; proxy_port = 0; block_quarantine_execution = $true;
        block_user_temp_execution = $true; block_download_execution = $false;
        block_risky_script_command = $true; block_office_child_process = $true;
        system_network_guard = $true; block_unsolicited_inbound = $false;
        block_browser_non_web = $false }
    New-SignedEnvelope $default $currentFile
    Set-PolicyState 1 $false "initialized"
    Write-Output "policy initialized signer=$($certificate.Thumbprint)"
    exit 0
}

if ($Action -eq "sign") {
    if (-not $InputFile -or -not $OutputFile) { throw "sign requires InputFile and OutputFile." }
    New-SignedEnvelope (Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json) $OutputFile
    Write-Output "signed policy: $OutputFile"
    exit 0
}

if ($Action -eq "apply") {
    if (-not $InputFile) { throw "apply requires InputFile." }
    $policy = Read-VerifiedPolicy $InputFile
    $state = Get-PolicyState
    if ([uint64]$policy.security_version -le [uint64]$state.security_version) { throw "Policy downgrade or replay rejected." }
    Copy-Item -LiteralPath $InputFile -Destination $stagedFile -Force
    Set-PolicyState ([uint64]$state.security_version) $true "applying"
    $applied = $false
    try {
        Invoke-KernelPolicy $policy
        if (Test-Path -LiteralPath $currentFile) { Copy-Item $currentFile $previousFile -Force }
        Move-Item -LiteralPath $stagedFile -Destination $currentFile -Force
        Set-PolicyState ([uint64]$policy.security_version) $false "active"
        $applied = $true
    } finally {
        if (-not $applied) { Restore-ActivePolicy }
    }
    Write-Output "policy active security_version=$($policy.security_version)"
    exit 0
}

if ($Action -eq "recover") {
    $state = Get-PolicyState
    if ([bool]$state.recovery_required) { Restore-ActivePolicy }
    elseif (Test-Path -LiteralPath $currentFile) { Invoke-KernelPolicy (Read-VerifiedPolicy $currentFile) }
    else { & $kernelctl audit }
    Write-Output "policy recovery completed"
    exit 0
}

if ($Action -eq "status") {
    $state = Get-PolicyState
    $policy = Read-VerifiedPolicy $currentFile
    Write-Output "policy signature=valid security_version=$($policy.security_version) mode=$($policy.mode)"
    Write-Output "recovery_required=$($state.recovery_required) last_result=$($state.last_result)"
    exit 0
}
