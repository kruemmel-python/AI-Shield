param(
    [string]$ConsumerPackage = "AI_Shield_Private_Desktop.zip",
    [string]$OutputDirectory = "dist\msi",
    [switch]$SkipSigning
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$packagePath = if ([IO.Path]::IsPathRooted($ConsumerPackage)) {
    [IO.Path]::GetFullPath($ConsumerPackage)
} else { [IO.Path]::GetFullPath((Join-Path $repo $ConsumerPackage)) }
$outputRoot = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else { [IO.Path]::GetFullPath((Join-Path $repo $OutputDirectory)) }
$wixBin = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
$heat = Join-Path $wixBin "heat.exe"
$candle = Join-Path $wixBin "candle.exe"
$light = Join-Path $wixBin "light.exe"
$signtoolCandidates = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
)

foreach ($required in @($packagePath, $heat, $candle, $light)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required build input is missing: $required" }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("AIShieldMsi_" + [Guid]::NewGuid().ToString("N"))
$extract = Join-Path $work "extract"
$obj = Join-Path $work "obj"
$payload = Join-Path $extract "AI_Shield_Private_Desktop"
$harvest = Join-Path $work "Payload.wxs"
$msiName = "AI_Shield_Private_Desktop_2.0.0-rc.8_x64.msi"
$msiPath = Join-Path $outputRoot $msiName

try {
    New-Item -ItemType Directory -Force -Path $extract, $obj, $outputRoot | Out-Null
    Expand-Archive -LiteralPath $packagePath -DestinationPath $extract -Force
    if (-not (Test-Path -LiteralPath (Join-Path $payload "PACKAGE_MANIFEST.json"))) {
        throw "Consumer package root or manifest is invalid."
    }
    $manifest = Get-Content -LiteralPath (Join-Path $payload "PACKAGE_MANIFEST.json") -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files) {
        $file = Join-Path $payload ([string]$entry.path).Replace('/', '\')
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Manifest file is missing: $($entry.path)" }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne [string]$entry.sha256) {
            throw "Manifest hash mismatch: $($entry.path)"
        }
    }

    & $heat dir $payload -nologo -ag -srd -sreg -scom -sfrag `
        -cg PayloadComponents -dr INSTALLFOLDER -var "var.PayloadDir" -out $harvest
    if ($LASTEXITCODE -ne 0) { throw "WiX payload harvesting failed with exit code $LASTEXITCODE." }
    & $candle -nologo -arch x64 "-dPayloadDir=$payload" "-dSourceDir=$PSScriptRoot" `
        -out ($obj + "\") (Join-Path $PSScriptRoot "AIShieldPrivateDesktop.wxs") $harvest
    if ($LASTEXITCODE -ne 0) { throw "WiX compilation failed with exit code $LASTEXITCODE." }
    & $light -nologo -ext WixUIExtension -cultures:de-de -sice:ICE61 `
        -out $msiPath (Join-Path $obj "AIShieldPrivateDesktop.wixobj") (Join-Path $obj "Payload.wixobj")
    if ($LASTEXITCODE -ne 0) { throw "WiX linking or MSI validation failed with exit code $LASTEXITCODE." }

    if (-not $SkipSigning) {
        $signtool = $signtoolCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        $certificatePath = Join-Path $payload "driver_package\Release\ai_shield_testsigning.cer"
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
        $storeCertificate = Get-ChildItem Cert:\LocalMachine\My,Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $certificate.Thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
        if ($null -eq $signtool -or $null -eq $storeCertificate) {
            throw "MSI signing requires signtool and the local AI Shield test-signing private key. Use -SkipSigning only for development."
        }
        $signArguments = @("sign", "/fd", "SHA256", "/sha1", $certificate.Thumbprint, "/s", "My")
        if ($storeCertificate.PSParentPath -match 'LocalMachine') { $signArguments += "/sm" }
        $signArguments += $msiPath
        & $signtool @signArguments
        if ($LASTEXITCODE -ne 0) { throw "MSI signing failed with exit code $LASTEXITCODE." }
        & $signtool verify /pa /v $msiPath
        if ($LASTEXITCODE -ne 0) { throw "MSI signature verification failed with exit code $LASTEXITCODE." }
    }

    Copy-Item -LiteralPath $msiPath -Destination (Join-Path $outputRoot "AI_Shield_Private_Desktop.msi") -Force
    $hash = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText((Join-Path $outputRoot "$msiName.sha256"), "$hash  $msiName`r`n",
        [Text.UTF8Encoding]::new($false))
    Write-Output "created=$msiPath"
    Write-Output "sha256=$hash"
} finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
