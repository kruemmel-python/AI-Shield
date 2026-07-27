[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("sign", "verify")]
    [string]$Action,

    [Parameter(Mandatory)]
    [string]$PayloadPath,

    [Parameter(Mandatory)]
    [string]$SignaturePath,

    [ValidatePattern("^[0-9A-Fa-f]{40}$")]
    [string]$SigningCertificateThumbprint,

    [ValidatePattern("^[0-9A-Fa-f]{64}$")]
    [string]$TrustedCertificateSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Security

function Get-CertificateSha256 {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
}

$payload = (Resolve-Path -LiteralPath $PayloadPath).Path
$content = [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($payload))

if ($Action -eq "sign") {
    if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        throw "sign requires SigningCertificateThumbprint."
    }
    $thumbprint = $SigningCertificateThumbprint.ToUpperInvariant()
    $certificate = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
    if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
        throw "The LocalMachine signing certificate does not exist or has no private key."
    }
    $now = Get-Date
    if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
        throw "The signing certificate is outside its validity period."
    }
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $certificate)
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new("2.16.840.1.101.3.4.2.1")
    $signer.IncludeOption =
        [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cms.ComputeSignature($signer, $false)
    [IO.File]::WriteAllBytes($SignaturePath, $cms.Encode())
    Write-Output ("signed payload={0} signer_sha256={1}" -f
        $payload, (Get-CertificateSha256 $certificate))
    exit 0
}

if ([string]::IsNullOrWhiteSpace($TrustedCertificateSha256)) {
    throw "verify requires TrustedCertificateSha256."
}
if (-not (Test-Path -LiteralPath $SignaturePath -PathType Leaf)) {
    throw "Detached CMS signature does not exist."
}

$cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
$cms.Decode([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $SignaturePath).Path))
if ($cms.SignerInfos.Count -ne 1) {
    throw "Exactly one CMS signer is required."
}
$cms.CheckSignature($true)
$signerCertificate = $cms.SignerInfos[0].Certificate
if ($null -eq $signerCertificate) {
    throw "CMS signature does not contain the signer certificate."
}
$actualPin = Get-CertificateSha256 $signerCertificate
if ($actualPin -ne $TrustedCertificateSha256.ToUpperInvariant()) {
    throw "CMS signer does not match the pinned SHA-256 certificate fingerprint."
}

$chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
try {
    $chain.ChainPolicy.RevocationMode =
        [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    $chain.ChainPolicy.RevocationFlag =
        [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $chain.ChainPolicy.VerificationFlags =
        [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(15)
    if (-not $chain.Build($signerCertificate)) {
        $status = ($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ","
        throw "CMS signer certificate chain or revocation check failed: $status"
    }
} finally {
    $chain.Dispose()
}

Write-Output ("verified payload={0} signer_sha256={1}" -f $payload, $actualPin)
