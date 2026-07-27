[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("configure", "status", "remove")]
    [string]$Action,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$OrganizationId,

    [ValidateRange(1, [long]::MaxValue)]
    [long]$SiteId,

    [uri]$ControlPlaneUri,

    [ValidatePattern("^[0-9A-Fa-f]{64}$")]
    [string]$PinnedSpkiSha256,

    [ValidatePattern("^[0-9A-Fa-f]{40}$")]
    [string]$CertificateThumbprint,

    [string]$StateDirectory = "$env:ProgramData\AIShield\enterprise"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Security

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Enterprise enrollment requires an elevated PowerShell."
    }
}

function Get-StatePath {
    Join-Path $StateDirectory "enrollment.bin"
}

function Set-StateAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Protect-MachineData {
    param([Parameter(Mandatory)][byte[]]$Plaintext)
    $entropy = [Text.Encoding]::UTF8.GetBytes("AIShield/EnterpriseEnrollment/v1")
    [Security.Cryptography.ProtectedData]::Protect(
        $Plaintext, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
}

function Unprotect-MachineData {
    param([Parameter(Mandatory)][byte[]]$Ciphertext)
    $entropy = [Text.Encoding]::UTF8.GetBytes("AIShield/EnterpriseEnrollment/v1")
    [Security.Cryptography.ProtectedData]::Unprotect(
        $Ciphertext, $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
}

function Get-Enrollment {
    $path = Get-StatePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Enterprise enrollment is not configured."
    }
    $plain = Unprotect-MachineData ([IO.File]::ReadAllBytes($path))
    try {
        [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    } finally {
        [Array]::Clear($plain, 0, $plain.Length)
    }
}

Assert-Elevated

switch ($Action) {
    "configure" {
        if ($OrganizationId -le 0 -or $SiteId -le 0 -or $null -eq $ControlPlaneUri -or
            [string]::IsNullOrWhiteSpace($PinnedSpkiSha256) -or
            [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            throw "configure requires OrganizationId, SiteId, ControlPlaneUri, PinnedSpkiSha256 and CertificateThumbprint."
        }
        if ($ControlPlaneUri.Scheme -ne "https" -or -not [string]::IsNullOrEmpty($ControlPlaneUri.UserInfo) -or
            -not [string]::IsNullOrEmpty($ControlPlaneUri.Fragment)) {
            throw "The control plane must be an HTTPS URI without user information or fragment."
        }
        $thumbprint = $CertificateThumbprint.ToUpperInvariant()
        $certificate = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
        if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
            throw "The LocalMachine client certificate does not exist or has no private key."
        }
        $now = Get-Date
        if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
            throw "The enrollment certificate is outside its validity period."
        }
        $clientAuthOid = "1.3.6.1.5.5.7.3.2"
        $hasClientAuth = $false
        foreach ($extension in $certificate.Extensions) {
            if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                $hasClientAuth = $extension.EnhancedKeyUsages |
                    Where-Object { $_.Value -eq $clientAuthOid } |
                    Select-Object -First 1
            }
        }
        if (-not $hasClientAuth) {
            throw "The certificate does not permit TLS client authentication."
        }

        $machineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $bindingBytes = $sha256.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes("$machineGuid|$OrganizationId|$SiteId"))
            $deviceBinding = ([BitConverter]::ToString($bindingBytes)).Replace("-", "")
        } finally {
            $sha256.Dispose()
        }
        $state = [ordered]@{
            schema = "AIShieldEnterpriseEnrollment/v1"
            organization_id = $OrganizationId
            site_id = $SiteId
            control_plane_uri = $ControlPlaneUri.AbsoluteUri
            pinned_spki_sha256 = $PinnedSpkiSha256.ToUpperInvariant()
            certificate_thumbprint = $thumbprint
            device_binding_sha256 = $deviceBinding
            configured_utc = [DateTime]::UtcNow.ToString("O")
        }
        New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
        Set-StateAcl -Path $StateDirectory
        $plain = [Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json -Compress))
        try {
            $cipher = Protect-MachineData $plain
            $temporary = Join-Path $StateDirectory ("enrollment.{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
            [IO.File]::WriteAllBytes($temporary, $cipher)
            Move-Item -LiteralPath $temporary -Destination (Get-StatePath) -Force
        } finally {
            [Array]::Clear($plain, 0, $plain.Length)
        }
        Set-StateAcl -Path $StateDirectory
        Write-Output "AI Shield enterprise enrollment configured."
    }
    "status" {
        $state = Get-Enrollment
        $certificate = Get-ChildItem "Cert:\LocalMachine\My\$($state.certificate_thumbprint)" `
            -ErrorAction SilentlyContinue
        [pscustomobject]@{
            OrganizationId = $state.organization_id
            SiteId = $state.site_id
            ControlPlane = $state.control_plane_uri
            DeviceBinding = $state.device_binding_sha256
            CertificatePresent = $null -ne $certificate
            CertificateExpires = if ($null -ne $certificate) { $certificate.NotAfter } else { $null }
            ConfiguredUtc = $state.configured_utc
        } | Format-List
    }
    "remove" {
        $path = Get-StatePath
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
        Write-Output "AI Shield enterprise enrollment removed. The device certificate was retained."
    }
}
