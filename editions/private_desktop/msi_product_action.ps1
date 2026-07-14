param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("install", "uninstall")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
$logRoot = Join-Path $env:ProgramData "AIShield\installer"
$logPath = Join-Path $logRoot "msi-product-action.log"

function Write-AIShieldMsiLog([string]$Message) {
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $line = "{0} action={1} {2}" -f [DateTime]::UtcNow.ToString("o"), $Action, $Message
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
    Write-Output $line
}

function Invoke-AIShieldChild([string]$Script, [string[]]$Arguments, [string]$LogPrefix) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $output | ForEach-Object { Write-AIShieldMsiLog "$LogPrefix $_" }
    if ($exitCode -ne 0) { throw "$LogPrefix failed with exit code $exitCode." }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The MSI product action must run elevated."
    }
    Write-AIShieldMsiLog "started identity=$($identity.Name) root=$PSScriptRoot"

    if ($Action -eq "install") {
        $marker = Join-Path $env:ProgramData "AIShield\private-desktop\install.json"
        $script:hadExistingInstallation = Test-Path -LiteralPath $marker
        if ($script:hadExistingInstallation) {
            Write-AIShieldMsiLog "existing installation detected; refreshing components in place"
        }
        Invoke-AIShieldChild -Script (Join-Path $PSScriptRoot "install_private_desktop.ps1") `
            -Arguments @("-SuppressUiLaunch", "-RefreshInstalledComponents") -LogPrefix "install"
        Write-AIShieldMsiLog "completed"
        exit 0
    }

    Invoke-AIShieldChild -Script (Join-Path $PSScriptRoot "uninstall_private_desktop.ps1") `
        -Arguments @() -LogPrefix "uninstall"
    Write-AIShieldMsiLog "completed; audit and quarantine data preserved"
} catch {
    Write-AIShieldMsiLog "failed error=$($_.Exception.Message)"
    if ($Action -eq "install" -and $script:hadExistingInstallation -ne $true) {
        Write-AIShieldMsiLog "rolling back resources from failed fresh installation"
        try {
            Invoke-AIShieldChild -Script (Join-Path $PSScriptRoot "uninstall_private_desktop.ps1") `
                -Arguments @() -LogPrefix "rollback"
        } catch {
            Write-AIShieldMsiLog "rollback failed error=$($_.Exception.Message)"
        }
    }
    Write-Error $_
    exit 1
}
