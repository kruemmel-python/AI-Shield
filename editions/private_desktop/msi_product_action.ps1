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
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `
            (Join-Path $PSScriptRoot "install_private_desktop.ps1") -SuppressUiLaunch -RefreshInstalledComponents 2>&1 |
            ForEach-Object { Write-AIShieldMsiLog "install $_" }
        if ($LASTEXITCODE -ne 0) { throw "Product installation failed with exit code $LASTEXITCODE." }
        Write-AIShieldMsiLog "completed"
        exit 0
    }

    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `
        (Join-Path $PSScriptRoot "uninstall_private_desktop.ps1") 2>&1 |
        ForEach-Object { Write-AIShieldMsiLog "uninstall $_" }
    if ($LASTEXITCODE -ne 0) { throw "Product removal failed with exit code $LASTEXITCODE." }
    Write-AIShieldMsiLog "completed; audit and quarantine data preserved"
} catch {
    Write-AIShieldMsiLog "failed error=$($_.Exception.Message)"
    if ($Action -eq "install" -and $script:hadExistingInstallation -ne $true) {
        Write-AIShieldMsiLog "rolling back resources from failed fresh installation"
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `
            (Join-Path $PSScriptRoot "uninstall_private_desktop.ps1") 2>&1 |
            ForEach-Object { Write-AIShieldMsiLog "rollback $_" }
    }
    Write-Error $_
    exit 1
}
