function Get-AIShieldPrivateRoot {
    $sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    foreach ($candidate in @($sourceRoot, [IO.Path]::GetFullPath($PSScriptRoot))) {
        if (Test-Path -LiteralPath (Join-Path $candidate "build_vs\Release\ai_shield_driverctl.exe")) {
            return $candidate
        }
    }
    throw "AI Shield program files were not found. Extract the complete private desktop package first."
}

function Test-AIShieldAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-AIShieldElevated([string]$ScriptPath, [string[]]$ForwardedArguments = @()) {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $ScriptPath + '"'))
    $arguments += $ForwardedArguments
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments
}

function Assert-AIShieldFile([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing: $Path"
    }
}
