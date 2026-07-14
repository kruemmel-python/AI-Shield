$ErrorActionPreference = "Stop"
$transactionPath = Join-Path $env:ProgramData "AIShield\update-transaction.json"
if (-not (Test-Path $transactionPath)) { Write-Output "no pending update"; exit 0 }
$transaction = Get-Content $transactionPath -Raw | ConvertFrom-Json
if ($transaction.format -ne "AIShieldUpdateTransaction/2" -or
    [string]::IsNullOrWhiteSpace($transaction.previous_broker_path) -or
    [string]::IsNullOrWhiteSpace($transaction.previous_core_path)) {
    throw "Pending update transaction is malformed."
}
$root = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "AIShield")).TrimEnd('\') + '\'
$broker = [IO.Path]::GetFullPath([string]$transaction.previous_broker_path)
$core = [IO.Path]::GetFullPath([string]$transaction.previous_core_path)
if (-not $broker.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
    -not $core.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {
    throw "Pending update recovery path escaped the protected installation root."
}
if (-not (Test-Path $broker) -or -not (Test-Path $core)) { throw "Recovery slot is incomplete." }
Stop-Service AIShieldCore,AIShieldBroker -Force -ErrorAction SilentlyContinue
& sc.exe config AIShieldBroker binPath= ('"' + $broker + '"') | Out-Null
& sc.exe config AIShieldCore binPath= ('"' + $core + '"') | Out-Null
Start-Service AIShieldBroker
Start-Service AIShieldCore
Remove-Item $transactionPath -Force
Write-Output "rolled back pending update to protected service baseline"
