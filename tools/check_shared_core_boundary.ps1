$ErrorActionPreference = "Stop"
$patterns = @(
    "windows\.h",
    "ntddk\.h",
    "wdm\.h",
    "fwpsk\.h",
    "fwpmk\.h",
    "fltKernel\.h",
    "\bHANDLE\b",
    "\bNTSTATUS\b",
    "\bUNICODE_STRING\b",
    "\bIRP\b",
    "\bNET_BUFFER_LIST\b"
)
$paths = @("include\ai_shield", "src")
$hits = foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -File | Select-String -Pattern $patterns
    }
}
if ($hits) {
    $hits | ForEach-Object { Write-Error "$($_.Path):$($_.LineNumber): $($_.Line)" }
    exit 1
}
Write-Output "shared-core-boundary-ok"
