param(
    [Parameter(Mandatory=$true)]
    [string]$PackageDirectory
)

$ErrorActionPreference="Stop"
$kitsBin="C:\Program Files (x86)\Windows Kits\10\bin"
$signtool=Get-ChildItem $kitsBin -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object FullName -match "\\x64\\" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "x64 SignTool from the Windows Driver Kit is required." }
$files=@(Get-ChildItem $PackageDirectory -Recurse -File | Where-Object Extension -in @(".sys",".cat"))
if (($files|Where-Object Extension -eq ".sys").Count -ne 3 -or ($files|Where-Object Extension -eq ".cat").Count -ne 3) {
    throw "Expected exactly three SYS and three CAT files in the returned package."
}
foreach($file in $files){
    & $signtool.FullName verify /kp /all /v $file.FullName
    if($LASTEXITCODE -ne 0){throw "Microsoft kernel signature verification failed: $($file.FullName)"}
}
$manifest=@($files|Sort-Object FullName|ForEach-Object{[ordered]@{path=$_.FullName.Substring((Resolve-Path $PackageDirectory).Path.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash;size=$_.Length}})
$output=Join-Path $PackageDirectory "MICROSOFT_SIGNED_SHA256SUMS.json"
[IO.File]::WriteAllText($output,($manifest|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
Write-Output "microsoft kernel signature gate passed files=$($files.Count)"
Write-Output "manifest=$output"
