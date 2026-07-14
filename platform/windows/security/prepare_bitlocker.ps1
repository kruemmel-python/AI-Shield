param(
    [ValidateSet("inspect","enable")][string]$Action="inspect",
    [string]$RecoveryDirectory="",
    [switch]$ConfirmEncryption
)

$ErrorActionPreference="Stop"
$os=Get-BitLockerVolume|Where-Object VolumeType -eq OperatingSystem|Select-Object -First 1
if($null-eq$os){throw "Operating-system BitLocker volume was not found."}
if($Action-eq"inspect"){
    [ordered]@{mount_point=$os.MountPoint;volume_status=[string]$os.VolumeStatus;
        protection_status=[string]$os.ProtectionStatus;encryption_percentage=$os.EncryptionPercentage;
        protectors=@($os.KeyProtector|Select-Object KeyProtectorType,KeyProtectorId)}|ConvertTo-Json -Depth 5;exit 0
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)-or-not$ConfirmEncryption){
    throw "Elevated execution and -ConfirmEncryption are required."
}
if([string]::IsNullOrWhiteSpace($RecoveryDirectory)){throw "RecoveryDirectory is required."}
$recovery=[IO.Path]::GetFullPath($RecoveryDirectory)
$osRoot=[IO.Path]::GetPathRoot([IO.Path]::GetFullPath($os.MountPoint))
if(-not(Test-Path $recovery -PathType Container)){throw "RecoveryDirectory does not exist."}
if([IO.Path]::GetPathRoot($recovery) -eq $osRoot -and -not $recovery.StartsWith('\\')){
    throw "Recovery material must not be stored on the operating-system volume."
}
if($os.VolumeStatus-ne'FullyDecrypted'){throw "BitLocker volume is not in the expected decrypted state."}
$protector=Add-BitLockerKeyProtector -MountPoint $os.MountPoint -RecoveryPasswordProtector
$recoveryProtector=@($protector.KeyProtector|Where-Object KeyProtectorType -eq RecoveryPassword)|Select-Object -Last 1
if($null -eq $recoveryProtector -or [string]::IsNullOrWhiteSpace($recoveryProtector.RecoveryPassword)){
    throw "Recovery password creation failed."
}
$computer=($env:COMPUTERNAME-replace'[^A-Za-z0-9_-]','_')
$file=Join-Path $recovery ("AIShield-BitLocker-$computer-"+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'.txt')
[IO.File]::WriteAllText($file,("MountPoint: {0}`r`nProtectorId: {1}`r`nRecoveryPassword: {2}`r`n" -f
    $os.MountPoint,$recoveryProtector.KeyProtectorId,$recoveryProtector.RecoveryPassword),[Text.UTF8Encoding]::new($false))
if(-not (Test-Path $file) -or (Get-Item $file).Length -lt 80){throw "Recovery material verification failed."}
Enable-BitLocker -MountPoint $os.MountPoint -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
Write-Output "BitLocker staged with TPM and verified recovery password; hardware test and restart remain required"
Write-Output "recovery_file=$file"
