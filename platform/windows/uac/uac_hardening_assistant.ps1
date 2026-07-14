param(
    [ValidateSet("inspect","generate-reg")][string]$Action="inspect",
    [string]$OutputPath=""
)

$ErrorActionPreference="Stop"
$path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$values=Get-ItemProperty -Path $path
$issues=[Collections.Generic.List[string]]::new()
if($values.EnableLUA-ne1){$issues.Add('UAC is disabled.')}
if($values.ConsentPromptBehaviorAdmin-eq0){$issues.Add('Administrators elevate without consent or credentials.')}
if($values.PromptOnSecureDesktop-ne1){$issues.Add('Elevation prompts are not isolated on the secure desktop.')}
if($values.FilterAdministratorToken-ne1){$issues.Add('The built-in Administrator does not use Admin Approval Mode.')}
$report=[ordered]@{schema='AIShieldUacAssessment/1';generated_utc=[DateTime]::UtcNow.ToString('o');
    enable_lua=$values.EnableLUA;admin_prompt=$values.ConsentPromptBehaviorAdmin;
    secure_desktop=$values.PromptOnSecureDesktop;filter_builtin_admin=$values.FilterAdministratorToken;
    issues=$issues;recommended=[ordered]@{EnableLUA=1;ConsentPromptBehaviorAdmin=5;PromptOnSecureDesktop=1;
    FilterAdministratorToken=1};requires_restart=$true;applied=$false}
if($Action-eq"inspect"){$report|ConvertTo-Json -Depth 5;exit 0}
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path (Get-Location) 'AIShield-UAC-Recommendation.reg'}
$content=@"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"EnableLUA"=dword:00000001
"ConsentPromptBehaviorAdmin"=dword:00000005
"PromptOnSecureDesktop"=dword:00000001
"FilterAdministratorToken"=dword:00000001
"@
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),$content,[Text.UnicodeEncoding]::new($false,$true))
Write-Output "Recommendation generated but not applied: $OutputPath"

