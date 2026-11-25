<# Install an owner's public key and a controller-scoped SSH rule on one lab source PC.
Run in Administrator Windows PowerShell 5.1. No test traffic is generated.
#>
param(
    [Parameter(Mandatory=$true)][string]$PublicKeyFile,
    [Parameter(Mandatory=$true)][string]$ControllerIp,
    [string]$Login=$env:USERNAME
)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Use Administrator PowerShell on the owned source PC.'}
$address=[System.Net.IPAddress]::Parse($ControllerIp)
if($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork){throw 'Use the controller private IPv4 address.'}
$octets=$address.GetAddressBytes()
$isPrivate=$octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or ($octets[0] -eq 192 -and $octets[1] -eq 168)
if(-not $isPrivate){throw 'Only a private lab-controller IPv4 address is accepted.'}
$publicKey=(Get-Content -Raw -LiteralPath $PublicKeyFile).Trim()
if($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [^\r\n]*)?$'){throw 'Supply one Ed25519 public-key line, never a private key.'}
$account=Get-LocalUser -Name $Login
$adminSids=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {$_.SID.Value})
$isAdmin=$adminSids -contains $account.SID.Value
if($isAdmin){$keyPath=Join-Path (Join-Path $env:ProgramData 'ssh') 'administrators_authorized_keys'}
else{
    $labUserProfile=Get-CimInstance Win32_UserProfile | Where-Object {$_.SID -eq $account.SID.Value} | Select-Object -First 1
    if(-not $labUserProfile){throw 'The requested local account has no Windows profile.'}
    $keyPath=Join-Path (Join-Path $labUserProfile.LocalPath '.ssh') 'authorized_keys'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $keyPath) | Out-Null
if(Test-Path -LiteralPath $keyPath){Copy-Item -LiteralPath $keyPath -Destination ($keyPath+'.rakshak-backup-'+(Get-Date -Format 'yyyyMMddHHmmssfff'))}
if(-not(Test-Path -LiteralPath $keyPath) -or -not((Get-Content -LiteralPath $keyPath) -contains $publicKey)){
    Add-Content -LiteralPath $keyPath -Value ("`r`n"+$publicKey) -Encoding Ascii
}
if($isAdmin){& icacls.exe $keyPath /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'}
else{
    & icacls.exe $keyPath /inheritance:r /grant:r ('*'+$account.SID.Value+':F') '*S-1-5-32-544:F' '*S-1-5-18:F'
    if($LASTEXITCODE -ne 0){throw 'SSH key ACL failed.'}
    & icacls.exe $keyPath /setowner ('*'+$account.SID.Value)
}
if($LASTEXITCODE -ne 0){throw 'SSH key ACL failed.'}
$rule=Get-NetFirewallRule -Name 'Rakshak-Lab-SSH' -ErrorAction SilentlyContinue
if($rule){
    $filters=@($rule | Get-NetFirewallAddressFilter)
    if($filters.Count -ne 1 -or $filters[0].RemoteAddress -ne $ControllerIp){throw 'Existing Rakshak-Lab-SSH rule has another source; review it before changing.'}
}else{
    New-NetFirewallRule -Name 'Rakshak-Lab-SSH' -DisplayName 'Rakshak SSH from owned controller' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $ControllerIp -Profile Any | Out-Null
}
Write-Output ('Public key installed for '+$account.Name+'; TCP22 allowed only from controller '+$ControllerIp+'. Existing rules are retained.')
