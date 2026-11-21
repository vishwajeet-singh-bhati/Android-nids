param(
    [ValidateSet('Prepare','Status','Smoke','Benign','FTPBruteForce','SSHBruteForce','BotBehavior','DoS','DDoS')][string]$Profile='Status',
    [switch]$Preview
)
$ErrorActionPreference='Stop'
$runner=@('--profile',$Profile)
if($Preview){$runner+='--preview'}
& python (Join-Path $PSScriptRoot 'protocol_phone_test.py') @runner
if($LASTEXITCODE -ne 0){throw 'Protocol setup/test stopped. Inspect runs\protocol_phone_tests; no next profile is scheduled.'}
