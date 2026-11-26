param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('PortScan','SlowScan','PasswordGuessing','SQLInjection','XSS','HTTPFlood','ConnectionExhaustion','Beacon','Benign','ClosedPortControl','NormalBurst','NmapScan','Status','Check','Smoke','Clean')]
    [string]$Profile,
    [ValidateRange(10,180)][int]$ObserveSeconds=130,
    [ValidateRange(0.2,10.0)][double]$LoginIntervalSeconds=0.2,
    [ValidateSet('connect','syn')][string]$NmapType='connect',
    [switch]$Preview
)
$ErrorActionPreference='Stop'
$pythonCommand=Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonCommand) { throw 'Python 3 is required on this work PC.' }
$runnerArgs=@('--profile',$Profile,'--observe-seconds',$ObserveSeconds,'--login-interval-seconds',$LoginIntervalSeconds,'--nmap-type',$NmapType)
if ($Preview) { $runnerArgs+='--preview' }
& $pythonCommand.Source (Join-Path $PSScriptRoot 'controlled_phone_test.py') @runnerArgs
if ($LASTEXITCODE -ne 0) { throw "Controlled test stopped. See the message above; no next test was scheduled." }
