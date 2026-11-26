param(
    [ValidateSet('All','Controlled','Protocol')][string]$Suite='All',
    [switch]$Preview,
    [switch]$PreflightOnly
)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $pythonCommand=Get-Command python.exe -ErrorAction SilentlyContinue
    if(-not $pythonCommand){throw 'Python 3 is required; activate the documented environment first.'}
    $planText=& $pythonCommand.Source (Join-Path $projectRoot 'validation/network_test_plan.py') --suite $Suite
    if($LASTEXITCODE -ne 0){throw 'Command sheet is invalid. No tests started.'}
    $selection=($planText -join "`n") | ConvertFrom-Json
    Write-Host ("Suite: {0}; cases: {1}; sequential execution; stop on first failure." -f $Suite,$selection.cases)
    if($Preview){
        foreach($step in $selection.plan){
            if($step.kind -eq 'wait'){Write-Output ("Wait {0} seconds" -f $step.seconds)}
            else {Write-Output ("{0}: {1}" -f $step.kind,$step.profile)}
        }
        Write-Output 'Preview only: no ADB, SSH, target, capture, wait or test traffic.'
        return
    }
    & $pythonCommand.Source (Join-Path $projectRoot 'validation/network_test_preflight.py') --suite $Suite
    if($LASTEXITCODE -ne 0){throw 'Preflight failed. No test started; fix the reported setup issue first.'}
    if($PreflightOnly){return}
    $completed=0
    foreach($step in $selection.plan){
        if($step.kind -eq 'wait'){
            Write-Host ("Waiting {0} seconds with monitoring running to isolate connection history." -f $step.seconds)
            Start-Sleep -Seconds $step.seconds
            continue
        }
        $runnerName=if($step.kind -eq 'controlled'){'Run-ControlledPhoneTest.ps1'}else{'Run-ProtocolPhoneTest.ps1'}
        Write-Host ("Case {0}/{1}: {2} {3}" -f ($completed+1),$selection.cases,$step.kind,$step.profile)
        & (Join-Path $projectRoot ('validation/'+$runnerName)) -Profile $step.profile
        if($LASTEXITCODE -ne 0){throw 'Case failed; no later test will start.'}
        $completed++
    }
    Write-Output ("Completed {0} cases. Review saved captures/effects and matched model flags; completion does not mean detection succeeded." -f $completed)
} finally {
    Pop-Location
}
