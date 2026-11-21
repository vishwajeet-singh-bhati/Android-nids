param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{8,80}$')][string]$Session)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$folder=Split-Path -Parent $PSCommandPath
$contract=Get-Content -LiteralPath (Join-Path $folder 'contract.json') -Raw | ConvertFrom-Json
$phone=[string]$contract.phone;$local=[string]$contract.receiver_host
if($phone -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or $local -notmatch '^\d{1,3}(\.\d{1,3}){3}$'){throw 'Invalid private lab address contract'}
$rule='NIDS-ProtocolReceiver-'+$Session
$program=(Get-Process -Id $PID).Path
$blocks=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True | Where-Object Action -eq Block | ForEach-Object {
    $r=$_;$app=$r|Get-NetFirewallApplicationFilter;$ports=$r|Get-NetFirewallPortFilter
    if(($app.Program -eq 'Any' -or $app.Program -eq $program) -and ([string]$ports.Protocol -in @('Any','TCP','6')) -and ([string]$ports.LocalPort -in @('Any','43991'))){$r.Name}
})
if($blocks.Count){throw ('Existing receiver block needs review; no workaround or policy removal: '+($blocks -join ','))}
$listener=$null;$rows=@();$errorText=''
try {
    New-NetFirewallRule -Name $rule -DisplayName 'NIDS temporary phone-only protocol receiver' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 43991 -LocalAddress $local -RemoteAddress $phone -Program $program -Profile Any | Out-Null
    try {
        $cleanupPath=Join-Path $folder 'ReceiverCleanup.ps1'
        $cleanupArgs='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$cleanupPath+'" -Rule "'+$rule+'"'
        $action=New-ScheduledTaskAction -Execute $program -Argument $cleanupArgs
        $trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(120))
        $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
        Register-ScheduledTask -TaskName ($rule+'-cleanup') -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    } catch {Remove-NetFirewallRule -Name $rule;throw}
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse($local),43991);$listener.Start(4)
    [pscustomobject]@{state='listening';session=$Session;port=43991} | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $folder ('receiver-'+$Session+'-status.json')) -Encoding UTF8
    $until=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+90000
    while($rows.Count -lt 12 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -lt $until){
        if(-not $listener.Pending()){Start-Sleep -Milliseconds 100;continue}
        $client=$listener.AcceptTcpClient()
        try {
            if($client.Client.RemoteEndPoint.Address.ToString() -ne $phone){continue}
            $stream=$client.GetStream();$stream.ReadTimeout=2500;$stream.WriteTimeout=2500
            $command=if($rows.Count%2 -eq 0){'PING'}else{'STATUS'}
            $bytes=[Text.Encoding]::ASCII.GetBytes($command+"`n");$stream.Write($bytes,0,$bytes.Length);$stream.Flush()
            $reply=New-Object Text.StringBuilder
            for($i=0;$i -lt 32;$i++){$value=$stream.ReadByte();if($value -lt 0 -or $value -eq 10){break};[void]$reply.Append([char]$value)}
            $rows+= [pscustomobject]@{time_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();peer=$phone;peer_port=$client.Client.RemoteEndPoint.Port;command=$command;reply=$reply.ToString()}
        } finally { $client.Dispose() }
    }
} catch {$errorText=$_.Exception.Message} finally {
    if($listener){$listener.Stop()}
    $owned=Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
    if($owned){$owned | Remove-NetFirewallRule}
    $task=Get-ScheduledTask -TaskName ($rule+'-cleanup') -ErrorAction SilentlyContinue
    if($task){$task | Unregister-ScheduledTask -Confirm:$false}
    [pscustomobject]@{state='complete';session=$Session;rows=$rows;error=$errorText;owned_rule_removed=$true} | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath (Join-Path $folder ('receiver-'+$Session+'-results.json')) -Encoding UTF8
}
if($errorText){throw $errorText}
