param(
    [Parameter(Mandatory=$true)][ValidateSet('probe','resource')][string]$Kind,
    [ValidateRange(1,96)][int]$Count=32,
    [ValidateRange(1,6)][int]$Workers=2,
    [Parameter(Mandatory=$true)][long]$StartAtMs,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]{8,80}$')][string]$Session
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$labFolder=Split-Path -Parent $PSCommandPath
$contract=Get-Content -LiteralPath (Join-Path $labFolder 'contract.json') -Raw | ConvertFrom-Json
$phone=[string]$contract.phone
if($phone -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or $contract.http_port -ne 43194){throw 'Invalid owned-phone contract'}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
if($StartAtMs -gt $now+60000 -or $StartAtMs -lt $now-10000){throw 'Start time outside bounded schedule'}
$jobs=@()
try {
    for($worker=0;$worker -lt $Workers;$worker++) {
        $jobs+=Start-Job -ArgumentList $phone,$Kind,$Count,$Workers,$worker,$StartAtMs -ScriptBlock {
            param($Phone,$Kind,$Count,$Workers,$Worker,$StartAtMs)
            $ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
            while([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -lt $StartAtMs){Start-Sleep -Milliseconds 25}
            for($index=$Worker;$index -lt $Count;$index+=$Workers) {
                $began=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                $socket=New-Object Net.Sockets.TcpClient
                $code=$null;$failure='';$source='';$sourcePort=0
                try {
                    $pending=$socket.BeginConnect($Phone,43194,$null,$null)
                    if(-not $pending.AsyncWaitHandle.WaitOne(2500)){throw 'Connection timeout'}
                    $socket.EndConnect($pending)
                    $source=$socket.Client.LocalEndPoint.Address.ToString();$sourcePort=$socket.Client.LocalEndPoint.Port
                    $stream=$socket.GetStream();$stream.ReadTimeout=5000;$stream.WriteTimeout=2500
                    $payload=[Text.Encoding]::ASCII.GetBytes("GET /$Kind HTTP/1.1`r`nHost: nids-owned-lab`r`nConnection: close`r`n`r`n")
                    $stream.Write($payload,0,$payload.Length);$stream.Flush()
                    $buffer=New-Object byte[] 2048;$text=New-Object IO.MemoryStream
                    while($text.Length -lt 16384){$n=$stream.Read($buffer,0,$buffer.Length);if($n -eq 0){break};$text.Write($buffer,0,$n)}
                    $response=[Text.Encoding]::ASCII.GetString($text.ToArray());$text.Dispose()
                    if($response -notmatch '^HTTP/1\.1 (\d{3}) '){throw 'Invalid lab response'}
                    $code=[int]$Matches[1]
                } catch { $failure=$_.Exception.GetType().Name+': '+$_.Exception.Message } finally { $socket.Dispose() }
                [pscustomobject]@{index=$index;source=$source;sport=$sourcePort;destination=$Phone;dport=43194;http_status=$code;error=$failure;start_ms=$began;end_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()}
                Start-Sleep -Milliseconds 100
            }
        }
    }
    $done=$jobs | Wait-Job -Timeout 100
    if(@($done).Count -ne $jobs.Count){throw 'Bounded source job timed out'}
    if(@($jobs | Where-Object State -ne 'Completed').Count){throw 'Source worker failed'}
    $rows=@($jobs | Receive-Job | Select-Object index,source,sport,destination,dport,http_status,error,start_ms,end_ms | Sort-Object index)
    if($rows.Count -ne $Count){throw 'Source request count mismatch'}
    $result=[pscustomobject]@{session=$Session;hostname=$env:COMPUTERNAME;kind=$Kind;count=$Count;workers=$Workers;rows=$rows}
    $result | ConvertTo-Json -Depth 5 -Compress
} finally {
    $jobs | Stop-Job -ErrorAction SilentlyContinue
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
}
