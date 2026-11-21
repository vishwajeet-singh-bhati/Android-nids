param([Parameter(Mandatory=$true)][ValidatePattern('^NIDS-ProtocolReceiver-[A-Za-z0-9_-]{8,80}$')][string]$Rule)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$owned=Get-NetFirewallRule -Name $Rule -ErrorAction SilentlyContinue
if($owned){$owned | Remove-NetFirewallRule}
$task=Get-ScheduledTask -TaskName ($Rule+'-cleanup') -ErrorAction SilentlyContinue
if($task){$task | Unregister-ScheduledTask -Confirm:$false}
