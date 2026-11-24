"""One manually launched protocol case on the owned Pixel; no suite/scheduler.

Prepare installs an inert separate app/helpers. Only an explicit traffic profile
starts targets, sources or the restricted receiver. Existing NIDS models stay fixed.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
from http.client import HTTPConnection
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'validation'));sys.path.insert(0,str(ROOT))
import controlled_phone_test as lab
from manual_test_correlation import key,endpoint
from experiments.phone_capture_v1 import collect as raw_capture

RUN=ROOT/'runs/protocol_phone_tests'
PUBLIC=ROOT/'validation/reports/protocol_phone_tests'
HELPERS=ROOT/'validation/protocol_lab'
REMOTE='C:/ProgramData/NidsProtocolLab'
KEYS=ROOT/'runs/protocol_phone_tests'
_config=KEYS/'ssh_config.json'
_verified=json.loads(_config.read_text(encoding='utf-8')) if _config.exists() else {'hosts':[]}

PEERS=[(r['name'],r['host'],r['expected_hostname'].lower()) for r in _verified['hosts'] if r.get('identity_verified')]
SSH=Path(os.environ.get('NIDS_SSH') or shutil.which('ssh') or 'ssh')
JAVA=Path(java_path())

if os.environ.get('NIDS_ADB'):lab.ADB=Path(os.environ['NIDS_ADB'])
POWERSHELL=Path(os.environ.get('NIDS_POWERSHELL') or shutil.which('powershell.exe') or 'powershell.exe')
APK=ROOT/'android/protocollab/build/outputs/apk/debug/protocollab-debug.apk'
PROFILES=('Benign','FTPBruteForce','SSHBruteForce','BotBehavior','DoS','DDoS')
CAPTURE_PACKET_LIMIT=2000000
CAPTURE_MIN_FREE_BYTES=2*1024**3
NAMES=('Benign','Bot','Brute Force','DDoS','DoS','Port Scan','Web Attack','Unclassified')
EXPECTED={'gate':'733187848e41b5d28c58af4df0a779646c9388d8c010d0e217d9fd9ad47a2b2e','diagnosis':'e91e6fe319f459b54c657ac1964c66f2c848bbd2e0b202f07aef03377bce752e'}


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def psquote(value):return "'"+str(value).replace("'","''")+"'"


def remote_args(host,script):
    prefix="$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
    encoded=base64.b64encode((prefix+script).encode('utf-16-le')).decode()
    assert len(encoded)<7000,'Remote command exceeds conservative Windows shell budget'
    identity=next(r for r in _verified['hosts'] if r['host']==host and r.get('identity_verified'))
    login=identity['login']
    return [str(SSH),'-F','NUL','-T','-i',str(Path(_verified['identity_file']).expanduser().resolve()),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
        '-o','ConnectTimeout=7','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(Path(_verified['known_hosts_file']).expanduser().resolve()),
        '-l',login,host,'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -EncodedCommand '+encoded]


def remote(host,script,timeout=30):
    p=subprocess.run(remote_args(host,script),capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('Remote setup/client failed on '+host+': '+p.stderr[-1800:])
    return p.stdout.strip().lstrip('\ufeff')


def upload(host,name,data):
    assert name in {'LabSource.ps1','LabReceiver.ps1','ReceiverCleanup.ps1','contract.json'}
    path=REMOTE+'/'+name
    existing=remote(host,'if(Test-Path -LiteralPath '+psquote(path)+'){(Get-FileHash -Algorithm SHA256 -LiteralPath '+psquote(path)+').Hash}').lower()
    if existing==hashlib.sha256(data).hexdigest():return
    remote(host,"New-Item -ItemType Directory -Path "+psquote(REMOTE)+" -Force|Out-Null;[IO.File]::WriteAllBytes("+psquote(path)+",[byte[]]@())")
    for start in range(0,len(data),1000):
        chunk=base64.b64encode(data[start:start+1000]).decode()
        remote(host,"$b=[Convert]::FromBase64String('"+chunk+"');$s=[IO.File]::Open("+psquote(path)+",[IO.FileMode]::Append);try{$s.Write($b,0,$b.Length)}finally{$s.Dispose()}")
    actual=remote(host,"(Get-FileHash -Algorithm SHA256 -LiteralPath "+psquote(path)+").Hash").lower()
    assert actual==hashlib.sha256(data).hexdigest(),'Remote helper transfer hash mismatch'


def attest():
    lab.select_phone()
    for kind,want in EXPECTED.items():
        data=lab.adb('exec-out','run-as','nids.app','cat','files/aligned_v2_'+kind+'.pte',binary=True)
        assert hashlib.sha256(data).hexdigest()==want,'NIDS model changed; do not compare this case'
    return EXPECTED


def preparation():
    value=json.loads((RUN/'preparation.json').read_text(encoding='utf-8'))
    assert value['passed'] and sha(APK)==value['apk_sha256'],'Rebuild/re-prepare changed lab app first'
    for name,digest in value['helper_sha256'].items():assert sha(HELPERS/name)==digest,'Helper changed; prepare first'
    for name,digest in value['client_sha256'].items():assert sha(ROOT/'android/protocolcore/build/install/protocolcore/lib'/name)==digest,'Protocol client changed; prepare first'
    return value


def launch_lab(*extras):
    """Start a fresh activity after its previous process has fully exited."""
    lab.adb('shell','am','force-stop','nids.protocollab')
    for _ in range(25):
        if not lab.adb('shell','pidof','nids.protocollab',required=False).strip():break
        time.sleep(.2)
    else:raise RuntimeError('Previous protocol lab process did not stop; no target started')
    if 'validate_only' in extras:
        lab.adb('shell','run-as','nids.protocollab','rm','-f','files/platform_check.json')
    return lab.adb('shell','am','start','-W','-f','0x10008000','-n','nids.protocollab/.ProtocolActivity',*extras)


def prepare():
    assert APK.exists(),'Build the protocol lab first; see docs/protocol_phone_tests/README.md'
    assert len(PEERS)==2,'Verify exactly two owned SSH PCs before preparing this three-source lab'
    pending={'passed':False,'state':'preparing','attack_requests_sent':0,'listeners_started':0}
    lab.save(RUN/'preparation.json',pending);lab.save(PUBLIC/'preparation.json',pending)
    attest();phone,controller=lab.endpoints()
    for _,host,expected in PEERS:
        name=remote(host,'$env:COMPUTERNAME').lower();assert name==expected,'Remote host identity mismatch'
        policy=json.loads(remote(host,"[pscustomobject]@{admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);machine=[string](Get-ExecutionPolicy -Scope MachinePolicy);user=[string](Get-ExecutionPolicy -Scope UserPolicy)}|ConvertTo-Json -Compress"))
        assert policy['admin'],'Receiver setup needs the existing authorized administrator account'
        assert policy['machine'] in ('Undefined','RemoteSigned','Unrestricted') and policy['user'] in ('Undefined','RemoteSigned','Unrestricted'),'Managed script policy needs administrator review; not overridden'
        remote(host,'New-Item -ItemType Directory -Path '+psquote(REMOTE)+' -Force|Out-Null;& icacls.exe '+psquote(REMOTE)+" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null;if($LASTEXITCODE -ne 0){throw 'Lab helper folder ACL failed'}")
    contract={'phone':phone,'controller':controller,'receiver_host':PEERS[0][1],'http_port':43194,
        'allowed_sources':[controller]+[h for _,h,_ in PEERS],'max_total_load_requests':96,'max_concurrent_load_workers':6}
    local=RUN/'local_source';local.mkdir(parents=True,exist_ok=True)
    lab.save(local/'contract.json',contract)
    for name in ('LabSource.ps1','LabReceiver.ps1','ReceiverCleanup.ps1'):shutil.copy2(HELPERS/name,local/name)
    for _,host,_ in PEERS:
        for name in ('LabSource.ps1','LabReceiver.ps1','ReceiverCleanup.ps1'):upload(host,name,(HELPERS/name).read_bytes())
        upload(host,'contract.json',(local/'contract.json').read_bytes())
    assert 'Success' in lab.adb('install','-r',str(APK),timeout=150)
    lab.adb('shell','pm','grant','nids.protocollab','android.permission.POST_NOTIFICATIONS')
    launch=launch_lab('--ez','validate_only','true')
    (RUN/'platform_launch.txt').write_text(launch,encoding='utf-8')
    platform={}
    for _ in range(40):
        try:platform=json.loads(lab.adb('exec-out','run-as','nids.protocollab','cat','files/platform_check.json',required=False))
        except ValueError:pass
        if platform:break
        time.sleep(.5)
    assert platform.get('passed'),platform
    assert platform['listeners_started']==platform['network_requests_sent']==0
    attest();lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity')
    sealed=ROOT/'artifacts/releases/nids-protocollab-0.1.0.apk';shutil.copy2(APK,sealed)
    report={'passed':True,'contract':contract,'apk_sha256':sha(APK),'apk':str(sealed.relative_to(ROOT)),
        'helper_sha256':{n:sha(HELPERS/n) for n in ('LabSource.ps1','LabReceiver.ps1','ReceiverCleanup.ps1')},
        'client_sha256':{p.name:sha(p) for p in (ROOT/'android/protocolcore/build/install/protocolcore/lib').glob('*.jar')},
        'platform_check':platform,'models_unchanged':EXPECTED,'listeners_started':0,'attack_requests_sent':0,
        'scope':'Inert lab installed and helpers copied; live protocol/path/attack validation awaits explicit manual profile commands.'}
    lab.save(RUN/'preparation.json',report)
    public={**report,'contract':{'phone':'owned-Pixel','controller':'work-PC','receiver_host':'PC1',
        'http_port':43194,'allowed_sources':['work-PC','PC1','PC2'],'max_total_load_requests':96,'max_concurrent_load_workers':6}}
    lab.save(PUBLIC/'preparation.json',public)
    state('prepared',listeners_started=0,attack_requests_sent=0)
    print('SETUP_READY: app inert, both PC helpers verified, no phone attack/profile executed.',flush=True)


def state(phase,**extra):lab.save(RUN/'status.json',{'phase':phase,'updated_at_ist':datetime.now(lab.IST).isoformat(),**extra})


def health():
    h=lab.monitor_state();assert h['enabled'] and h['foreground'],'Start NIDS monitoring first; Pause is respected'
    assert h['schema']=='phone-aligned-v2'
    beat=h.get('last_heartbeat') or {}
    assert all(beat.get(k,-1)==0 for k in ('late_packets','queue_drops','evictions','history_evictions','forced_reorder','invalid_rate_flows')),beat
    return h


def capture_preflight(case):
    text=lab.adb('shell','df','-k','/data/local/tmp')
    columns=text.splitlines()[-1].split()
    assert len(columns)>=6 and columns[3].isdigit(),'Cannot verify phone capture storage'
    available=int(columns[3])*1024
    assert available>=CAPTURE_MIN_FREE_BYTES,'Raw capture requires at least 2 GiB free on the phone; no test started'
    pc_available=shutil.disk_usage(case).free
    assert pc_available>=CAPTURE_MIN_FREE_BYTES,'Raw capture requires at least 2 GiB free on the work-PC drive; no test started'
    policy={'packet_limit':CAPTURE_PACKET_LIMIT,'minimum_free_bytes':CAPTURE_MIN_FREE_BYTES,
        'available_bytes_before_capture':available,'available_pc_bytes_before_capture':pc_available,
        'maximum_pcap_bytes':24+CAPTURE_PACKET_LIMIT*(768+16),
        'snaplen':768,'interface':'any','rotating_or_overwriting':False,'full_warmup_retained':True}
    lab.save(case/'capture_policy.json',policy)
    return policy


def require_capture(capture):
    code=capture['process'].poll()
    if code is not None:
        raise RuntimeError('Raw capture stopped (exit '+str(code)+', packet budget '+str(capture['packet_limit'])+
            '). Case cannot continue; inspect capture_quality.json and capture_stderr.txt. No next profile is scheduled.')


def wait_with_capture(seconds,capture):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        require_capture(capture)
        time.sleep(min(5,max(.01,until-time.monotonic())))
    require_capture(capture)


def fresh_history(case,profile,capture):
    health();lab.adb('shell','am','force-stop','nids.app')
    (case/'previous_native_trace.jsonl').write_bytes(lab.adb('exec-out','run-as','nids.app','cat','files/tsanet_validation_trace.jsonl',binary=True,required=False))
    lab.adb('shell','run-as','nids.app','rm','-f','files/tsanet_validation_trace.jsonl')
    lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','--ez','start_monitor','true','--ez','validation_trace','true')
    deadline=time.monotonic()+45
    while True:
        require_capture(capture)
        try:h=health()
        except (AssertionError,RuntimeError):h={}
        if h.get('history_age_seconds') is not None and h['history_age_seconds']<45:break
        assert time.monotonic()<deadline,'Fresh monitor did not initialize'
        time.sleep(1)
    remaining=max(0,305-h['history_age_seconds'])
    print('Warming a fresh full 300-second history and diagnostic trace. No attack traffic yet.',flush=True)
    until=time.monotonic()+remaining
    while time.monotonic()<until:
        seconds=round(until-time.monotonic());state('warming_history',profile=profile,seconds_remaining=seconds,attack_traffic_started=False)
        print('History warm-up:',seconds,'seconds remaining',flush=True)
        wait_with_capture(min(30,max(.01,until-time.monotonic())),capture)
    health()


def target(contract,session):
    # Refuse a port conflict rather than contacting/replacing an installed phone service.
    listening=lab.adb('shell','ss','-ltn')
    for port in (43194,43195,43196):assert not re.search(r':'+str(port)+r'\b',listening),'Phone lab port already occupied'
    launch=launch_lab('--ez','start_listener','true',
        '--es','bind',contract['phone'],'--es','sources',','.join(contract['allowed_sources']),
        '--es','receiver',contract['receiver_host'],'--es','session',session)
    for _ in range(40):
        try:value=json.loads(lab.adb('exec-out','run-as','nids.protocollab','cat','files/status.json',required=False))
        except ValueError:value={}
        if value.get('session')==session:
            if value.get('state')=='failed':raise RuntimeError('Android lab start failed: '+value.get('error',''))
            if value.get('state')=='listening':
                value['activity_launch']=launch
                return value
        time.sleep(.5)
    raise RuntimeError('Unlock Pixel; protocol target did not become ready')


def http_request(phone,path):
    started=time.time();c=HTTPConnection(phone,43194,timeout=5)
    try:c.request('GET',path,headers={'Host':'nids-owned-lab'});r=c.getresponse();r.read(16384);return {'start_unix':started,'end_unix':time.time(),'path':path,'status':r.status}
    finally:c.close()


def protocol(kind,phone,mode,fingerprint,case):
    cp=str(ROOT/'android/protocolcore/build/install/protocolcore/lib/*')
    p=subprocess.run([str(JAVA),'-cp',cp,'nids.lab.ProtocolClient',kind,phone,mode,fingerprint],capture_output=True,text=True,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
    (case/(kind+'_client.log')).write_text(p.stdout+p.stderr,encoding='utf-8')
    assert p.returncode==0,kind+' protocol client failed; inspect its log'
    rows=lab.json_lines(p.stdout);assert len(rows)==(2 if mode=='control' else 32)
    assert all(r['accepted']==r['expected_success'] for r in rows),'Unexpected dummy account authentication result'
    return rows


def source_process(host,kind,count,workers,session,start_pc_ms):
    if host:
        before=time.time()*1000;clock=int(remote(host,'[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()'));after=time.time()*1000
        start=int(start_pc_ms+clock-(before+after)/2)
        script='& '+psquote(REMOTE+'/LabSource.ps1')+' -Kind '+kind+' -Count '+str(count)+' -Workers '+str(workers)+' -StartAtMs '+str(start)+' -Session '+session
        command=remote_args(host,script)
    else:
        command=[str(POWERSHELL),'-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',str(RUN/'local_source/LabSource.ps1'),
            '-Kind',kind,'-Count',str(count),'-Workers',str(workers),'-StartAtMs',str(start_pc_ms),'-Session',session]
    return subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW)


def sources(profile,contract,case,session):
    start=int(time.time()*1000)+15000
    settings=[(None,96,6)] if profile=='DoS' else [(None,32,2)]+[(host,32,2) for _,host,_ in PEERS]
    before=[http_request(contract['phone'],'/probe') for _ in range(3)];assert all(r['status']==200 for r in before)
    actors=[(host,source_process(host,'resource',count,workers,session,start)) for host,count,workers in settings]
    probes=[]
    while time.time()*1000<start:time.sleep(.1)
    try:
        with ThreadPoolExecutor(max_workers=len(actors)) as pool:
            # Drain all output concurrently: a full stdout pipe must not deadlock
            # a source while the controller waits for its exit.
            readers=[pool.submit(p.communicate,timeout=120) for _,p in actors]
            while any(not f.done() for f in readers):
                if len(probes)<64:
                    try:probes.append(http_request(contract['phone'],'/probe'))
                    except OSError as e:probes.append({'error':type(e).__name__})
                time.sleep(.25)
            results=[]
            for (host,p),reader in zip(actors,readers):
                stdout,stderr=reader.result()
                (case/('source_'+(host or 'controller')+'.log')).write_text(stdout+stderr,encoding='utf-8')
                assert p.returncode==0,'Source failed; no successful distributed test is inferred'
                r=json.loads(stdout.strip().lstrip('\ufeff'));assert all(not v['error'] for v in r['rows']);results.append(r)
    finally:
        for _,p in actors:
            if p.poll() is None:p.terminate()
    after=[http_request(contract['phone'],'/probe') for _ in range(3)];assert all(r['status']==200 for r in after)
    return {'sources':results,'baseline_probes':before,'during_probes':probes,'recovery_probes':after}


def bot(contract,case,session):
    host=contract['receiver_host'];base=REMOTE+'/receiver-'+session
    script='& '+psquote(REMOTE+'/LabReceiver.ps1')+' -Session '+session
    # Keep this SSH session alive while the receiver runs; SSH session cleanup
    # must not terminate an independently spawned receiver unexpectedly.
    with (case/'receiver_transport.log').open('w',encoding='utf-8') as log:
        process=subprocess.Popen(remote_args(host,script),stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(30):
                assert process.poll() is None,'Receiver failed; inspect receiver_transport.log and policy'
                data=remote(host,'if(Test-Path -LiteralPath '+psquote(base+'-status.json')+'){Get-Content -Raw -LiteralPath '+psquote(base+'-status.json')+'}')
                if data and json.loads(data)['session']==session:break
                time.sleep(.5)
            else:raise RuntimeError('Authorized additional-PC receiver did not start')
            trigger=http_request(contract['phone'],'/bot-start');assert trigger['status']==202
            process.wait(timeout=100)
            assert process.returncode==0,'Receiver failed; no successful behavior inferred'
            data=remote(host,'Get-Content -Raw -LiteralPath '+psquote(base+'-results.json'))
            report=json.loads(data);lab.save(case/'receiver.json',report)
            assert not report['error'] and len(report['rows'])==12,'Beacon exchanges incomplete; test is inconclusive'
            assert all(r['reply']==('PONG' if r['command']=='PING' else 'LAB-OK') for r in report['rows'])
            return report
        finally:
            if process.poll() is None:process.terminate()


def packet_tuples(path,phone,allowed):
    by_tuple=defaultdict(list)
    with path.open('rb') as f:
        h=f.read(24);endian='<' if h[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
        resolution=1e9 if h[:4] in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d') else 1e6
        link=struct.unpack_from(endian+'I',h,20)[0];assert link in (1,113,276,101)
        while True:
            r=f.read(16)
            if not r:break
            assert len(r)==16;sec,frac,size,orig=struct.unpack(endian+'IIII',r);assert size<=65536
            b=f.read(size);assert len(b)==size;off={1:14,113:16,276:20,101:0}[link]
            if len(b)<off+40 or b[off]>>4!=4 or b[off+9]!=6:continue
            tcp=off+(b[off]&15)*4
            if len(b)<tcp+20:continue
            a=str(ipaddress.ip_address(b[off+12:off+16]));d=str(ipaddress.ip_address(b[off+16:off+20]));sp,dp=struct.unpack_from('!HH',b,tcp)
            if phone not in (a,d) or (d if a==phone else a) not in allowed or not {sp,dp}.intersection({43194,43195,43196,43991}):continue
            by_tuple[key(6,(a,sp),(d,dp))].append(sec+frac/resolution)
    return by_tuple


def review(case,profile,contract,effects):
    raw=lab.adb('exec-out','run-as','nids.app','cat','files/tsanet_validation_trace.jsonl',binary=True)
    (case/'native.jsonl').write_bytes(raw);trace=lab.json_lines(raw.decode('utf-8'));assert len(trace)<2000,'Native diagnostic cap reached'
    tuples=packet_tuples(case/'capture.pcap',contract['phone'],set(contract['allowed_sources']));assert tuples,'No phone-visible test packets captured'
    rows=[r for r in trace if key(r['protocol'],(r['source'],r['sport']),(r['destination'],r['dport'])) in tuples]
    counts=Counter();maximum=0.0
    for r in rows:
        k=key(r['protocol'],(r['source'],r['sport']),(r['destination'],r['dport']));counts[k]+=int(r['flow'][1]+r['flow'][2])
        maximum=max(maximum,min(abs(r['start']-s) for s in tuples[k]));assert len(r['flow'])==32 and len(r['context'])==115
        assert all(math.isfinite(v) for v in r['flow']+r['context'])
        assert r['flagged']==(r['gate_score']>=.5408333333333333)==(r['class_id']!=0)
    assert counts==Counter({k:len(v) for k,v in tuples.items()}),'Test packet/native accounting mismatch'
    assert maximum<=1e-6,'Native segment starts do not match captured packet times'
    events=lab.json_lines(lab.adb('exec-out','run-as','nids.protocollab','cat','files/events.jsonl'))
    lab.save(case/'target_events.json',events);event_counts=Counter(r['event'] for r in events)
    if profile in ('FTPBruteForce','SSHBruteForce'):
        name='ftp' if profile.startswith('FTP') else 'ssh';assert event_counts[name+'_login_failure']==32 and event_counts[name+'_login_success']==0
    if profile in ('DoS','DDoS'):
        peers={r.get('peer') for r in events if r['event'] in ('resource_held','resource_denied')}
        assert len(peers)==(3 if profile=='DDoS' else 1),'Required independent source IPs not observed on phone'
        assert event_counts['probe_denied']>0 and event_counts['resource_denied']>0,'No measured resource availability loss; do not claim DoS effect'
        if profile=='DDoS':
            intervals=[(min(r['time_ms'] for r in events if r.get('peer')==peer and r['event'].startswith('resource_')),max(r['time_ms'] for r in events if r.get('peer')==peer and r['event'].startswith('resource_'))) for peer in peers]
            assert max(a for a,b in intervals)<min(b for a,b in intervals),'Sources did not overlap; not a distributed interval'
    if profile=='BotBehavior':assert event_counts['bot_exchange']==12 and event_counts['bot_error']==0
    if profile=='Benign':assert event_counts['ftp_login_failure']==event_counts['ssh_login_failure']==event_counts['ftp_login_success']==event_counts['ssh_login_success']==1
    health();attest()
    flags=[r for r in rows if r['flagged']]
    fingerprints=set();log_flags=[]
    earliest=min(t for times in tuples.values() for t in times)*1000-2000
    for r in lab.monitor_log():
        if r.get('event')!='model_flag' or r.get('time_ms',0)<earliest:continue
        evidence=r.get('evidence') or {};owner=evidence.get('attribution') or {};a=endpoint(owner.get('initiator'));b=endpoint(owner.get('responder'))
        if a and b and key(6,a,b) in tuples:
            log_flags.append(r);fingerprints.add(evidence.get('fingerprint'))
    assert len(log_flags)==len(flags),'Independent monitor-log/native flags disagree; preserve evidence for review'
    activity=[];notification_error=None
    try:
        db_path=lab.history_snapshot(case/'history');db=sqlite3.connect(db_path)
        try:
            assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
            activities=[json.loads(r[0]) for r in db.execute('SELECT body FROM observations')]
        finally:db.close()
        ids=set(lab.notification_ids())
        for a in activities:
            evidence=a.get('model_evidence') or {};explanation=a.get('explanation') or {}
            if evidence.get('fingerprint') in fingerprints or a.get('fingerprint') in fingerprints:
                activity.append({'type':evidence.get('suspected_pattern'),'grouped_flags':a.get('count'),
                    'visible_notification':lab.java_hash(a['id']) in ids,'explanation_status':a.get('explanation_status'),
                    'display_source':explanation.get('display_source'),'generated_text_accepted':explanation.get('generated_text_accepted')})
    except Exception as error:notification_error=repr(error)
    result={'profile':profile,'run_id':case.name,'model_sha256':EXPECTED,'source_events':dict(event_counts),
        'native_segments':len(rows),'flagged_segments':len(flags),'classification_counts':dict(Counter(NAMES[r['class_id']] for r in rows)),
        'captured_test_packets':sum(len(v) for v in tuples.values()),'unique_tcp_connections':len(tuples),
        'all_per_connection_packet_counts_exact':True,'maximum_start_timestamp_error_seconds':maximum,
        'activity_groups':activity,'visible_matched_notification_groups':sum(a['visible_notification'] for a in activity),
        'notification_snapshot_error':notification_error,'notification_scope':'Visible snapshot only; absence does not prove never posted.',
        'capture_healthy':True,'receiver_or_source_effects_verified':True,'next_test_scheduled':False,
        'scope':'One manually launched bounded development case. C2 emulator is not real malware; capacity loss is confined to the dummy service; no general class recall claim.'}
    lab.save(case/'review.json',result);lab.save(PUBLIC/(case.name+'.json'),result)
    return result


def run(profile):
    prepared=preparation();contract=prepared['contract'];attest()
    assert lab.endpoints()==(contract['phone'],contract['controller']),'Phone/PC address changed; prepare again'
    if profile == 'Benign':
        for _, host, _ in PEERS:
            try:
                with socket.create_connection((host, 22), timeout=3):
                    pass
            except OSError as error:
                raise RuntimeError(
                    'Benign control requires both remote PCs. SSH is unreachable on '
                    + host + ':22. Check that PC is awake, its current IP, sshd and firewall. '
                    'Stopped before capture and the five-minute warm-up.'
                ) from error
    installed=lab.adb('shell','pm','path','nids.protocollab').strip().removeprefix('package:')
    assert re.fullmatch(r'/data/app/[A-Za-z0-9_~+=/.-]+/base\.apk',installed),'Unexpected protocol APK location'
    installed_hash=lab.adb('shell','su','-c',"'sha256sum "+installed+"'").split()[0]
    assert installed_hash==prepared['apk_sha256'],'Installed lab app changed; prepare again'
    session=datetime.now(lab.IST).strftime('%Y%m%d_%H%M%S_')+profile+'_'+uuid.uuid4().hex[:6]
    case=RUN/'cases'/session;case.mkdir(parents=True);capture=None
    lab.save(case/'run.json',{'profile':profile,'session':session,'manual_invocation':True,'start_pc_unix':time.time(),'contract':contract,'next_test_scheduled':False})
    print('ONE MANUAL CASE:',profile,'| no following profile will start.',flush=True)
    try:
        with lab.exclusive():
            health()
            capture_preflight(case)
            capture=raw_capture.begin_capture(case,packet_limit=CAPTURE_PACKET_LIMIT)
            lab.save(case/'watched_addresses.json',raw_capture.addresses())
            fresh_history(case,profile,capture)
            require_capture(capture)
            state('starting_target',profile=profile,session=session)
            target_status=target(contract,session);lab.save(case/'target_status.json',target_status)
            print('Target ready; executing only',profile,flush=True);state('testing',profile=profile,session=session)
            if profile=='FTPBruteForce':effects={'ftp':protocol('ftp',contract['phone'],'guess',target_status['ssh_fingerprint'],case)}
            elif profile=='SSHBruteForce':effects={'ssh':protocol('ssh',contract['phone'],'guess',target_status['ssh_fingerprint'],case)}
            elif profile=='BotBehavior':effects=bot(contract,case,session)
            elif profile in ('DoS','DDoS'):effects=sources(profile,contract,case,session)
            else:
                effects={'ftp':protocol('ftp',contract['phone'],'control',target_status['ssh_fingerprint'],case),
                    'ssh':protocol('ssh',contract['phone'],'control',target_status['ssh_fingerprint'],case),
                    'controller_probes':[http_request(contract['phone'],'/probe') for _ in range(3)],'remote_probes':[]}
                for _,host,_ in PEERS:
                    proc=source_process(host,'probe',1,1,session,int(time.time()*1000)+4000);out,err=proc.communicate(timeout=30)
                    assert proc.returncode==0,err;value=json.loads(out.strip().lstrip('\ufeff'));assert value['rows'][0]['http_status']==200;effects['remote_probes'].append(value)
            lab.save(case/'effects.json',effects)
            print('Traffic finished. Observing 130 seconds for flow completion and notifications.',flush=True)
            state('observing',profile=profile,session=session);wait_with_capture(130,capture)
            item=capture;capture=None;quality=raw_capture.end_capture(item,case)
            assert not quality['ended_early'] and quality['kernel_drops']==0,quality
            lab.save(case/'capture_quality.json',quality)
            result=review(case,profile,contract,effects);state('complete',profile=profile,session=session,summary=result)
            print(json.dumps(result,indent=2),flush=True);print('Saved:',case/'review.json',flush=True)
    except BaseException as error:
        state('failed',profile=profile,session=session,error=repr(error));lab.save(case/'failure.json',{'error':repr(error),'next_test_scheduled':False});raise
    finally:
        if capture is not None:
            try:lab.save(case/'capture_quality.json',raw_capture.end_capture(capture,case))
            except Exception as error:print('Capture cleanup:',error,flush=True)
        if (case/'failure.json').exists():
            snapshots=[('nids.app','tsanet_validation_trace.jsonl','native_at_failure.jsonl')]
            target_ready=(case/'target_status.json').exists()
            if target_ready:snapshots.append(('nids.protocollab','events.jsonl','target_events_at_failure.jsonl'))
            lab.save(case/'failure_snapshot_scope.json',{'current_case_target_confirmed_ready':target_ready,
                'target_events_omitted_without_current_target':not target_ready,
                'scope':'A previous session\'s target events must not be interpreted as this failed case\'s effects.'})
            for package,filename,output in snapshots:
                try:
                    raw=lab.adb('exec-out','run-as',package,'cat','files/'+filename,binary=True,required=False)
                    if raw:(case/output).write_bytes(raw)
                except Exception as error:print('Failure evidence snapshot:',error,flush=True)
        lab.adb('shell','am','force-stop','nids.protocollab',required=False)
        if profile=='BotBehavior':
            try:remote(contract['receiver_host'],"Get-NetFirewallRule -Name "+psquote('NIDS-ProtocolReceiver-'+session)+" -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            except Exception:pass  # Independent120s cleanup watchdog remains active.
        print('Lab target stopped. NIDS stays running. No next test is scheduled.',flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--profile',choices=PROFILES+('Prepare','Status','Smoke'),required=True);parser.add_argument('--preview',action='store_true');args=parser.parse_args()
    RUN.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    if args.preview:
        print(json.dumps({'profile':args.profile,'preview_only':True,'phone_actions':0,'attack_requests_sent':0,'only_one_profile':True,
            'max_load_requests':96 if args.profile in ('DoS','DDoS') else 0,'max_load_workers':6 if args.profile in ('DoS','DDoS') else 0,
            'auth_guesses':32 if args.profile in ('FTPBruteForce','SSHBruteForce') else 0,
            'bot_exchanges':12 if args.profile=='BotBehavior' else 0,'full_history_warmup_seconds':305},indent=2));return
    if args.profile=='Prepare':
        with lab.exclusive():prepare()
    elif args.profile=='Status':
        for path in (RUN/'preparation.json',RUN/'status.json'):
            if path.exists():print(path.read_text(encoding='utf-8'))
    elif args.profile=='Smoke':
        subprocess.run([str(JAVA),'-cp',str(ROOT/'android/protocolcore/build/install/protocolcore/lib/*'),'nids.lab.ProtocolSmoke'],check=True)
    else:run(args.profile)


if __name__=='__main__':main()
