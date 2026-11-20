"""Bounded single-case lab tests, manually invoked or explicitly authorized by suite.

Destinations are derived from the explicitly selected owned test device and this PC's WLAN route.
Actual exploit targets exist only in the disposable nids.trafficlab application.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'runs/manual_phone_tests'
ADB=Path(adb_path())
IST=timezone(timedelta(hours=5,minutes=30))
ATTACKS=('PortScan','SlowScan','PasswordGuessing','SQLInjection','XSS','HTTPFlood','ConnectionExhaustion','Beacon')
SERIAL=None


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');temporary.replace(path)


def adb(*args,binary=False,required=True,timeout=35):
    command=[str(ADB)]+(['-s',SERIAL] if SERIAL else [])+list(args)
    result=subprocess.run(command,capture_output=True,timeout=timeout)
    if required and result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors='replace').strip())
    return result.stdout if binary else result.stdout.decode(errors='replace')


def select_phone():
    global SERIAL
    selected=os.environ.get('NIDS_DEVICE_SERIAL')
    if not selected:raise RuntimeError('Set NIDS_DEVICE_SERIAL explicitly for your owned test device; see docs/ANDROID_SETUP.md')
    SERIAL=None
    devices=[line.split()[0] for line in adb('devices').splitlines()[1:] if len(line.split())>=2 and line.split()[1]=='device']
    if selected not in devices:raise RuntimeError('Selected device is not connected/authorized')
    SERIAL=selected
    expected=os.environ.get('NIDS_DEVICE_CODENAME')
    if expected and adb('shell','getprop','ro.product.device').strip()!=expected:raise RuntimeError('Device codename differs from explicit configuration')


def endpoints():
    interface=adb('shell','ip','-o','-4','addr','show','wlan0')
    match=re.search(r'\binet ([0-9.]+/\d+)',interface)
    if not match:raise RuntimeError('The Pixel needs a WLAN address reachable from this PC.')
    phone_interface=ipaddress.ip_interface(match[1]);phone=str(phone_interface.ip)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
        route.connect((phone,9));controller=route.getsockname()[0]  # Route lookup; sends no datagram.
    if not phone_interface.ip.is_private or not ipaddress.ip_address(controller).is_private:
        raise RuntimeError('Only private owned-PC/Pixel endpoints are supported.')
    if ipaddress.ip_address(controller) not in phone_interface.network or controller==phone:
        raise RuntimeError('This PC must be on the same WLAN as the test Pixel.')
    return phone,controller


def json_lines(text):
    result=[]
    for line in text.splitlines():
        try:result.append(json.loads(line))
        except (ValueError,TypeError):pass
    return result


def monitor_log():
    return json_lines(adb('exec-out','run-as','nids.app','tail','-n','1500','files/tsanet_monitor.jsonl',required=False))


def monitor_state():
    import xml.etree.ElementTree as ET
    prefs=ET.fromstring(adb('exec-out','run-as','nids.app','cat','shared_prefs/background_monitor.xml'))
    enabled=any(row.attrib.get('name')=='enabled' and row.attrib.get('value')=='true' for row in prefs)
    services=adb('shell','dumpsys','activity','services','nids.app')
    rows=monitor_log();starts=[r for r in rows if r.get('event')=='session_start']
    beats=[r for r in rows if r.get('event')=='heartbeat']
    age=max(0,(time.time()*1000-starts[-1]['time_ms'])/1000) if starts else None
    if age is None and beats:
        age=beats[-1].get('uptime_ms',0)/1000+max(0,time.time()-beats[-1]['time_ms']/1000)
    return {'enabled':enabled,'foreground':'.TsanetCaptureService' in services and 'isForeground=true' in services,
            'history_age_seconds':age,'last_heartbeat':beats[-1] if beats else None,
            'schema':starts[-1].get('schema','tsanet_phone_v1') if starts else (beats[-1].get('schema','tsanet_phone_v1') if beats else 'unknown'),
            'longest_history_seconds':300 if ((starts[-1].get('schema') if starts else (beats[-1].get('schema') if beats else None))=='phone-aligned-v2') else 900,
            'model_sha256':starts[-1].get('model_sha256') if starts else None,
            'diagnosis_model_sha256':starts[-1].get('diagnosis_model_sha256') if starts else None}


def history_snapshot(directory):
    directory.mkdir(parents=True,exist_ok=True)
    for name in ('activity_history_v1.db','activity_history_v1.db-wal'):
        data=adb('exec-out','run-as','nids.app','cat','files/'+name,binary=True,required=False)
        if data:(directory/name).write_bytes(data)
    path=directory/'activity_history_v1.db'
    if not path.exists():raise RuntimeError('NIDS activity database is unavailable.')
    return path


def notification_ids():
    text=adb('shell','dumpsys','notification','--noredact')
    return sorted({int(m.group(1)) for line in text.splitlines()
        if 'NotificationRecord(' in line and re.search(r'\bpkg=nids\.app\b',line)
        for m in [re.search(r'\bid=(-?\d+)',line)] if m and int(m.group(1))!=2})


def java_hash(value):
    number=0
    for letter in value:number=(31*number+ord(letter))&0xffffffff
    return number if number<0x80000000 else number-0x100000000


def capture_summary(path,phone,controller):
    """Summarize packet delivery, not model decisions or exact collector segmentation."""
    with path.open('rb') as stream:
        header=stream.read(24)
        if len(header)!=24:raise RuntimeError('Passive capture has no PCAP header.')
        magic=header[:4]
        if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'):endian='<'
        elif magic in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):endian='>'
        else:raise RuntimeError('Unsupported PCAP format.')
        link=struct.unpack(endian+'I',header[20:24])[0]
        counts={'captured_records':0,'pc_to_phone_syn_packets':0,'phone_to_pc_rst_packets':0,
                'phone_to_pc_tcp_packets':0,'pc_to_phone_tcp_packets':0,'unsupported_records':0}
        ports=set();tuples={}
        while True:
            record=stream.read(16)
            if not record:break
            if len(record)!=16:raise RuntimeError('Truncated PCAP record header.')
            _,_,length,_=struct.unpack(endian+'IIII',record)
            if length>65536:raise RuntimeError('Invalid PCAP record length.')
            frame=stream.read(length)
            if len(frame)!=length:raise RuntimeError('Truncated PCAP packet.')
            counts['captured_records']+=1
            offset={1:14,113:16,276:20,101:0}.get(link)
            if offset is None or len(frame)<offset+40 or frame[offset]>>4!=4:
                counts['unsupported_records']+=1;continue
            ihl=(frame[offset]&15)*4;tcp=offset+ihl
            if ihl<20 or frame[offset+9]!=6 or len(frame)<tcp+20:continue
            source=socket.inet_ntoa(frame[offset+12:offset+16]);destination=socket.inet_ntoa(frame[offset+16:offset+20])
            sport,dport=struct.unpack('!HH',frame[tcp:tcp+4]);flags=frame[tcp+13]
            if source==controller and destination==phone:
                counts['pc_to_phone_tcp_packets']+=1
                if flags&2 and not flags&16:counts['pc_to_phone_syn_packets']+=1;ports.add(dport)
            elif source==phone and destination==controller:
                counts['phone_to_pc_tcp_packets']+=1
                if flags&4:counts['phone_to_pc_rst_packets']+=1
            else:continue
            key=tuple(sorted(((source,sport),(destination,dport))))
            tuples[key]=tuples.get(key,0)+1
    return dict(counts,linktype=link,syn_target_ports=sorted(ports),tcp_tuples=len(tuples),
                single_packet_tuples=sum(n==1 for n in tuples.values()),
                scope='Packet evidence only. TCP tuples are not exact NIDS flow segments. No classifier decisions inferred.')


def begin_capture(directory,controller):
    pidfile='/data/local/tmp/nids_manual_capture_'+str(time.time_ns())+'.pid'
    remote_error=pidfile+'.stderr'
    bpf=f'tcp and host {controller} and (port 43190 or portrange 43200-43500 or port 43990)'
    command=f'echo $$ > {pidfile}; exec /data/local/tmp/tcpdump -i wlan0 -U -s 96 -c 20000 -w - "{bpf}" 2>{remote_error}'
    output=(directory/'traffic.pcap').open('wb');errors=(directory/'capture_stderr.txt').open('wb')
    # exec-out preserves the argument boundary; shell-style outer quotes would become literal.
    process=subprocess.Popen([str(ADB),'-s',SERIAL,'exec-out','su','-c',command],stdout=output,stderr=errors)
    try:
        time.sleep(.5)
        if process.poll() is not None:raise RuntimeError('Passive packet capture failed; no attack was started. Read capture_stderr.txt.')
        pid=adb('shell','su','-c',"'cat "+pidfile+"'").strip()
        if not pid.isdigit():raise RuntimeError('Passive capture did not publish a valid PID.')
        return {'process':process,'output':output,'errors':errors,'pid':pid,'pidfile':pidfile,'remote_error':remote_error,'controller':controller}
    except BaseException:
        try:
            value=adb('shell','su','-c',"'cat "+pidfile+"'",required=False).strip()
            if value.isdigit():
                running=adb('shell','su','-c',f"'cat /proc/{value}/cmdline'",required=False).replace('\x00',' ')
                if '/data/local/tmp/tcpdump' in running and '-i wlan0' in running and controller in running:
                    adb('shell','su','-c',f"'kill -INT {value}'",required=False)
            (directory/'capture_tcpdump_stderr.txt').write_text(adb('shell','su','-c',"'cat "+remote_error+"'",required=False))
            adb('shell','su','-c',"'rm -f "+pidfile+' '+remote_error+"'",required=False)
        finally:
            if process.poll() is None:process.terminate()
            process.wait(timeout=5);output.close();errors.close()
        raise


def end_capture(capture,directory,phone):
    process=capture['process'];pid=capture['pid']
    try:
        command=adb('shell','su','-c',f"'cat /proc/{pid}/cmdline'",required=False).replace('\x00',' ')
        # Stop only this uniquely identified auxiliary capture, never the NIDS capture.
        if '/data/local/tmp/tcpdump' in command and '-i wlan0' in command and capture['controller'] in command:
            adb('shell','su','-c',f"'kill -INT {pid}'",required=False)
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
    finally:
        capture['output'].close();capture['errors'].close()
        (directory/'capture_tcpdump_stderr.txt').write_text(adb('shell','su','-c',"'cat "+capture['remote_error']+"'",required=False))
        adb('shell','su','-c',"'rm -f "+capture['pidfile']+' '+capture['remote_error']+"'",required=False)
    result=capture_summary(directory/'traffic.pcap',phone,capture['controller'])
    result['sha256']=hashlib.sha256((directory/'traffic.pcap').read_bytes()).hexdigest()
    save(directory/'packet_evidence.json',result)
    return result


@contextmanager
def exclusive():
    with exclusive_file_lock(RUN/'manual_test.lock'):
        yield


def request(phone,port,path=None):
    row={'start_unix':time.time(),'port':port,'connected':False}
    try:
        with socket.create_connection((phone,port),timeout=2) as stream:
            row['connected']=True
            if path is not None:
                stream.settimeout(8)
                stream.sendall(('GET '+path+' HTTP/1.1\r\nHost: nids-owned-test\r\nConnection: close\r\n\r\n').encode())
                chunks=[];size=0
                while size<16384:
                    part=stream.recv(2048)
                    if not part:break
                    chunks.append(part);size+=len(part)
                text=b''.join(chunks).decode(errors='replace');pieces=text.split('\r\n\r\n',1)
                row['http_status']=int(text.split(' ',2)[1]) if text.startswith('HTTP/') else None
                row['body']=pieces[-1][:4000]
    except OSError as error:row['socket_error']=type(error).__name__
    row['end_unix']=time.time();return row


def jobs(phone,specifications,workers,interval):
    if not 1<=workers<=8 or len(specifications)>256 or interval<.02:raise ValueError('Test exceeds its fixed budget.')
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures=[]
        for port,path in specifications:
            futures.append(pool.submit(request,phone,port,path));time.sleep(interval)
        return [future.result() for future in futures]


def start_target(controller):
    adb('shell','am','force-stop','nids.trafficlab')
    began=time.time()
    adb('shell','am','start','-n','nids.trafficlab/.LabActivity','--es','controller',controller,'--ez','start_listener','true')
    for _ in range(20):
        text=adb('exec-out','run-as','nids.trafficlab','cat','files/lab_status.json',required=False)
        try:status=json.loads(text)
        except ValueError:status={}
        if status.get('state')=='listening' and status.get('controller')==controller and status.get('expires_ms',0)>began*1000+800000:
            if status.get('version')!='0.2.0':raise RuntimeError('Install Traffic Lab 0.2.0; old mock listener is not an attack target.')
            adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity');return
        time.sleep(.25)
    raise RuntimeError('Isolated test target did not start. Unlock the Pixel and try again.')


def scan_ports(count):
    # Never scan a different installed service. Include only our lab and verified closed ports.
    text=adb('shell','ss','-ltn')
    listening={int(n) for n in re.findall(r':(\d+)\b',text)}
    closed=[port for port in range(43200,43500) if port not in listening]
    if len(closed)<count:raise RuntimeError('Insufficient verified closed ports for this fixed scan.')
    return [43190]+closed[:count]


def beacon_case(phone,controller):
    results=[]
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind((controller,43990));server.listen(4);server.settimeout(4)
        trigger=request(phone,43190,'/beacon-start');until=time.monotonic()+48
        while len(results)<12 and time.monotonic()<until:
            try:client,address=server.accept()
            except socket.timeout:continue
            with client:
                if address[0]!=phone:continue
                client.settimeout(2);client.sendall(b'PING\n')
                results.append({'time_unix':time.time(),'peer':address[0],'response':client.recv(32).decode(errors='replace').strip()})
    return [trigger],results


def collect(directory,meta):
    start=meta['start_unix'];rows=monitor_log()
    flags=[r for r in rows if r.get('event')=='model_flag' and r.get('time_ms',0)>=start*1000]
    associated=[]
    for row in flags:
        evidence=row.get('evidence',{})
        # Full evidence is retained privately. Attribution is a best-effort observation, not proof of origin.
        associated.append({'time_ms':row.get('time_ms'),'class':evidence.get('suspected_pattern'),
                           'attribution':evidence.get('attribution'),'flow_packets':evidence.get('flow_packets'),
                           'fingerprint':evidence.get('fingerprint'),'gate_score':evidence.get('gate_score')})
    from manual_test_correlation import correlate
    correlation=correlate(associated,meta,directory/'traffic.pcap')
    associated=correlation['flags']
    activities=[];read_error=None
    try:
        path=history_snapshot(directory/('history_'+str(time.time_ns())))
        with closing(sqlite3.connect(path)) as db:
            if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('Activity snapshot was not consistent; run Check again.')
            activities=[json.loads(row[0]) for row in db.execute('SELECT body FROM observations WHERE time_ms>=? ORDER BY time_ms',(int(start*1000),))]
    except (sqlite3.Error,RuntimeError) as error:read_error=str(error)
    live_ids=notification_ids()
    observed_ids=[r.get('id','') for r in activities]
    target_text=adb('exec-out','run-as','nids.trafficlab','cat','files/lab_events.jsonl',required=False)
    events=[r for r in json_lines(target_text) if r.get('time_ms',0)>=start*1000]
    counts={kind:sum(r['event']==kind for r in events) for kind in sorted({r['event'] for r in events})}
    attempts=meta.get('attempts',[])
    summary={'attempts':len(attempts),'connected':sum(r.get('connected',False) for r in attempts),
             'timeouts':sum(r.get('socket_error')=='TimeoutError' for r in attempts),
             'open_ports':sorted({r['port'] for r in attempts if r.get('connected')})}
    packet_path=directory/'packet_evidence.json'
    packet_evidence=json.loads(packet_path.read_text()) if packet_path.exists() else None
    report={'profile':meta['profile'],'start_unix':start,'checked_at_ist':datetime.now(IST).isoformat(),
            'traffic_summary':summary,'packet_evidence':packet_evidence,
            'nids_model_flags_during_window':len(flags),'model_flags':associated,'new_or_updated_activity_rows':len(activities),
            'traffic_correlation':{k:v for k,v in correlation.items() if k!='flags'},
            'activities':activities,'activity_read_error':read_error,'target_event_counts':counts,
            'currently_visible_alerts_for_activity_rows':sum(java_hash(v) in live_ids for v in observed_ids),
            'monitor':monitor_state(),
            'scope':'Flags/rows are from the time window and may include unrelated background traffic. Visible notification absence does not prove one was never posted. History carries over. No fabricated alerts.'}
    save(directory/'check.json',report);save(directory/'target_events.json',events)
    from manual_test_log import update_log
    ledger=update_log()
    print('Traffic outcomes:',json.dumps(summary),flush=True)
    if packet_evidence:print('Packet evidence:',json.dumps(packet_evidence),flush=True)
    print('Target application events:',json.dumps(counts),flush=True)
    if meta['profile'] in ('PortScan','SlowScan'):print('A TCP-only scan need not create HTTP events.',flush=True)
    print('NIDS model flags in test window:',len(flags),'| New/updated activities:',len(activities),flush=True)
    print('Flag correlation:',json.dumps(correlation['counts']),'(matched traffic is not automatically a confirmed attack)',flush=True)
    print('Currently visible NIDS alerts for those activities:',report['currently_visible_alerts_for_activity_rows'],flush=True)
    if read_error:print('Activity snapshot incomplete:',read_error,flush=True)
    print('Monitor running:',report['monitor']['foreground'],flush=True)
    print('Saved:',directory/'check.json',flush=True)
    print('Combined log:',ledger,flush=True)
    return report


def run_case(name,observe,login_interval=.2,*,suite_id=None):
    select_phone();phone,controller=endpoints();state=monitor_state()
    if not state['enabled'] or not state['foreground']:raise RuntimeError('Tap Start monitoring in NIDS first. This command does not override Pause.')
    age=state['history_age_seconds']
    required_history=state['longest_history_seconds']
    if age is None or age<required_history:
        raise RuntimeError(f'Connection history is not ready ({round(age or 0)}/{required_history} seconds). Leave NIDS running, then invoke this command manually. No attack started.')
    print('Single automated test:' if suite_id else 'Single manual test:',name,'| Pixel:',phone,'| PC:',controller,flush=True)
    print('Connection-history age:',round(age or 0),'seconds (full longest window:',required_history,'seconds).',flush=True)
    try:start_target(controller)
    except BaseException:
        adb('shell','am','force-stop','nids.trafficlab',required=False);raise
    directory=RUN/(datetime.now(IST).strftime('%Y%m%d_%H%M%S_')+name);directory.mkdir(parents=True)
    meta={'profile':name,'start_unix':time.time(),'phone':phone,'controller':controller,'history_age_at_start':age,
          'manual_invocation':suite_id is None,'invocation_mode':'manual' if suite_id is None else 'user_authorized_automated_suite',
          'suite_id':suite_id,'next_test_scheduled':False,'detector_unchanged':True,
          'detector_schema':state['schema'],'gate_model_sha256':state['model_sha256'],
          'diagnosis_model_sha256':state['diagnosis_model_sha256'],'history_window_seconds':required_history}
    if name=='PasswordGuessing':
        meta['login_interval_seconds']=login_interval
        meta['profile_variant']='original_fast' if login_interval==.2 else 'spacing_'+str(login_interval)+'s'
        print('Login launch interval:',login_interval,'seconds; same 32 dummy-account guesses.',flush=True)
    save(directory/'run.json',meta);save(RUN/'latest.json',{'directory':str(directory)})
    results=[];beacons=[];capture=None
    try:
        capture=begin_capture(directory,controller)
        if name in ('PortScan','SlowScan'):
            ports=scan_ports(128 if name=='PortScan' else 31)
            results=jobs(phone,[(p,None) for p in ports],4 if name=='PortScan' else 1,.05 if name=='PortScan' else 1)
        elif name=='PasswordGuessing':
            paths=['/login?user=nids-lab-user&password='+quote('nids-lab-'+str(i)) for i in range(32)]
            results=jobs(phone,[(43190,p) for p in paths],2,login_interval)
        elif name=='SQLInjection':
            inputs=['missing-record',"missing' OR 1=1 --", "missing' UNION SELECT 'NIDS_SQLI_PROOF' --"]
            results=jobs(phone,[(43190,'/search?q='+quote(v,safe='')) for v in inputs],1,1)
        elif name=='XSS':
            payload='<script>LabProof.mark("NIDS_XSS_PROOF")</script>'
            results=jobs(phone,[(43190,'/xss?q='+quote(payload,safe=''))],1,1)
        elif name=='HTTPFlood':results=jobs(phone,[(43190,'/http-load')]*128,8,.02)
        elif name=='ConnectionExhaustion':results=jobs(phone,[(43190,'/hold')]*16,8,.1)
        elif name=='Beacon':results,beacons=beacon_case(phone,controller)
        elif name=='Benign':results=jobs(phone,[(43190,'/normal')]*8,1,1)
        meta.update({'traffic_end_unix':time.time(),'attempts':results,'beacon_responses':beacons,'traffic_completed':True})
        save(directory/'run.json',meta)
        print('Traffic complete. Connections:',sum(r['connected'] for r in results),'/',len(results),flush=True)
        if name in ('PortScan','SlowScan'):print('Open ports found:',[r['port'] for r in results if r['connected']],flush=True)
        print('HTTP statuses:',{s:sum(r.get('http_status')==s for r in results) for s in sorted({r.get('http_status') for r in results if r.get('http_status') is not None})},flush=True)
        wait=max(observe,130) if name in ('PortScan','SlowScan') else observe
        meta['observation_seconds']=wait;save(directory/'run.json',meta)
        print('Observing this test for',wait,'seconds;',
              'suite will enforce context isolation before the next case.' if suite_id else 'check the phone. No next test will start.',flush=True)
        time.sleep(wait)
        finished_capture=capture;capture=None;end_capture(finished_capture,directory,phone)
        collect(directory,meta)
    except BaseException as error:
        meta.update({'error':str(error),'interrupted_or_failed':True,'attempts':results,'beacon_responses':beacons})
        save(directory/'run.json',meta);raise
    finally:
        if capture is not None:
            try:end_capture(capture,directory,phone)
            except Exception as error:print('Passive capture cleanup:',error,flush=True)
        adb('shell','am','force-stop','nids.trafficlab',required=False)
        print('Isolated target stopped. NIDS and its new activity remain available for review.',flush=True)


def clean_activity():
    select_phone()
    stamp=datetime.now(IST).strftime('%Y%m%d_%H%M%S')
    backup=ROOT/'validation/private'/('before_manual_tests_'+stamp);backup.mkdir(parents=True)
    adb('shell','am','force-stop','nids.app')
    adb('shell','am','force-stop','nids.trafficlab')
    names=adb('exec-out','run-as','nids.app','ls','-1','files').splitlines()
    pattern=re.compile(r'(?:activity_history_v1\.db(?:-wal|-shm)?|alerts\.jsonl|evidence_packs\.jsonl|sessions\.jsonl|observations_v1\.json|feedback_v1\.jsonl|last_local_explanation\.json|learned_network\.jsonl(?:\.1)?|resources(?:_llama)?_v1\.jsonl(?:\.1)?|tsanet_monitor\.jsonl(?:\.1)?|tsanet_validation_trace\.jsonl|(?:behavior_score|learned_score)_\d+\.jsonl|learned_packets_\d+\.tsv)')
    chosen=[n for n in names if pattern.fullmatch(n)]
    hashes={}
    for name in chosen:
        data=adb('exec-out','run-as','nids.app','cat','files/'+name,binary=True)
        (backup/name).write_bytes(data);hashes[name]=hashlib.sha256(data).hexdigest()
    if 'activity_history_v1.db' not in chosen:raise RuntimeError('No backed-up history database. Nothing cleared.')
    active_models=[n for n in ('aligned_v2_gate.pte','aligned_v2_diagnosis.pte') if n in names]
    if not active_models:active_models=['tsanet_context_v1.pte']
    model_before={n:hashlib.sha256(adb('exec-out','run-as','nids.app','cat','files/'+n,binary=True)).hexdigest() for n in active_models}
    work=backup/'working';work.mkdir()
    for name in ('activity_history_v1.db','activity_history_v1.db-wal'):
        if (backup/name).exists():shutil.copy2(backup/name,work/name)
    clean=backup/'empty_history.db'
    with closing(sqlite3.connect(work/'activity_history_v1.db')) as original,closing(sqlite3.connect(clean)) as destination:
        counts={table:original.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('observations','feedback')}
        original.backup(destination)
        destination.execute('DELETE FROM observations');destination.execute('DELETE FROM feedback');destination.commit()
        destination.execute('PRAGMA journal_mode=DELETE');destination.execute('VACUUM')
        if destination.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('Empty history validation failed.')
    save(backup/'backup_manifest.json',{'before_counts':counts,'sha256':hashes,'model_sha256':model_before,'backup_complete_before_clear':True})
    temporary='/data/local/tmp/nids_empty_history_'+stamp+'.db'
    adb('push',str(clean),temporary)
    try:
        # Exact backed-up files only. Model/cache directories and migration marker are untouched.
        for name in chosen:
            if name!='activity_history_v1.db':adb('shell','run-as','nids.app','rm','-f','files/'+name)
        adb('shell','run-as','nids.app','cp',temporary,'files/activity_history_v1.db')
        if hashlib.sha256(adb('exec-out','run-as','nids.app','cat','files/activity_history_v1.db',binary=True)).digest()!=hashlib.sha256(clean.read_bytes()).digest():
            raise RuntimeError('Phone history replacement did not verify. Use the retained backup.')
    finally:adb('shell','rm','-f',temporary,required=False)
    model_after={n:hashlib.sha256(adb('exec-out','run-as','nids.app','cat','files/'+n,binary=True)).hexdigest() for n in active_models}
    if model_after!=model_before:raise RuntimeError('Detector hash changed unexpectedly.')
    adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','--ez','start_monitor','true')
    time.sleep(3)
    state=monitor_state()
    if not state['foreground']:raise RuntimeError('History cleared; normal monitor did not start. Open NIDS and tap Start monitoring.')
    with tempfile.TemporaryDirectory(dir=RUN) as scratch:
        path=history_snapshot(Path(scratch))
        with closing(sqlite3.connect(path)) as db:after={table:db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in counts}
    report={'cleared_at_ist':datetime.now(IST).isoformat(),'backup_directory':str(backup.relative_to(ROOT)),
            'before_counts':counts,'after_counts':after,'old_log_files_backed_up':len(chosen),'models_preserved':True,
            'model_sha256':model_after,'monitor_running':state['foreground'],'active_old_alert_ids':notification_ids(),
            'test_attacks_run':0,'scheduled_attacks':0}
    save(ROOT/'validation/reports/manual_phone_tests/preparation.json',report)
    print(json.dumps(report,indent=2),flush=True)


def smoke():
    # Loopback-only harness check. Does not select a phone, start a target, or run an attack profile.
    from manual_test_correlation import smoke as correlation_smoke
    assert correlation_smoke()['passed']
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'{"smoke":true}';self.send_response(200);self.send_header('Content-Length',str(len(body)))
            self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        row=request('127.0.0.1',server.server_port,'/health')
        assert row['connected'] and row['http_status']==200 and json.loads(row['body'])['smoke']
        assert java_hash('abc')==96354
        assert len(ATTACKS)==8 and len(set(ATTACKS))==8
        # Windows regression: connection context managers do not close SQLite handles.
        with tempfile.TemporaryDirectory(dir=RUN) as scratch:
            with closing(sqlite3.connect(Path(scratch)/'history.db')) as db:
                db.execute('CREATE TABLE observations(id TEXT)');db.commit()
                assert db.execute('SELECT count(*) FROM observations').fetchone()[0]==0
            pcap=Path(scratch)/'fixture.pcap'
            data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,96,1)
            for reverse,flags in ((False,2),(True,20)):
                ip=bytearray(20);ip[0]=0x45;ip[9]=6
                ip[12:16]=socket.inet_aton('10.0.0.2' if reverse else '10.0.0.1')
                ip[16:20]=socket.inet_aton('10.0.0.1' if reverse else '10.0.0.2')
                tcp=bytearray(20);tcp[:4]=struct.pack('!HH',43200 if reverse else 50000,50000 if reverse else 43200);tcp[13]=flags
                frame=bytes(14)+ip+tcp;data+=struct.pack('<IIII',1,0,len(frame),len(frame))+frame
            pcap.write_bytes(data);result=capture_summary(pcap,'10.0.0.2','10.0.0.1')
            assert result['pc_to_phone_syn_packets']==1 and result['phone_to_pc_rst_packets']==1 and result['tcp_tuples']==1
        try:jobs('127.0.0.1',[(1,None)]*257,1,.1)
        except ValueError:pass
        else:raise AssertionError('Budget guard did not reject excess requests')
        with exclusive():
            try:
                with exclusive():raise AssertionError('Concurrent manual run allowed')
            except RuntimeError:pass
        value={'passed':True,'loopback_http_passed':True,'budget_guard_passed':True,'single_run_lock_passed':True,
               'traffic_correlation_smoke_passed':True,
               'windows_sqlite_handle_check_passed':True,'passive_capture_parser_passed':True,
               'phone_attack_profiles_run':0,'scheduled_attacks':0,'checked_at_ist':datetime.now(IST).isoformat()}
        save(ROOT/'validation/reports/manual_phone_tests/harness_smoke.json',value)
        print(json.dumps(value,indent=2),flush=True)
    finally:server.shutdown();server.server_close();thread.join(2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True,choices=ATTACKS+('Benign','Status','Check','Smoke','Clean'))
    parser.add_argument('--observe-seconds',type=int,default=130)
    parser.add_argument('--login-interval-seconds',type=float,default=.2)
    parser.add_argument('--preview',action='store_true',help='Print the plan only; no ADB or traffic.')
    args=parser.parse_args()
    if not 10<=args.observe_seconds<=180:parser.error('Observe seconds must be between 10 and 180.')
    if not .2<=args.login_interval_seconds<=10:parser.error('Login interval must be between 0.2 and 10 seconds.')
    if args.profile!='PasswordGuessing' and args.login_interval_seconds!=.2:parser.error('Login interval applies only to PasswordGuessing.')
    if args.preview:
        if args.profile not in ATTACKS+('Benign',):parser.error('Preview supports traffic cases only.')
        print(json.dumps({'preview_only':True,'profile':args.profile,'observe_seconds':args.observe_seconds,
            'login_guesses':32 if args.profile=='PasswordGuessing' else None,
            'login_interval_seconds':args.login_interval_seconds if args.profile=='PasswordGuessing' else None,
            'phone_accessed':False,'attack_requests_sent':0,'next_test_scheduled':False},indent=2));return
    RUN.mkdir(parents=True,exist_ok=True)
    if args.profile=='Smoke':smoke();return
    with exclusive():
        if args.profile=='Clean':clean_activity()
        elif args.profile=='Status':select_phone();print(json.dumps(monitor_state(),indent=2))
        elif args.profile=='Check':
            if not (RUN/'latest.json').exists():raise RuntimeError('No manual attack test has run yet. Check becomes available after your first test.')
            select_phone();latest=json.loads((RUN/'latest.json').read_text());directory=Path(latest['directory']).resolve()
            if not directory.is_relative_to(RUN.resolve()):raise RuntimeError('Invalid saved run directory.')
            collect(directory,json.loads((directory/'run.json').read_text()))
        else:run_case(args.profile,args.observe_seconds,args.login_interval_seconds)


if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError,subprocess.SubprocessError) as error:
        print('STOPPED:',error,flush=True);raise SystemExit(1)
