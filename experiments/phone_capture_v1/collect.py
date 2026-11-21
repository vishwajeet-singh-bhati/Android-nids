"""Bounded real-phone recording with out-of-band request and target ground truth."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'));sys.path.insert(0,str(ROOT))
import controlled_phone_test as lab
import run_v2_remaining_suite as fixed

RUN=ROOT/'runs/phone_capture_v1'
PUBLIC=ROOT/'validation/reports/phone_capture_v1'
JAVA=Path(java_path())
BUNDLE=ROOT/'runs/phone_alignment_v2/extractor'
TOOLS=ROOT/'android/datasettools/build/libs/datasettools.jar'
APK=ROOT/'android/datasetlab/build/outputs/apk/debug/datasetlab-debug.apk'
WARM_SECONDS=340  # 300s context +30s maximum flow segment +margin.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_state(session,phase,**extra):
    lab.save(RUN/'status.json',{'session':session,'phase':phase,'updated_at_ist':datetime.now(lab.IST).isoformat(),**extra})


def cancelled():
    if (RUN/'STOP').exists():raise RuntimeError('Collection STOP marker present')


def pause(seconds,session,phase):
    until=time.monotonic()+max(0,seconds)
    while time.monotonic()<until:
        cancelled();write_state(session,phase,remaining_seconds=round(until-time.monotonic()))
        time.sleep(min(10,max(.05,until-time.monotonic())))


def addresses():
    text=lab.adb('shell','ip','-o','addr','show');out=set()
    for value in re.findall(r'\binet6? ([0-9a-fA-F:.]+)(?:/|%)',text):
        a=ipaddress.ip_address(value)
        out.add(str(a) if a.version==4 else ':'.join(v.lstrip('0') or '0' for v in a.exploded.split(':')))
    assert out;return sorted(out)


def begin_capture(case,*,packet_limit=100000):
    if type(packet_limit) is not int or not 1<=packet_limit<=2000000:
        raise ValueError('Raw capture packet limit must be an integer between 1 and 2000000')
    token=case.name
    assert re.fullmatch('[a-zA-Z0-9_-]{8,80}',token)
    remote='/data/local/tmp/nids_dataset_'+token
    command=f'echo $$ > {remote}.pid; exec /data/local/tmp/tcpdump --immediate-mode -i any -U -s 768 -c {packet_limit} -w {remote}.pcap 2>{remote}.stderr'
    output=(case/'capture_transport.txt').open('wb')
    process=subprocess.Popen([str(lab.ADB),'-s',lab.SERIAL,'exec-out','su','-c',command],stdout=output,stderr=subprocess.STDOUT)
    time.sleep(1)
    if process.poll() is not None:
        output.close();raise RuntimeError('Raw phone capture failed to start')
    pid=lab.adb('shell','su','-c',f"'cat {remote}.pid'").strip();assert pid.isdigit()
    return {'process':process,'output':output,'remote':remote,'pid':pid,'packet_limit':packet_limit}


def end_capture(capture,case):
    remote=capture['remote'];pid=capture['pid'];process=capture['process']
    early=process.poll() is not None
    command=lab.adb('shell','su','-c',f"'cat /proc/{pid}/cmdline'",required=False).replace('\x00',' ')
    if '/data/local/tmp/tcpdump' in command and remote+'.pcap' in command:
        lab.adb('shell','su','-c',f"'kill -INT {pid}'",required=False)
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
    finally:capture['output'].close()
    error=lab.adb('shell','su','-c',f"'cat {remote}.stderr'",required=False)
    (case/'capture_stderr.txt').write_text(error,encoding='utf-8')
    digest=lab.adb('shell','su','-c',f"'sha256sum {remote}.pcap'").split()[0]
    lab.adb('shell','su','-c',f"'chmod 644 {remote}.pcap'")
    lab.adb('pull',remote+'.pcap',str(case/'capture.pcap'),timeout=120)
    assert sha(case/'capture.pcap')==digest,'Raw capture transfer hash mismatch'
    # Delete only uniquely named, verified session files, after preserving the capture.
    lab.adb('shell','su','-c',f"'rm -f {remote}.pcap {remote}.pid {remote}.stderr'")
    dropped=re.findall(r'(\d+) packets dropped by kernel',error)
    captured=re.findall(r'(\d+) packets captured',error)
    count=int(captured[-1]) if captured else None
    return {'capture_sha256':digest,'ended_early':early,'kernel_drops':int(dropped[-1]) if dropped else None,
        'snaplen':768,'interface':'any','filtered_attack_ports_only':False,'streamed_packet_data_during_capture':False,
        'packet_limit':capture.get('packet_limit',100000),'captured_packets':count,
        'packet_limit_reached':count is not None and count>=capture.get('packet_limit',100000)}


def restart_trace(case,session):
    fixed.health();lab.adb('shell','am','force-stop','nids.app')
    fixed.trace_snapshot(case/'previous_native_trace.jsonl')
    lab.adb('shell','run-as','nids.app','rm','-f','files/tsanet_validation_trace.jsonl')
    lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','-f','0x20000000','--ez','start_monitor','true','--ez','validation_trace','true')
    until=time.monotonic()+40
    while time.monotonic()<until:
        cancelled()
        try:
            value=fixed.health()
            if value['history_age_seconds'] is not None and value['history_age_seconds']<40:return
        except (AssertionError,RuntimeError):pass
        time.sleep(1)
    raise RuntimeError('Fresh native monitor did not become healthy')


def target(meta):
    lab.adb('shell','am','force-stop','nids.datasetlab')
    args=['shell','am','start','-n','nids.datasetlab/.DatasetActivity','--ez','start_listener','true']
    for name in ['controller','session','user','password','bridge']:args+=['--es',name,str(meta[name])]
    args+=['--es','bind_address',meta['phone'],'--ei','port',str(meta['port']),'--el','seed',str(meta['seed'])]
    lab.adb(*args)
    until=time.monotonic()+30
    while time.monotonic()<until:
        value=lab.adb('exec-out','run-as','nids.datasetlab','cat','files/status.json',required=False)
        try:status=json.loads(value)
        except ValueError:status={}
        if status.get('session')==meta['session'] and status.get('state')=='listening':
            assert status['controller']==meta['controller'] and status['bind_address']==meta['phone'] and status['port']==meta['port']
            return status
        time.sleep(.5)
    raise RuntimeError('Isolated dataset target did not start')


def verify_target_apk():
    installed=lab.adb('shell','pm','path','nids.datasetlab').strip().removeprefix('package:')
    assert re.fullmatch(r'/data/app/[A-Za-z0-9_~+=/.-]+/base\.apk',installed),'Unexpected dataset APK path'
    digest=lab.adb('shell','su','-c',"'sha256sum "+installed+"'").split()[0]
    assert digest==sha(APK),'Installed dataset target differs from the recorded build'


def specifications(meta,status):
    rng=random.Random(meta['seed']);out=[]
    def add(route,query,subtype,label):out.append({'route':route,'query':query,'subtype':subtype,'label':label})
    for _ in range(4):
        add('/normal',{'q':rng.choice(['weather','notes','hello world','index 17'])+'a'*rng.choice([0,30,90,180,240])},'normal_http',0)
        add('/login',{'user':meta['user'],'password':meta['password']},'successful_login',0)
        add('/login',{'user':meta['user'],'password':'incorrect'+str(rng.randrange(1000))},'ordinary_failed_login',0)
        add('/search',{'q':rng.choice([status['public_value'],'SELECT value FROM example','<script>1+1</script>','nothing'])},'normal_search_or_code',0)
        add('/page',{'q':rng.choice(['hello','<b>example</b>','&lt;script&gt;example&lt;/script&gt;'])+'x'*rng.choice([0,40,120,220])},'normal_page',0)
        add('/service-error',{},'ordinary_server_error',0)
    if meta['mode']=='benign':
        for _ in range(48):add('/normal',{'q':'item'+str(rng.randrange(10**9))+'a'*rng.choice([0,30,90,180,240])},'legitimate_http_burst',0)
    if meta['mode']!='benign':
        partition=meta.get('partition','development')
        sql=["x' OR '1'='1","' OR 1=1 -- ","' UNION SELECT value FROM items -- "]
        xss=[f'<script>window.{meta["bridge"]}.done(1)</script>',f'<svg onload="window.{meta["bridge"]}.done(1)"></svg>']
        if partition=='validation':
            sql=["' OR (2+2)=4 -- ","x' OR 'b' LIKE 'b"]
            xss=[f'<SCRIPT>window.{meta["bridge"]}.done(1)</SCRIPT>',f'<script>(function(){{window.{meta["bridge"]}.done(1)}})()</script>']
        elif partition=='test':
            sql=["' OR 4 BETWEEN 1 AND 7 -- ","' UNION SELECT value FROM items WHERE value != '"+status['public_value']+"' -- "]
            xss=[f'<script>setTimeout(()=>window.{meta["bridge"]}.done(1),20)</script>',f"<svg onload='window[{json.dumps(meta['bridge'])}].done(1)'></svg>"]
        # Independent sequence labels live only in controller/target files, never request headers.
        for i in range(12):
            add('/login',{'user':meta['user'],'password':'guess'+str(rng.randrange(10**6))},'http_password_guessing',6)
        for i in range(8):
            add('/login',{'user':meta['user']+str(i),'password':'oneincorrectguess'},'http_password_spraying',6)
        for _ in range(6):add('/search',{'q':rng.choice(sql)},'sql_injection',6)
        for _ in range(6):add('/page',{'q':rng.choice(xss)},'xss',6)
    rng.shuffle(out)
    return out


def request(meta,spec,index):
    row={'index':index,**spec,'start_unix':time.time(),'connected':False}
    stream=socket.socket(socket.AF_INET,socket.SOCK_STREAM);stream.settimeout(8)
    try:
        stream.bind((meta['controller'],0));row['source']=meta['controller'];row['sport']=stream.getsockname()[1]
        row['destination']=meta['phone'];row['dport']=meta['port'];row['protocol']=6
        stream.connect((meta['phone'],meta['port']));row['connected']=True
        path=spec['route']+('?' +urlencode(spec['query']) if spec['query'] else '')
        headers=['GET '+path+' HTTP/1.1','Host: '+meta['phone'],'Accept: */*','Connection: close','','']
        stream.sendall('\r\n'.join(headers).encode('utf-8'));data=b''
        while len(data)<32768:
            part=stream.recv(4096)
            if not part:break
            data+=part
        row['response_sha256']=hashlib.sha256(data).hexdigest();row['response_bytes']=len(data)
        row['http_status']=int(data.split(b' ',2)[1]) if data.startswith(b'HTTP/') else None
    except OSError as error:row['error']=type(error).__name__
    finally:stream.close()
    row['end_unix']=time.time();return row


def replay(case):
    manifest=json.loads((BUNDLE/'manifest.json').read_text(encoding='utf-8'))
    assert sha(BUNDLE/'core.jar')==manifest['core_sha256'] and sha(BUNDLE/'kotlin-stdlib.jar')==manifest['runtime_sha256']
    cp=classpath([TOOLS,BUNDLE/'core.jar',BUNDLE/'kotlin-stdlib.jar'])
    native=lab.json_lines((case/'native_features.jsonl').read_text(encoding='utf-8'))
    first=min(row['start'] for row in native if row.get('schema')=='phone-aligned-v2')
    # Sidecar starts before NIDS. Align the deterministic first observed packet,
    # including persistent TCP connections whose 30s segment phase never washes out.
    result=subprocess.run([str(JAVA),'-Xmx2g','-cp',cp,'nids.dataset.DatasetReplay',str(case/'capture.pcap'),str(case/'watched.txt'),str(case/'offline_features.jsonl'),str(first)],capture_output=True,text=True,timeout=180)
    (case/'replay_stdout.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
    assert result.returncode==0,'Frozen offline replay failed'
    return json.loads(result.stdout.splitlines()[-1])


def collect(plan):
    session=plan['session'];assert re.fullmatch('[a-zA-Z0-9_-]{8,80}',session)
    case=RUN/'sessions'/session;case.mkdir(parents=True,exist_ok=True)
    if (case/'quality.json').exists():
        old=json.loads((case/'quality.json').read_text(encoding='utf-8'))
        if old.get('passed'):return old
        raise RuntimeError('Existing rejected session retained; allocate a new session ID for any retry')
    if (case/'session.json').exists():raise RuntimeError('Incomplete session retained for review; do not overwrite raw evidence on resume')
    cancelled();fixed.validate_identity();fixed.health();phone,controller=lab.endpoints()
    assert APK.exists() and TOOLS.exists();verify_target_apk()
    port=43191+plan['seed']%9
    listening=lab.adb('shell','ss','-ltn')
    assert port not in {int(v) for v in re.findall(r':(\d+)\b',listening)},'Selected dataset port is already occupied'
    rng=random.Random(plan['seed'])
    token=''.join(rng.choice('abcdef0123456789') for _ in range(12))
    meta={**plan,'phone':phone,'controller':controller,'port':port,'user':'user'+token[:8],'password':'pw'+token,
        'bridge':'b'+token[:8],'schema':'phone-aligned-v2','feature_dimensions':[32,115],
        'gate_sha256':fixed.GATE,'diagnosis_sha256':fixed.DIAG,'target_apk_sha256':sha(APK),
        'frozen_core_sha256':sha(BUNDLE/'core.jar'),'started_at_ist':datetime.now(lab.IST).isoformat(),
        'warmup_seconds':WARM_SECONDS,'no_model_prediction_labels':True,'background_flow_labels':'unknown/excluded'}
    lab.save(case/'session.json',meta);capture=None
    try:
        write_state(session,'starting_capture');capture=begin_capture(case)
        lab.save(case/'capture_process.json',{k:capture[k] for k in ['remote','pid']})
        restart_trace(case,session);meta['monitor_restart_unix']=time.time()
        (case/'watched.txt').write_text('\n'.join(addresses())+'\n',encoding='utf-8')
        pause(WARM_SECONDS,session,'warming_context')
        fixed.health();cancelled();status=target(meta);lab.save(case/'target_status.json',status)
        meta['eligible_start_unix']=time.time();lab.save(case/'session.json',meta)
        specs=specifications(meta,status);assert len(specs)<=96
        results=[]
        ranges={'train':(.15,.5),'validation':(.35,.8),'test':(.7,1.2),'development':(.2,.35)}
        interval=random.Random(plan['seed']+31).uniform(*ranges.get(plan['partition'],(.2,.6)))
        sequential=[(i,s) for i,s in enumerate(specs) if s['subtype']!='legitimate_http_burst']
        burst=[(i,s) for i,s in enumerate(specs) if s['subtype']=='legitimate_http_burst']
        for i,spec in sequential:
            cancelled();assert capture['process'].poll() is None,'Capture stopped early'
            results.append(request(meta,spec,i));lab.save(case/'requests.json',results)
            write_state(session,'recording',completed_requests=i+1,total_requests=len(specs));time.sleep(interval)
        if burst:
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures=[]
                for i,spec in burst:
                    cancelled();futures.append(pool.submit(request,meta,spec,i));time.sleep(.03)
                results += [future.result() for future in futures]
            lab.save(case/'requests.json',results)
        meta['traffic_end_unix']=time.time();lab.save(case/'session.json',meta)
        pause(45,session,'flushing_complete_flows')
        target_events=lab.json_lines(lab.adb('exec-out','run-as','nids.datasetlab','cat','files/events.jsonl'))
        lab.save(case/'target_events.json',target_events)
        lab.adb('shell','am','force-stop','nids.datasetlab')
        meta['capture_stop_unix']=time.time()
        item=capture;capture=None;meta['capture_quality']=end_capture(item,case)
        fixed.trace_snapshot(case/'native_features.jsonl');meta['monitor_after']=fixed.health()
        lab.save(case/'session.json',meta)
        write_state(session,'checking_replay');meta['offline_replay']=replay(case);lab.save(case/'session.json',meta)
        from experiments.phone_capture_v1.quality import audit
        quality=audit(case);lab.save(case/'quality.json',quality)
        lab.save(PUBLIC/(session+'_quality.json'),quality)
        if not quality['passed']:raise RuntimeError('Recording rejected by quality audit: '+str(quality['failures']))
        write_state(session,'accepted',labels=quality['label_counts'],subtypes=quality['subtype_counts'])
        print('SESSION_ACCEPTED',session,json.dumps(quality['label_counts']),flush=True)
        return quality
    except BaseException as error:
        lab.save(case/'failure.json',{'error':str(error),'time_ist':datetime.now(lab.IST).isoformat()})
        write_state(session,'failed',error=str(error));raise
    finally:
        lab.adb('shell','am','force-stop','nids.datasetlab',required=False)
        if capture is not None:
            try:lab.save(case/'interrupted_capture.json',end_capture(capture,case))
            except Exception as error:print('Capture cleanup:',error,flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',required=True);parser.add_argument('--mode',choices=['mixed','benign'],default='mixed')
    parser.add_argument('--seed',type=int,default=1201);args=parser.parse_args()
    plan={'session':args.session,'mode':args.mode,'seed':args.seed,'partition':'development','campaign':'pilot'}
    RUN.mkdir(parents=True,exist_ok=True)
    with lab.exclusive():collect(plan)


if __name__=='__main__':main()
