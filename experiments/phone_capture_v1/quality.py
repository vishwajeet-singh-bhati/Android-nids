"""Strict saved-capture QC and flow labels; no predictions are used as ground truth."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter,defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys

import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'));sys.path.insert(0,str(ROOT))
from manual_test_correlation import key
from experiments.phone_alignment_v2.capture_audit import validate_capture


def flow_key(row):
    return key(row['protocol'],(row['source'],int(row['sport'])),(row['destination'],int(row['dport'])))


def identity(row):
    return (flow_key(row),row['watched'],round(row['start']*1e6),round(row['end']*1e6))


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def tcp_counts(path,wanted):
    counts=Counter()
    with path.open('rb') as stream:
        h=stream.read(24);endian='<' if h[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
        link=struct.unpack_from(endian+'I',h,20)[0]
        while True:
            h=stream.read(16)
            if not h:break
            n=struct.unpack_from(endian+'I',h,8)[0];b=stream.read(n)
            off={1:14,113:16,276:20,101:0}.get(link)
            if off is None:raise ValueError('Unsupported companion link framing')
            if len(b)<off+20 or b[off]>>4!=4 or b[off+9]!=6:continue
            tcp=off+(b[off]&15)*4
            if len(b)<tcp+20:continue
            source=str(ipaddress.ip_address(b[off+12:off+16]));dest=str(ipaddress.ip_address(b[off+16:off+20]))
            sport,dport=struct.unpack_from('!HH',b,tcp);k=key(6,(source,sport),(dest,dport))
            if k in wanted:counts[k]+=1
    return counts


def verified_label(request,events):
    """Require exact socket events; no window-wide or model-derived labels."""
    same=[e for e in events if e.get('connection') and flow_key(e['connection'])==flow_key(request)]
    accepts=[e for e in same if e['event']=='connection_accepted']
    assert len(accepts)==1,'Ambiguous/missing accepted connection'
    connection_id=accepts[0]['connection']['connection_id']
    assert all(e['connection']['connection_id']==connection_id for e in same)
    received=[e for e in same if e['event']=='request_received']
    assert len(received)==1 and received[0]['route']==request['route'],'Request/target route mismatch'
    responses=[e for e in same if e['event']=='response_sent']
    assert len(responses)==1 and responses[0]['status']==request['http_status'],'Response evidence mismatch'
    kinds=Counter(e['event'] for e in same)
    subtype=request['subtype'];label=request['label']
    assert label in (0,6)
    if subtype=='sql_injection':assert label==6 and kinds['sql_effect_confirmed']>=1;proof='confirmed_effect'
    elif subtype=='xss':assert label==6 and kinds['xss_effect_confirmed']>=1;proof='confirmed_effect'
    elif subtype in ('http_password_guessing','http_password_spraying'):
        assert label==6 and kinds['login_failure']==1;proof='verified_attack_attempt'
    else:
        assert label==0 and not kinds['sql_effect_confirmed'] and not kinds['xss_effect_confirmed']
        if subtype=='ordinary_failed_login':assert kinds['login_failure']==1
        if subtype=='successful_login':assert kinds['login_success']==1
        if subtype=='ordinary_server_error':assert kinds['ordinary_service_error']==1
        proof='controlled_normal_action'
    return {'connection_id':connection_id,'family':label,'subtype':subtype,'proof':proof,'target_event_counts':dict(kinds)}


def audit(case):
    meta=json.loads((case/'session.json').read_text(encoding='utf-8'))
    requests=json.loads((case/'requests.json').read_text(encoding='utf-8'))
    events=json.loads((case/'target_events.json').read_text(encoding='utf-8'))
    failures=[];labels=[];errors=[];report={'session':meta['session'],'partition':meta['partition'],'mode':meta['mode'],
        'model_predictions_used_for_labels':False,'captured_request_count':len(requests)}
    try:
        assert meta['capture_quality']['kernel_drops']==0 and not meta['capture_quality']['ended_early'],'Capture loss/early end'
        records=validate_capture(case/'capture.pcap');assert records<100000
        assert meta['eligible_start_unix']-meta['monitor_restart_unix']>=335,'Insufficient full-history warm-up'
        for name in ['late','forced_reorder','flow_evictions','history_evictions','invalid_flows']:
            assert meta['offline_replay'][name]==0,('Offline extractor unhealthy',name)
        expected={flow_key(r) for r in requests}
        assert len(expected)==len(requests),'Tuple reuse needs explicit disambiguation'
        native=[r for r in read_rows(case/'native_features.jsonl') if r.get('schema')=='phone-aligned-v2' and r['watched']==meta['phone'] and flow_key(r) in expected]
        replay=[r for r in read_rows(case/'offline_features.jsonl') if r['watched']==meta['phone'] and flow_key(r) in expected]
        assert {flow_key(r) for r in native}==expected and {flow_key(r) for r in replay}==expected,'Missing native/replay test connection'
        by_id=defaultdict(list)
        for r in replay:by_id[identity(r)].append(r)
        assert Counter(identity(r) for r in native)==Counter(identity(r) for r in replay),'Native/offline segment identity mismatch'
        actual_packets=Counter()
        for row in native:
            other=by_id[identity(row)].pop()
            a=np.array(row['flow']+row['context'],dtype=np.float32);b=np.array(other['flow']+other['context'],dtype=np.float32)
            assert a.shape==(147,) and np.isfinite(a).all() and np.isfinite(b).all()
            error=float(np.max(np.abs(a.astype(np.float64)-b.astype(np.float64))));errors.append(error)
            assert error<=1e-4,'Native/offline147-input parity failure'
            actual_packets[flow_key(row)]+=int(row['flow'][1]+row['flow'][2])
        assert actual_packets==tcp_counts(case/'capture.pcap',expected),'Native/PCAP per-tuple packet counts differ'
        indexed={flow_key(r):r for r in requests}
        truth={}
        for request in requests:
            assert request['connected'] and request.get('http_status') is not None and not request.get('error'),'Incomplete controller request'
            truth[flow_key(request)]=verified_label(request,events)
        for row in native:
            request=indexed[flow_key(row)];label=truth[flow_key(row)]
            labels.append({**label,'request_index':request['index'],'session':meta['session'],'partition':meta['partition'],
                'start':row['start'],'end':row['end'],'watched':row['watched'],
                'source':row['source'],'sport':row['sport'],'destination':row['destination'],'dport':row['dport'],'protocol':row['protocol'],
                'raw':row['flow']+row['context']})
        signatures=defaultdict(set)
        for row in labels:signatures[hashlib.sha256(np.asarray(row['raw'],np.float32).tobytes()).hexdigest()].add(row['family'])
        contradictions=sum(len(v)>1 for v in signatures.values())
        report.update({'pcap_records':records,'native_segments':len(native),'eligible_values_compared':len(native)*147,
            'maximum_feature_error':max(errors,default=0),'all_test_connection_packet_counts_exact':True,
            'exact_input_label_conflicts':contradictions,'label_counts':dict(Counter(str(r['family']) for r in labels)),
            'subtype_counts':dict(Counter(r['subtype'] for r in labels)),
            'background_flows_automatically_labeled':0,'normal_context_contains_attacks_possible':meta['mode']=='mixed',
            'capture_sha256':meta['capture_quality']['capture_sha256'],'extractor_sha256':meta['frozen_core_sha256']})
    except (AssertionError,ValueError,KeyError,IndexError) as error:failures.append(str(error) or repr(error))
    report['passed']=not failures;report['failures']=failures
    if not failures:
        (case/'labeled_features.jsonl').write_text(''.join(json.dumps(r,allow_nan=False)+'\n' for r in labels),encoding='utf-8')
    return report
