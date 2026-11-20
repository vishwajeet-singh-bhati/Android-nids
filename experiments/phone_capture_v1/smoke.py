"""Test capture automation and label rejection; device actions require --device."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_capture_v1 import collect as capture
from experiments.phone_capture_v1.quality import verified_label,validate_capture
lab=capture.lab


def negative_label_checks():
    r={'source':'172.16.88.233','sport':51000,'destination':'172.16.89.83','dport':43191,'protocol':6,
        'route':'/page','http_status':200,'subtype':'normal_page','label':0}
    c={k:r[k] for k in ['source','sport','destination','dport','protocol']};c['connection_id']='one'
    events=[{'event':'connection_accepted','connection':c},{'event':'request_received','connection':c,'route':'/page'},
        {'event':'response_sent','connection':c,'status':200},{'event':'xss_effect_confirmed','connection':c}]
    try:verified_label(r,events)
    except AssertionError:pass
    else:raise AssertionError('Confirmed script effect must not receive a normal label')
    # A different socket's confirmation cannot label this request.
    r.update({'label':6,'subtype':'xss'})
    events[-1]={'event':'xss_effect_confirmed','connection':dict(c,sport=51001)}
    try:verified_label(r,events)
    except AssertionError:pass
    else:raise AssertionError('Wrong-socket proof must not create a positive example')
    return {'normal_with_attack_effect_rejected':True,'wrong_socket_proof_rejected':True}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--device',action='store_true');parser.add_argument('--all-variants',action='store_true');args=parser.parse_args()
    result={'label_rejection_checks':negative_label_checks(),'feature_vectors_fabricated_for_training':0,'device_test_requested':args.device}
    if args.device:
        with lab.exclusive():
            capture.fixed.validate_identity();capture.fixed.health();phone,controller=lab.endpoints()
            session=datetime.now(lab.IST).strftime('%Y%m%d_%H%M%S_dataset_smoke')
            case=capture.RUN/'smoke'/session;case.mkdir(parents=True,exist_ok=True)
            meta={'session':session,'seed':1201,'mode':'mixed','phone':phone,'controller':controller,
                'port':43191,'user':'userabcdef12','password':'pwabcdef123456','bridge':'babcdef12'}
            cap=None
            try:
                cap=capture.begin_capture(case);status=capture.target(meta)
                specs=[]
                for partition in (['train','validation','test'] if args.all_variants else ['development']):
                    specs+=capture.specifications(dict(meta,partition=partition),status)
                selected=[];seen=set()
                for s in specs:
                    k=(s['subtype'],json.dumps(s['query'],sort_keys=True) if s['subtype'] in ('sql_injection','xss') else '')
                    if k in seen:continue
                    if s['subtype'] not in ('sql_injection','xss','successful_login','ordinary_failed_login','normal_search_or_code'):continue
                    selected.append(s);seen.add(k)
                rows=[capture.request(meta,s,i) for i,s in enumerate(selected)]
                time.sleep(4)
                events=lab.json_lines(lab.adb('exec-out','run-as','nids.datasetlab','cat','files/events.jsonl'))
                lab.save(case/'requests.json',rows);lab.save(case/'target_events.json',events)
                labels=[verified_label(r,events) for r in rows]
                lab.adb('shell','am','force-stop','nids.datasetlab')
                item=cap;cap=None;qc=capture.end_capture(item,case)
                assert qc['kernel_drops']==0 and not qc['ended_early']
                frames=validate_capture(case/'capture.pcap');assert frames>0
                result.update({'case':str(case.relative_to(ROOT)),'controller_requests':len(rows),'verified_requests':len(labels),
                    'positive_effects':sum(x['proof']=='confirmed_effect' for x in labels),'captured_records':frames,'capture_quality':qc})
                capture.fixed.health()
            finally:
                lab.adb('shell','am','force-stop','nids.datasetlab',required=False)
                if cap is not None:capture.end_capture(cap,case)
    result['passed']=True
    lab.save(capture.PUBLIC/'capture_smoke.json',result);print(json.dumps(result,indent=2))


if __name__=='__main__':main()
