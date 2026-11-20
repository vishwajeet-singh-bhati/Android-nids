"""Inventory recorded v2 diagnostics for dataset preparation; filesystem only."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'validation/reports/phone_capture_v1/development_inventory.json'
CONTRACT=ROOT/'validation/reports/phone_alignment_v2/feature_contract.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_header(path):
    if not path.exists():return None
    with path.open('rb') as stream:head=stream.read(24)
    if len(head)!=24:return {'readable':False}
    endian={b'\xd4\xc3\xb2\xa1':'<',b'\x4d\x3c\xb2\xa1':'<',
            b'\xa1\xb2\xc3\xd4':'>',b'\xa1\xb2\x3c\x4d':'>'}.get(head[:4])
    if endian is None:return {'readable':False}
    return {'readable':True,'snaplen':struct.unpack_from(endian+'I',head,16)[0],
        'linktype':struct.unpack_from(endian+'I',head,20)[0]}


def main():
    records=[]
    for path in sorted((ROOT/'runs/manual_phone_tests').glob('*/run.json')):
        meta=json.loads(path.read_text(encoding='utf-8'))
        if meta.get('detector_schema')!='phone-aligned-v2':continue
        case=path.parent;check_path=case/'check.json'
        check=json.loads(check_path.read_text(encoding='utf-8')) if check_path.exists() else {}
        cap=case/'traffic.pcap';trace=case/'nids_numeric_trace.jsonl';events=case/'target_events.json'
        headers=capture_header(cap)
        records.append({'run_id':case.name,'profile':meta.get('profile'),
            'purpose':'development_only','eligible_for_new_blind_test':False,'training_ready':False,
            'labels_assigned_by_inventory':False,'observed_target_event_counts':check.get('target_event_counts',{}),
            'capture_header':headers,'native_feature_trace_available':trace.exists(),
            'raw_capture_can_reconstruct_complete_phone_inputs':False,
            'curation_requirements':['Explicit flow/request-to-event label review; no blanket episode labels.',
                'Retain known development status and session grouping.',
                'Filtered companion capture omits full context and may truncate protocol evidence.'],
            'recorded_model_hashes':{'gate':meta.get('gate_model_sha256'),'diagnosis':meta.get('diagnosis_model_sha256')},
            'artifact_sha256':{p.name:sha(p) for p in [path,check_path,cap,trace,events] if p.exists()}})
    payload={'prepared_at_ist':datetime.now(timezone(timedelta(hours=5,minutes=30))).isoformat(),
        'state':'preparation_only','new_traffic_sent':False,'new_training_started':False,
        'existing_data_modified':False,'feature_dimensions':[32,115],
        'feature_contract_sha256':sha(CONTRACT),'existing_diagnostic_runs':len(records),
        'profiles':dict(Counter(r['profile'] for r in records)),
        'all_existing_runs_excluded_from_new_blind_test':True,'records':records}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(payload,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'state':payload['state'],'existing_diagnostic_runs':len(records),
        'profiles':payload['profiles'],'output':str(OUT)},indent=2))


if __name__=='__main__':main()
