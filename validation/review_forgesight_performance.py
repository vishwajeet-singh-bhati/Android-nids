"""Recheck the saved PR/phone evidence without a device, fitting or generation."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json
from pathlib import Path
import statistics

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'validation/reports/forgesight_pr_review'


def read(name):return json.loads((OUT/name).read_text(encoding='utf-8'))


def main():
    warmup=read('warmup_comparison.json');assert warmup['passed']
    for category in (5,7,2):
        rows=[r for r in warmup['trials'] if r['fixture_class']==category]
        assert len(rows)==2 and {r['prewarmed'] for r in rows}=={False,True}
        assert rows[0]['normalized_local_draft']==rows[1]['normalized_local_draft']
        prepared=next(r for r in rows if r['prewarmed'])
        assert prepared['boot']['warmup_runtime_stats']['generated_tokens']==1
    native=read('native_budget_checks.json');assert native['passed']
    for row in native['token_budget_checks']['cases']:
        assert row['stopped'] and row['forwarded_callbacks']==row['limit']
        assert 1<=row['native_generated_tokens']<=row['limit']
    assert native['trials'][0]['normalized_local_draft']==native['trials'][1]['normalized_local_draft']
    runtime=read('hybrid_runtime_code39.json');assert runtime['passed'] and len(runtime['trials'])==8
    for row in runtime['trials']:
        stats=json.loads(row['runtime_stats_raw'])
        assert row['token_budget']==48 and row['stream_token_callbacks']<=48
        assert 0<stats['generated_tokens']<=48 and not row['runtime_error']
        assert row['display'].startswith(row['factual_prefix'])
        assert all(value in row['display'] for value in ('This does not confirm an attack.','Protocol Lab (nids.protocollab)','37 network packets','history is still building','Some traffic was skipped'))
        assert row['capture_queue_drops']==0
    assert runtime['immediate_notification_content_verified']
    deployment=read('final_deployment.json')
    assert deployment['installed'] and deployment['version_code']==39
    assert deployment['database_integrity']=='ok'
    assert all(row['missing']==0 for row in deployment['history_preservation'].values())
    warm=[r['request_wall_ms'] for r in runtime['trials'] if r['warm_model_reused']]
    result={'passed':True,'source':'Offline recomputation from public captured device reports; no phone/model/network calls.',
        'warmup_pairs_with_identical_output':3,'native_limit_cases':[r['limit'] for r in native['token_budget_checks']['cases']],
        'guidance_identical_after_truncated_generation':True,'production_requests_checked':8,
        'production_warm_median_ms':statistics.median(warm),'factual_prefix_and_app_warning_preserved':True,
        'all_native_counts_within_budget':True,'capture_queue_drops':0,'original_history_ids_missing':0}
    (OUT/'offline_audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('FORGESIGHT_PHONE_EVIDENCE_AUDIT_PASS')


if __name__=='__main__':main()
