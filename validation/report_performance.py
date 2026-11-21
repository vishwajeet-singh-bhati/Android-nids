"""Build a concise comparison from immutable phone benchmark reports."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json
from pathlib import Path
import statistics
import re

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'validation/reports/performance_v1'
RUN=ROOT/'runs/performance_v1'


def summary(values):
    values=[float(v) for v in values if isinstance(v,(int,float))]
    return {'n':len(values),'median':statistics.median(values),'min':min(values),'max':max(values)} if values else None


def report(name):return json.loads((RUN/name/'report.json').read_text(encoding='utf-8'))


def quality(row):
    text=row.get('normalized_local_draft',row.get('raw_local_draft',''));lower=text.lower()
    failures=[];known=row.get('known_receiver',False)
    if 'does not confirm an attack' not in lower:failures.append('Missing explicit uncertainty')
    if str(37 if known else 12) not in lower:failures.append('Missing packet count')
    if known:
        if 'nids.protocollab' not in lower or 'receiv' not in lower:failures.append('Missing receiving app/role')
        if 'history' not in lower or not any(x in lower for x in ('incomplete','building')):failures.append('Missing incomplete history warning')
        if 'traffic' not in lower or not any(x in lower for x in ('missed','skipped')):failures.append('Missing incomplete capture warning')
    elif not re.search(r'(?:app|socket|ownership)[^.!?\n]{0,45}(?:unknown|could not|cannot)',lower):
        failures.append('Missing explicit unknown app ownership')
    patterns={1:('bot','automated background communication'),2:('brute force','repeated sign-in attempts'),
        3:('ddos','overload from several sources'),4:('dos','connection overload'),
        5:('port scan','portscan','check for open connections'),6:('web attack','suspicious web activity'),
        7:('type is unknown','type is undetermined','type is not','unclassified')}
    if not any(p in lower for p in patterns.get(row.get('fixture_class'),())):failures.append('Missing supplied suspected pattern/type status')
    if not 8<=len(text.split())<=75:failures.append('Outside brief-note length')
    if any(p in lower for p in ('manual check to restate:','as an ai',"i'm sorry",'here is a rewritten','assistant\n')):
        failures.append('Prompt echo, refusal or model introduction')
    return {'passes_additional_evidence_checks':not failures,'failures':failures}


def model_rows(rows):
    # Repeated cold/warm fixtures are not independent quality examples.
    result={'requests':len(rows),'accepted':sum(r.get('generated_text_accepted',False) for r in rows),
        'unique_fixtures':len({(r.get('fixture_class'),r.get('known_receiver',False)) for r in rows}),
        'errors':[r.get('runtime_error') for r in rows if r.get('runtime_error')]}
    result['accepted_and_additional_evidence_checks_pass']=sum(r.get('generated_text_accepted',False) and quality(r)['passes_additional_evidence_checks'] for r in rows)
    for warm in (False,True):
        chosen=[r for r in rows if not r.get('quality_only') and r.get('warm_model_reused')==warm and 'elapsed_ms' in r]
        result['warm' if warm else 'cold']={k:summary([r.get(k) for r in chosen]) for k in
            ('elapsed_ms','generation_ms','verification_ms','load_ms','first_callback_including_verification_ms','process_cpu_ms','worker_process_cpu_ms')}
        result['warm' if warm else 'cold']['tokens']={k:summary([json.loads(r.get('runtime_stats_raw') or '{}').get(k) for r in chosen])
            for k in ('prompt_tokens','generated_tokens','prefill_token_per_sec','decode_token_per_sec')}
    result['examples']=[{k:r[k] for k in ('name','fixture_class','known_receiver','display','raw_local_draft','generated_text_accepted','runtime_error','elapsed_ms','display_source') if k in r} for r in rows]
    for example,row in zip(result['examples'],rows):example['independent_evidence_screen']=quality(row)
    return result


def main():
    output={'scope':'Component experiments preserve production app code37 and its model files. No new attack or accuracy measurement.',
        'production_worker':model_rows(report('current_llama_20261121')['trials']),
        'matched_components':{},'options':{},'excluded':{
            'current_detector_20261121':'Timings retained; all external telemetry failed.',
            'llama_paired_20261121':'Aborted: concurrent detector initialization imposed one-thread process-wide pool.',
            'hoisted_detector_20261121_r3':'Timings retained; only two valid external samples, below predeclared minimum of three.',
            'detector_paired_20261121':'Initial monitor-readiness race; no paired inference performed.'}}
    paired=report('llama_guidance_pool4_20261121')['trials']
    for profile in ('current','guidance_only48'):
        output['matched_components'][profile]=model_rows([r for r in paired if r.get('performance_profile')==profile])
    for name in ('llama_paired_pool4_20261121','llama_structured_pool4_20261121'):
        rows=report(name)['trials']
        for profile in sorted({r.get('performance_profile') for r in rows} - {None,'current'}):
            output['options'][profile]=model_rows([r for r in rows if r.get('performance_profile')==profile])
    option_path=RUN/'explainer_options_20261121/report.json'
    if option_path.exists():
        rows=report('explainer_options_20261121')['trials']
        for profile in ('plain_hybrid48','small_full96','small_hybrid48'):
            output['options'][profile]=model_rows([r for r in rows if r.get('performance_profile')==profile or r.get('name')==profile+'_runtime_failure'])
        output['plain_renderer']=next((r for r in rows if r.get('name')=='plain_evidence_renderer'),None)
    detector_path=RUN/'detector_paired_20261121_r2/report.json'
    if detector_path.exists():
        output['detector_paired']={variant:[r for r in report('detector_paired_20261121_r2')['trials'] if r.get('variant')==variant]
            for variant in ('current','hoisted_fp32')}
    output['notes']=[
        'Quality acceptance is a rule-based screen on eight fixture combinations, not human user testing or proof of factuality on arbitrary evidence.',
        'Cold means model released/reverified/reloaded; OS disk page cache is not flushed.',
        'Hybrid factual sentences are deterministic; only the guidance sentence comes from the language model.',
        'The direct component pool requests four threads and pauses capture. Production worker includes IPC and active capture; do not infer its optimized end-to-end latency from this A/B.',
        'Sampled PSS/RSS includes instrumentation and other app work; Android Debug totalPss includes proportional swap while /proc Pss is resident.',
        'Any candidate error is retained; runtime completion is distinct from explanation quality acceptance.'
    ]
    (OUT/'comparison.json').write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print('WROTE comparison.json')


if __name__=='__main__':main()
