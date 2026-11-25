"""Summarise every saved phone attack/control run per CONNECTION and test each claim.

Reads only local files under runs/ (no phone, no traffic). Writes counts only:
no IP addresses, ports, payloads or message text leave this machine.

    python validation/summarize_attack_claims.py

Output: results/attack_claims_review/summary.json and SUMMARY.md
See docs/ATTACK_TEST_AUDIT.md for why each comparison matters.
"""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from collections import Counter, defaultdict
from datetime import datetime
import json

from manual_test_correlation import endpoint, key

ROOT=Path(__file__).resolve().parents[1]
MANUAL=ROOT/'runs/manual_phone_tests'
PROTOCOL=ROOT/'runs/protocol_phone_tests/cases'
OUT=ROOT/'results/attack_claims_review'


def rate(flagged,total):
    return {'flagged':flagged,'connections':total,'rate':round(flagged/total,3) if total else None}


def manual_case(directory):
    """Connection-level view of one controlled_phone_test.py case."""
    run=json.loads((directory/'run.json').read_text(encoding='utf-8'))
    check_path=directory/'check_reconciled.json'
    if not check_path.exists():check_path=directory/'check.json'
    if run.get('error') or not run.get('traffic_completed'):
        return {'run_id':directory.name,'profile':run.get('profile'),'valid':False,'reason':'traffic interrupted/failed: '+str(run.get('error',''))[:160]}
    if not check_path.exists():return {'run_id':directory.name,'profile':run['profile'],'valid':False,'reason':'Check not run'}
    check=json.loads(check_path.read_text(encoding='utf-8'))
    packets=check.get('packet_evidence') or {}
    total=packets.get('tcp_tuples')
    flagged={};labels=Counter()
    for flag in check.get('model_flags',[]):
        if flag.get('traffic_correlation')!='matched_test_capture':continue
        owner=flag.get('attribution') or {};a=endpoint(owner.get('initiator'));b=endpoint(owner.get('responder'))
        if not (a and b):continue
        k=key(6,a,b)
        if k not in flagged:flagged[k]=flag.get('class');labels[flag.get('class')]+=1
    counts=check.get('traffic_correlation',{}).get('counts',{})
    return {'run_id':directory.name,'profile':run['profile'],'valid':bool(total),'reason':None if total else 'no captured test tuples',
        'harness':'controlled_phone_test','gate_model_sha256':run.get('gate_model_sha256'),
        'test_connections':rate(len(flagged),total or 0),'flagged_connection_labels':dict(labels),
        'logged_flags_matched':counts.get('matched_test_capture',0),'background_flags_ignored':counts.get('outside_test_endpoints',0),
        'target_events':check.get('target_event_counts',{}),'connected_attempts':check.get('traffic_summary',{}).get('connected'),
        'nmap':{k:v for k,v in run.get('nmap',{}).items() if k in ('command','scan_type','ports')} or None}


def protocol_case(directory):
    import review_protocol_results as review
    try:audited=review.audit(directory)
    except Exception as error:
        return {'run_id':directory.name,'profile':directory.name.split('_')[2] if directory.name.count('_')>=3 else None,
                'valid':False,'reason':type(error).__name__+': '+str(error)[:200]}
    roles={name:rate(v['flagged'],v['connections']) for name,v in audited['by_target_event'].items()}
    labels={name:v['class_counts'] for name,v in audited['by_target_event'].items()}
    return {'run_id':audited['run_id'],'profile':audited['profile'],'valid':True,'harness':'protocol_phone_test',
        'primary':rate(audited['primary']['flagged'],audited['primary']['connections']),
        'correctly_typed_primary':audited['correctly_typed_primary'],'by_role':roles,'labels_by_role':labels}


def pool(cases,profile,role=None):
    flagged=total=0;labels=Counter();runs=0
    for c in cases:
        if not c.get('valid') or c['profile']!=profile:continue
        if role is None:
            part=c.get('primary') or c.get('test_connections');lab=c.get('flagged_connection_labels',{})
        else:
            part=c.get('by_role',{}).get(role);lab=c.get('labels_by_role',{}).get(role,{})
            if lab and 'Benign' in lab:lab={k:v for k,v in lab.items() if k!='Benign'}
        if not part:continue
        runs+=1;flagged+=part['flagged'];total+=part['connections'];labels.update(lab)
    return dict(rate(flagged,total),runs=runs,flagged_labels=dict(labels))


def verdicts(cases):
    v={}
    scan=pool(cases,'PortScan');slow=pool(cases,'SlowScan');nmap=pool(cases,'NmapScan');closed=pool(cases,'ClosedPortControl')
    v['port_scan']={'scan':scan,'slow_scan':slow,'nmap_scan':nmap,'single_closed_port_control':closed,
        'verdict':('NEED ClosedPortControl run' if not closed['runs'] else
                   'Scan-specific: closed-port control quiet' if closed['flagged']==0 else
                   'Gate flags ANY unanswered inbound connection; claim only "scan traffic is flagged", and rely on the Port Scan label share'),
        'generalises_to_real_tool':None if not nmap['runs'] else bool(nmap['flagged'])}
    attack={p:pool(cases,p+'BruteForce',p.lower()+'_login_failure') for p in ('FTP','SSH')}
    normal={p:{'failure':pool(cases,'Benign',p.lower()+'_login_failure'),'success':pool(cases,'Benign',p.lower()+'_login_success')} for p in ('FTP','SSH')}
    rows={}
    for p in ('FTP','SSH'):
        n_flag=normal[p]['failure']['flagged']+normal[p]['success']['flagged'];n_tot=normal[p]['failure']['connections']+normal[p]['success']['connections']
        a=attack[p];normal_rate=n_flag/n_tot if n_tot else None
        rows[p]={'brute_force_attempts':a,'normal_logins':rate(n_flag,n_tot),
            'verdict':'NEED Benign protocol runs' if normal_rate is None else
                      ('NOT VALID: normal logins flagged at a similar rate; model flags the protocol, not brute force' if normal_rate>=.5 else
                       'Discriminates in this sample' if a['rate'] and a['rate']-normal_rate>=.5 else 'Weak separation')}
    v['brute_force']=rows
    guess=pool(cases,'PasswordGuessing');burst=pool(cases,'NormalBurst')
    v['http_password_guessing']={'attack':guess,'same_rate_normal_control':burst,
        'verdict':'NEED NormalBurst run' if not burst['runs'] else
                  ('Rate alone triggers it: not a password-guessing detector' if burst['flagged'] else 'Normal burst quiet'),
        'note':'Training used the same lab/phone (Web Attack class). In-distribution evidence only.'}
    for name in ('SQLInjection','XSS','HTTPFlood','ConnectionExhaustion','Beacon'):
        v[name]=pool(cases,name)
    v['Benign']=pool([c for c in cases if c.get('harness')=='controlled_phone_test'],'Benign')
    for p in ('DoS','DDoS'):
        held=pool(cases,p,'resource_held');denied=pool(cases,p,'resource_denied')
        v[p]={'served_requests':held,'refused_requests':denied,'primary':pool(cases,p),
              'verdict':'not run' if not (held['connections'] or denied['connections']) else 'Missed' if not (held['flagged'] or denied['flagged']) else
                        ('NOT VALID as DoS detection: only the slow served requests were flagged' if held['flagged'] and not denied['flagged'] else 'Partially flagged; check labels')}
    v['BotBehavior']=pool(cases,'BotBehavior','bot_exchange')
    v['protocol_benign_http_probes']=pool(cases,'Benign','probe_available')
    return v


def markdown(result):
    v=result['verdicts'];lines=['# Attack-claim review','',f"Generated {result['generated_at']} from {result['valid_cases']} valid saved cases "
        f"({result['invalid_cases']} incomplete/failed listed in summary.json). Unit: one TCP connection, not a segment.",'',
        '| Check | Attack connections flagged | Matching normal control flagged | Verdict |','|---|---|---|---|']
    f=lambda r:f"{r['flagged']}/{r['connections']}" if r['connections'] else 'not run'
    s=v['port_scan'];lines.append(f"| Port scan (harness) | {f(s['scan'])} | {f(s['single_closed_port_control'])} (single closed port) | {s['verdict']} |")
    lines.append(f"| Port scan (real nmap) | {f(s['nmap_scan'])} | - | {'not run' if s['generalises_to_real_tool'] is None else ('flagged' if s['generalises_to_real_tool'] else 'missed')} |")
    for p,r in v['brute_force'].items():
        lines.append(f"| {p} brute force | {f(r['brute_force_attempts'])} | {f(r['normal_logins'])} (normal logins) | {r['verdict']} |")
    g=v['http_password_guessing'];lines.append(f"| HTTP password guessing | {f(g['attack'])} | {f(g['same_rate_normal_control'])} (NormalBurst) | {g['verdict']} |")
    for p in ('DoS','DDoS'):
        r=v[p];lines.append(f"| {p} | served {f(r['served_requests'])}, refused {f(r['refused_requests'])} | - | {r['verdict']} |")
    lines.append(f"| Bot beacon | {f(v['BotBehavior'])} | - | {'not run' if not v['BotBehavior']['connections'] else 'Missed' if not v['BotBehavior']['flagged'] else 'Flagged'} |")
    for name in ('SQLInjection','XSS','HTTPFlood','ConnectionExhaustion','Beacon'):
        lines.append(f"| {name} | {f(v[name])} | - | in-distribution / bounded case; see audit |")
    lines.append(f"| Benign HTTP controls | {f(v['Benign'])} + protocol probes {f(v['protocol_benign_http_probes'])} | - | false-positive check |")
    lines+=['','Labels of flagged connections and per-run details: summary.json. Read docs/ATTACK_TEST_AUDIT.md before quoting any row.','']
    return '\n'.join(lines)


def main():
    cases=[]
    if MANUAL.exists():
        for d in sorted(p for p in MANUAL.iterdir() if p.is_dir() and (p/'run.json').exists()):
            try:cases.append(manual_case(d))
            except Exception as error:cases.append({'run_id':d.name,'valid':False,'reason':type(error).__name__+': '+str(error)[:200]})
    if PROTOCOL.exists():
        for d in sorted(p for p in PROTOCOL.iterdir() if p.is_dir() and (p/'review.json').exists()):
            cases.append(protocol_case(d))
    valid=[c for c in cases if c.get('valid')]
    result={'generated_at':datetime.now().astimezone().isoformat(timespec='seconds'),'valid_cases':len(valid),
        'invalid_cases':len(cases)-len(valid),'cases':cases,'verdicts':verdicts(cases),
        'privacy':'Counts and run IDs only; no addresses, ports, payloads or messages.'}
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    text=markdown(result);(OUT/'SUMMARY.md').write_text(text,encoding='utf-8',newline='\n')
    print(text);print('Saved',OUT/'summary.json')


if __name__=='__main__':main()
