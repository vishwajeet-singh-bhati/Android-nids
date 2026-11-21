"""Audit saved manual protocol cases on the PC; never starts phone/SSH traffic."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path

import protocol_phone_test as lab

CASE_IDS=(
    '20261121_161452_Benign_9641f2','20261121_163023_FTPBruteForce_8c74df',
    '20261121_163908_SSHBruteForce_737391','20261121_164814_BotBehavior_368522',
    '20261121_171054_DoS_014602','20261121_171906_DDoS_a4333b','20261121_172724_Benign_fea5e0',
)


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def counts(rows):
    return {'connections':len(rows),'flagged':sum(r['flagged'] for r in rows),
            'class_counts':dict(Counter(lab.NAMES[r['class_id']] for r in rows))}


def audit(case):
    read=lambda name:json.loads((case/name).read_text(encoding='utf-8'))
    review,meta,quality,events=map(read,('review.json','run.json','capture_quality.json','target_events.json'))
    assert meta['session']==read('target_status.json')['session']==review['run_id']==case.name
    assert review['model_sha256']==lab.EXPECTED
    assert quality['kernel_drops']==0 and not quality['ended_early']
    assert digest(case/'capture.pcap')==quality['capture_sha256']
    contract=meta['contract'];phone=contract['phone'];profile=review['profile']
    packets=lab.packet_tuples(case/'capture.pcap',phone,set(contract['allowed_sources']))
    trace=lab.lab.json_lines((case/'native.jsonl').read_text(encoding='utf-8'))
    assert len(trace)<2000
    rows=[];by_key=defaultdict(list);packet_counts=Counter();maximum_error=0
    for row in trace:
        key=lab.key(row['protocol'],(row['source'],row['sport']),(row['destination'],row['dport']))
        if key not in packets:continue
        assert len(row['flow'])==32 and len(row['context'])==115
        assert all(math.isfinite(x) for x in row['flow']+row['context'])
        assert row['flagged']==(row['gate_score']>=.5408333333333333)==(row['class_id']!=0)
        packet_counts[key]+=int(row['flow'][1]+row['flow'][2])
        maximum_error=max(maximum_error,min(abs(row['start']-t) for t in packets[key]))
        rows.append(row);by_key[key].append(row)
    assert packet_counts==Counter({k:len(v) for k,v in packets.items()}) and maximum_error<=1e-6
    assert len(rows)==review['native_segments'] and sum(r['flagged'] for r in rows)==review['flagged_segments']
    assert dict(Counter(lab.NAMES[r['class_id']] for r in rows))==review['classification_counts']
    # Every connection in these saved cases has exactly one native segment.
    # Stop rather than silently equating these denominators for future cases.
    assert all(len(values)==1 for values in by_key.values())
    roles=defaultdict(list);event_keys=set()
    for event in events:
        if 'peer' not in event:continue
        key=lab.key(6,(phone,event['local_port']),(event['peer'],event['peer_port']))
        assert key in by_key and key not in event_keys
        event_keys.add(key);roles[event['event']].append(by_key[key][0])
    assert event_keys==set(packets)
    if profile=='Benign':
        primary=rows;expected=None
        for name in ('ftp_login_failure','ftp_login_success','ssh_login_failure','ssh_login_success'):assert len(roles[name])==1
        assert len(roles['probe_available'])==5
    elif profile in ('FTPBruteForce','SSHBruteForce'):
        name='ftp_login_failure' if profile.startswith('FTP') else 'ssh_login_failure'
        primary=roles[name];expected='Brute Force';assert len(primary)==32
    elif profile=='BotBehavior':
        primary=roles['bot_exchange'];expected='Bot'
        assert len(primary)==12 and len(roles['bot_trigger'])==1
        receiver=read('receiver.json')
        assert not receiver['error'] and len(receiver['rows'])==12
        assert all(r['reply']==('PONG' if r['command']=='PING' else 'LAB-OK') for r in receiver['rows'])
    else:
        assert profile in ('DoS','DDoS')
        primary=roles['resource_held']+roles['resource_denied'];expected=profile
        effects=read('effects.json');source_keys=set()
        for source in effects['sources']:
            for r in source['rows']:
                assert not r['error'] and r['http_status'] in (200,503)
                source_keys.add(lab.key(6,(r['source'],r['sport']),(r['destination'],r['dport'])))
        target_events=[e for e in events if e['event'].startswith('resource_')]
        target_keys={lab.key(6,(phone,e['local_port']),(e['peer'],e['peer_port'])) for e in target_events}
        assert source_keys==target_keys and len(primary)==96
        peers={e['peer'] for e in target_events};assert len(peers)==(3 if profile=='DDoS' else 1)
        assert roles['probe_denied'] and roles['resource_denied']
        assert all(r['status']==200 for r in effects['baseline_probes']+effects['recovery_probes'])
        if profile=='DDoS':
            intervals=[(min(e['time_ms'] for e in target_events if e['peer']==peer),max(e['time_ms'] for e in target_events if e['peer']==peer)) for peer in peers]
            assert max(a for a,b in intervals)<min(b for a,b in intervals)
    primary_counts=counts(primary)
    return {'run_id':case.name,'profile':profile,'primary':primary_counts,'expected_family':expected,
        'correctly_typed_primary':primary_counts['class_counts'].get(expected,0) if expected else None,
        'all_test_connections':counts(rows),'by_target_event':{name:counts(values) for name,values in roles.items()},
        'matched_test_packets':sum(len(v) for v in packets.values()),'maximum_start_error_seconds':maximum_error,
        'pcap_sha256_verified':quality['capture_sha256'],'native_features_finite_and_frozen_decisions_verified':True,
        'source_effects_verified':True,'visible_notification_groups_at_snapshot':review['visible_matched_notification_groups'],
        'explanations':review['activity_groups'],'scope':'Primary counts exclude availability probes and the emulator trigger; normal controls are separate.'}


def main():
    # Freeze this completed sequence. Later retries must not silently replace or
    # inflate this report's denominators.
    cases=[audit(lab.RUN/'cases'/name) for name in CASE_IDS]
    assert all(g['explanation_status']=='complete' and g['display_source']=='evidence_based_fallback'
        and g['generated_text_accepted'] is False for c in cases for g in c['explanations'])
    result={'cases':cases,'completed_cases':len(cases),'matched_test_connections':sum(c['all_test_connections']['connections'] for c in cases),
        'matched_test_packets':sum(c['matched_test_packets'] for c in cases),'all_checks_passed':True,
        'model_sha256':lab.EXPECTED,'phone_or_remote_actions':0,
        'limits':'Small controlled development runs. BotBehavior is a restricted emulator; DoS/DDoS affect only the disposable application resource. No general class recall or everyday false-positive estimate.'}
    lab.lab.save(lab.PUBLIC/'COMPLETED_REVIEW.json',result)
    lines=['# Completed manual protocol tests - 21 November 2026','',
        'Seven completed manual cases; the earlier HTTP-controller and capture-limit failures remain separate incomplete attempts. Frozen NIDS models and cutoffs were unchanged. No additional phone traffic, training or retuning during this review.','',
        '| Case | Primary connections flagged | Correct family assigned | Visible notification groups* |',
        '|---|---:|---:|---:|']
    for c in cases:
        primary=c['primary'];typed=str(c['correctly_typed_primary']) if c['expected_family'] else 'Normal control'
        lines.append(f"| {c['profile']} | {primary['flagged']}/{primary['connections']} | {typed} | {c['visible_notification_groups_at_snapshot']} |")
    lines+=['','Primary counts use 96 load requests per DoS/DDoS case, 12 emulator exchanges, and 32 login attempts per guessing case. Availability probes and the emulator trigger are excluded from those primary denominators. Each matched connection has one native segment in these particular cases.','',
        '*Notification counts are visible groups in each saved snapshot, not individual model decisions or proof of every notification ever posted.','',
        'The DoS console total was 19/139: 18/96 load requests and 1/43 probes flagged. The DDoS console total was 1/143: 0/96 load requests and 1/47 probes flagged. Neither case received a DoS/DDoS family diagnosis. The single DDoS flag must not be reported as detection of a load request.','',
        'Independent target evidence confirms resource denial and recovery: DoS denied 36 availability probes and 78 resource requests; DDoS denied 38 probes and 76 requests. DDoS used three distinct phone-visible source IPs with overlapping intervals. This is application-resource denial, not a volumetric network flood.','',
        'Normal controls falsely flagged 3/9 and 4/9 connections (7/18 total). All four successful FTP/SSH control logins were flagged; ordinary wrong-password controls contributed three flags; all ten normal HTTP probes stayed quiet. This tiny protocol-specific sample is not an everyday false-positive-rate estimate.','',
        'FTP flagged 29/32 attempts, all Unclassified. SSH flagged 32/32, but only 6/32 received Brute Force; 26 were Unclassified. All 12 restricted emulator exchanges stayed Benign, which does not establish general real-malware recall.','',
        'Matched activity explanations completed through evidence-based fallback; no generated draft was accepted. Do not describe these displayed summaries as accepted Llama generations.','',
        'The pipeline needs improvement before normal-use deployment: benign authentication false positives, missed distributed load/emulator behavior and weak family classification remain. These completed checks establish the test plumbing and expose model limitations.','',
        f"PC-only re-audit passed: {result['matched_test_connections']} matched connections/native segments, {result['matched_test_packets']} packets, exact per-connection packet counts/start timestamps, finite 147-feature inputs, frozen binary decisions, PCAP hashes and target-event matching. Raw/private captures and endpoint records remain under ignored runs; aggregates are versioned.",'',
        'Re-run this saved-evidence review (no phone required): `python validation/review_protocol_results.py`. Detailed role partitions and evidence hashes: [COMPLETED_REVIEW.json](COMPLETED_REVIEW.json).','']
    (lab.PUBLIC/'RESULTS.md').write_text('\n'.join(lines),encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))
    for c in cases:print(c['profile'],c['primary'],'correct_family',c['correctly_typed_primary'])


if __name__=='__main__':main()
