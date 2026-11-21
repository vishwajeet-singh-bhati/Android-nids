"""Extend the report using frozen aggregate evidence; no model or phone actions."""
from datetime import datetime, timezone, timedelta
import hashlib
import json
import re
from pathlib import Path

FILES={
    'trial':'augmented_v1_phone_trial/results.json',
    'web_review':'augmented_manual_review_20261121/summary.json',
    'protocol':'protocol_phone_tests/COMPLETED_REVIEW.json',
    'performance':'performance_v1/comparison.json',
    'guidance':'forgesight_pr_review/release_summary.json',
    'warmup':'forgesight_pr_review/warmup_comparison.json',
    'deployment':'false_positive_audit_20261121/deployment.json',
    'idle':'false_positive_audit_20261121/initial_idle_audit.json',
    'normal':'false_positive_audit_20261121/benign_case_audit.json',
    'later_normal':'false_positive_audit_20261121/later_benign_case_audit.json',
    'password':'false_positive_audit_20261121/password_case_audit.json',
    'checkpoints':'false_positive_audit_20261121/frozen_checkpoint_regression.json',
    'passive':'false_positive_audit_20261121/passive_code40.json',
    'web_control':'false_positive_audit_20261121/benign_web_code40.json',
}


def update(root):
    path=root/'docs/project_report/REPORT_EVIDENCE.json'
    data=json.loads(path.read_text(encoding='utf-8'));current={}
    for key,name in FILES.items():
        source=root/'validation/reports'/name
        current[key]=json.loads(source.read_text(encoding='utf-8'))
        relative=source.relative_to(root).as_posix()
        data['source_files']=[v for v in data['source_files'] if v['path']!=relative]
        data['source_files'].append({'path':relative,'sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
    data['current_release']=current
    data['as_of_ist']=datetime.now(timezone(timedelta(hours=5,minutes=30))).isoformat()
    data['legacy_v5_rows']=[]
    for line in (root/'runs/robust_v5/COMPARISON.md').read_text(encoding='utf-8').splitlines():
        if line.startswith('| shortflow_') or line.startswith('| behavior_'):
            data['legacy_v5_rows'].append([c.strip() for c in line.split('|')[1:-1]])
    path.write_text(json.dumps(data,indent=2,allow_nan=False)+'\n',encoding='utf-8',newline='\n')


def render(data,table,esc,pct):
    c=data['current_release']
    protocol=table(['Case','Primary flags','Correct family','Visible groups'],[
        [esc(v['profile']),f"{v['primary']['flagged']}/{v['primary']['connections']}",
         '--' if v['correctly_typed_primary'] is None else str(v['correctly_typed_primary']),str(v['visible_notification_groups_at_snapshot'])]
        for v in c['protocol']['cases']],r'p{0.27\textwidth}rrr')
    regress=table(['Frozen checkpoint','Normal flags /118','Attack flags /268'],[
        [esc(name),str(v['normal_flags']),str(v['attack_flags'])] for name,v in c['checkpoints']['candidates'].items()],r'p{0.41\textwidth}rr')
    text=r'''
\chapter{Stage 7: experimental deployment and real protocol testing}
\section{From an offline candidate to a controlled phone trial}
The completed evaluation above was a frozen comparison, not a production release. The user later explicitly requested deployment of the available model for testing. After export/parity and 21 native self-checks, app code37 installed the augmented \code{gate_s0_final} and \code{diagnosis_s1_best}. Its scientific readiness decision remained false. Codes38--40 retained these exact detector weights; the later changes concern explanations, ownership and network scope. A trial installation must not be described as passing the failed false-positive criterion.

The current gate still receives 32 flow plus 115 context/protocol values. Its architecture is the same 147--96--48--1 MLP (18,913 parameters). The diagnosis retains convolution, recurrent attention, fusion and context branches (173,721 parameters). Current gate/type cutoffs are 0.5408333333333333/0.8. Gate-negative traffic skips diagnosis and Llama. Gate-positive traffic receives an estimated family only when the diagnosis supports a non-Benign class above its cutoff; otherwise it remains Unclassified. A normal connection can therefore be falsely flagged even when diagnosis says Benign.

\section{What the updated model detected in bounded HTTP tests}
The first normal eight-request control stayed quiet. The fast scan later produced 510 flags over 512 native segments; its 129 TCP connection attempts are a different denominator. The slower scan's rotated-log recovery retained 122 flags over 124 native segments and 31/32 attempted connections flagged. These are same-phone development findings, not general scan recall.

An independently audited eight-case subset contains 325 native segments and 3,248 packets, with all 147 inputs finite and packet/start-time accounting verified. Among 35 verified Web request attempts/effects, 22 were binary flagged and nine correctly typed Web; two embedded normal controls were quiet. HTTP guessing produced detections, but one SQL form was missed, XSS changed between attempts, and the two-slot capacity test remained quiet. Several early cases shared recent history; this prevents attributing every output change solely to a model improvement.

\section{The separate protocol lab and three-source arrangement}
ProtocolLab uses actual FTP and SSH authentication against invented accounts; SSH has no shell, executable command service, file-transfer subsystem or forwarding. Wrong and valid single-login controls are recorded separately from 32-attempt guessing episodes. The restricted Bot emulator exchanges only PING/STATUS and PONG/LAB-OK; it cannot execute arbitrary commands. Its receiver is a configured owned PC.

DoS uses at most 96 requests and six workers against a dummy service with two resource slots. DDoS uses the controller and two additional physical PCs, 32 requests/two workers each, with three distinct phone-visible source addresses and overlapping intervals. Denial affects only the disposable service; it does not establish volumetric network saturation or general Internet DDoS coverage. Independent ordinary probes measure service availability and recovery.

Unlike the old filtered companion captures, these protocol cases capture the full phone-visible warm-up at snaplen768. Each command warms 305 seconds and observes130 seconds, with no next profile scheduled. A failed warm-up reached an inherited100,000-packet cap before an attack started; it remains an incomplete attempt. The corrected manual controller permits2,000,000 packets and requires2GiB free on both endpoints, detects capture death promptly and avoids attaching stale previous-session target events. Dataset collection's original cap is a separate policy.

\section{Completed seven-case protocol sequence}
''' + protocol + r'''
The primary denominator is32 authentication attempts,12 completed emulator exchanges, or96 actual load requests. Ordinary availability probes and the emulator trigger are excluded from attack counts. The two Benign rows are separate initial/final controls. Their combined7/18 false flags are unacceptable negative-control findings, not a representative daily false-positive-rate estimate.

FTP flagged29/32 but never named Brute Force. SSH flagged32/32, with only6 correctly typed Brute Force. The emulator missed all12 exchanges. DoS flagged18/96 load requests, all Unknown; its console19/139 also includes one of43 probes. DDoS flagged0/96 load requests; the console1/143 is one of47 probes, not a detected distributed request. Target evidence confirms36/38 unavailable probes and78/76 resource denials for DoS/DDoS, followed by recovery. All377 matched connections and4,270 packets passed the saved-evidence re-audit. These findings expose actual classifier limitations after working transport/capture, rather than converting setup success into detection success.

\chapter{Stage 8: measured inference work and the deployed explanation pipeline}
\section{What ExecuTorch does here}
ExecuTorch is already the on-device inference runtime, using CPU/XNNPACK for the small PTE classifiers and an isolated persistent process for the1B SpinQuant INT4 Llama. Desktop PyTorch training, model export and Android execution are distinct steps. Llama is downstream of detection: a good explanation cannot repair a missed attack or a false binary flag.

\section{Detector optimization and E8 findings}
The paired frozen-weight detector study measured median1.583ms for the original graph versus1.182ms for a hoisted FP32 LSTM graph, a25.3\% reduction. Each variant had5,040 calls across three alternating blocks. CPU work per block fell2,192ms to1,755ms; diagnosis PTE size949,788 to921,116bytes. There were zero decision changes on1,125 validation diagnostic rows and2,351 previously saved phone inputs. The optimization was retained as an experiment and was not promoted into code40; preserving the trained function also preserves its false alarms and misses.

The user's E8 scripts supplied useful implementation ideas, but their packed BERT encoder kernels are not a drop-in autoregressive Llama backend. FP32-reconstructed E8 post-training approximations changed278/1,125 gate decisions and655/577 diagnosis decisions for the two tested reconstructions. They were rejected before deployment; no packed2-bit Android speedup or quantization-aware training claim is made. A smaller135M explanation model was also tested and rejected for unreliable advice/prompt echoes despite shorter latency.

\section{Fair timing comparisons}
Old full-note production-worker requests with monitoring active had cold/warm medians54.605/38.254seconds (three each), with no generated drafts accepted. A matched direct component comparison with capture paused and four requested threads reduced warm generation21.053 to3.888seconds by keeping facts deterministic and generating only guidance. This81.5\% component reduction must not be presented as the same experiment as production-worker timing. A later plain-wording component trial measured3.247seconds warm; it was a separate session.

Resource measurements include process CPU, RSS/PSS, available RAM, GPU counters where readable, battery and thermal readings. CPU counters are process-specific; battery/temperature cover the phone and cannot be attributed wholly to inference. The CPU backend has no separately measured model VRAM allocation; unavailable GPU counters are not zero usage. The1B model occupies1,135,951,488bytes plus a2,183,982-byte tokenizer; component tests showed roughly1.2GiB resident PSS. Instrumentation/all-process measurements and resident versus swapped memory must remain distinguished. Detailed sampled metrics and confounds are retained in the aggregate performance report.

\section{Immediate facts, then checked local Llama guidance}
Codes38/39 render an immediate factual note: observed connection pattern, verified receiving/initiating app when available, peer/phone endpoint role, packet count/duration, incomplete-history/capture warnings, and a manual precaution. Llama adds one short plain-language guidance sentence. The full visible note is more detailed than that one generated sentence. A receiving app is not blamed as the attack source, and an unknown or ambiguous owner is never replaced by an invented name.

The worker verifies model/tokenizer identities, loads once, resets generation context for every activity, and releases its warm model after about120 idle seconds. Late drafts are rejected when an activity revision changes or is dismissed. A generation failure, truncation, invented app/count/cause, or unsafe/irrelevant advice leaves the checked default guidance in place. The Android1.5.1 overload was found to omit the configured maximum-new-token dispatch; a conservative forwarded-callback stop guard now bounds text. Callback framing differs from native token accounting, so an exact-token guarantee is not claimed.

Code39's actual production IPC fixtures, with monitoring active, measured14.047seconds for one cold request and warm median3.690seconds (range3.221--4.021, seven requests). Seven of eight guidance drafts were accepted; one Web draft retained default advice. A labelled temporary TEST notification verified factual content before Llama in9ms and was removed; this is post/query time, not packet-to-alert latency. Capture drops were zero. These are eight fixtures across seven categories, not a human readability study or new attack-accuracy evidence.

ForgeSight PR5's persistent-worker approach was already present. PR17-inspired one-token boot warming was tested in three component pairs: ready request3.048seconds plus preparation10.202seconds; total median13.092seconds versus12.794seconds cold. It shifts the wait earlier without a proven total-time gain and remains disabled. No remote PR scripts were executed as part of the review.

\section{Simple dry run of the current user-facing flow}
A connection summary first passes the network-scope check, then normalization and the gate. If the gate is negative, there is no incident and no Llama call. If positive, diagnosis may name a family or leave it Unclassified; the factual note appears without waiting for Llama. For an incoming connection whose socket owner is a lab app, the note says that app received the traffic; it does not claim that app originated the attack. Llama may add ``Check recent account activity and review unexpected repeated connections.'' The advice never becomes ground truth or an automatic training label. AppendixC retains a complete invented numeric input and executed current-model output, solely as a software walkthrough.

\chapter{Stage 9: ordinary traffic, recurring idle alerts and code40}
\section{Two different false-alarm problems}
Nine new flags in the saved idle-session tail had both endpoints on127.0.0.1. They were real new flags and activity IDs, not an old notification being replayed. The producing app was not verified. A repeated loopback port alone cannot establish malware, the exact service, or safety.

The separate normal protocol case at20:16 had4/9 false flags: ordinary wrong/valid SSH logins and two normal HTTP probes. Both FTP controls were quiet. A later user-launched normal protocol case at22:59 had2/9 flags, both SSH; all five HTTP probes and both FTP controls were quiet. One grouped note accepted local Llama guidance, which does not make its underlying false positive correct. Different traffic histories and packet values prevent calling4\textrightarrow2 a causal accuracy gain from code40. The later case was re-audited offline only; reporting started no new phone traffic.

The separate saved HTTP guessing case flagged21 of31 failed dummy guesses: seven Web and14Unknown, with ten misses; its successful-login control stayed quiet. All21 flags match the recorded traffic. Detection, correct family, app attribution, grouping and explanation acceptance are five different outcomes.

\section{What code40 changed and what it did not solve}
Code40 observes/counts both-endpoint loopback separately and excludes it from default external-network model assessment. Device settings show the scope and an experimental local-alert opt-in. This is an explicit coverage change, not learning that loopback is benign: malicious on-device loopback traffic is also outside default model alerts. LAN/external connections, even to the same port numbers, remain scored. No app/port allowlist or threshold increase was added.

All104 original activity IDs and raw evidence survived installation. Fifty-seven old loopback activities were moved outside Active/automatic explanations/notifications while retaining the original model assessment in seven-day history. External records remained unchanged; SQLite integrity passed. Source-hashed fixtures verify local-history idempotence, stale-result rejection, and bit-identical147 external features when loopback traffic is interleaved. Ownership parsing now rejects TIME\_WAIT/inode-zero kernel entries without rejecting real UID0 sockets with a positive inode. The exact cause of each old root attribution remains unproven.

A new code40 normal HTTP control completed8/8 requests,80packets/eightTCPtuples and eight target events, with zero flags/new activities/notifications. At the recorded714-second post-install inspection,11local summaries were counted separately,159external checks had run, and capture counters were healthy with zero flags. That short window includes the normal web control; it cannot establish zero everyday false positives. The subsequent SSH failure above remains a documented counterexample.

\section{Frozen candidate regression and rejected shortcuts}
Eight already examined protocol cases supplied386 matched development connections, including118normal controls/probes and268attack attempts/exchanges. Probes affected by dummy-service capacity are not attack requests. Six frozen checkpoints were replayed at the unchanged cutoff; this is development diagnosis, not an independent selection benchmark:
''' + regress + r'''
None eliminates false positives. The installed seed0final has the fewest normal flags in this particular cohort, not demonstrated universal superiority. CPU/native probability difference was at most4.590e-6. Masking SSH/FTP indicators reduces normal flags13 to11 but attack flags79 to48; that shortcut was rejected and never installed. Raising a cutoff also cannot cleanly separate normal SSH examples already scoring1.0.

The actual training rows with positive SSH indicators comprise7,322Benign and4,096BruteForce; FTP indicators comprise3,490Benign and3,736BruteForce. Thus the cause is not a total absence of benign protocol training data. Some normal protocol examples have standardized rare indicators around13.8, which alone does not prove a scaling bug. The phone-specific extension contains848unique HTTP/web training segments and no modern phone FTP/SSH control cohort. A protocol/context distribution gap and poor generalization are plausible; exact causal contributions have not been isolated.

\section{What is needed for a genuine detector repair}
Collect independently labelled normal sessions with successful logins, occasional ordinary mistakes, browsing/downloads/background services and legitimate bursts, varying apps/rates/sizes. Background traffic is not automatically declared safe. Retain verified attack sessions and all original-class evaluations. Allocate fresh sessions/devices/days before prediction inspection, keep their300-second contexts disjoint, fit preprocessing/selection on training/validation only, and reserve a genuinely untouched final cohort. Preserve all40epoch checkpoints, compare classwise attack recall and precision plus false notifications per hour, and reject repairs with unacceptable class regressions. No such additional repair has been trained or promoted in code40. Ordinary-use readiness remains unproven.
'''
    codes=[]
    def protect(match):
        codes.append(match.group(0))
        return '@CODE'+chr(65+len(codes)-1)+'@'
    text=re.sub(r'\\code\{[^}]*\}',protect,text)
    text=re.sub(r'(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])',' ',text)
    for i,code in enumerate(codes):text=text.replace('@CODE'+chr(65+i)+'@',code)
    return text


if __name__=='__main__':update(Path(__file__).resolve().parents[2])
