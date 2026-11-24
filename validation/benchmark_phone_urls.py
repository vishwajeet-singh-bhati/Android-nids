"""Sequential on-device URL checks. No websites are opened or labels invented."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import time


def binary_metrics(labels, predicted):
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predicted))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predicted))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predicted))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predicted))
    def ratio(a, b):
        return a / b if b else None
    sensitivity, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    result = dict(n=len(labels), tp=tp, fp=fp, tn=tn, fn=fn,
                accuracy=ratio(tp + tn, len(labels)), precision=ratio(tp, tp + fp),
                recall=sensitivity, specificity=specificity,
                f1=ratio(2 * tp, 2 * tp + fp + fn), false_positive_rate=ratio(fp, fp + tn),
                false_negative_rate=ratio(fn, fn + tp), negative_predictive_value=ratio(tn, tn + fn),
                balanced_accuracy=(sensitivity + specificity) / 2 if sensitivity is not None and specificity is not None else None,
                mcc=ratio(tp * tn - fp * fn, math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))))
    if len(set(labels)) < 2:
        for key in ['accuracy', 'precision', 'f1', 'balanced_accuracy', 'mcc', 'negative_predictive_value']:
            result[key] = None
        result['limitation'] = 'Single-class labeled subset: no overall accuracy, precision or F1 estimate. Recall refers only to the known-positive subset.'
    return result


def summarize(rows, labels=None):
    from collections import Counter
    latencies = sorted(r['elapsed_ms'] for r in rows)
    summary = dict(rows=len(rows), decisions=dict(Counter(r['result'].get('decision') for r in rows)),
                   sources=dict(Counter(r['result'].get('source') for r in rows)),
                   errors=sum(bool(r['result'].get('error')) or r['result'].get('model_status') == 'failed' for r in rows),
                   timing_ms=dict(first=rows[0]['elapsed_ms'] if rows else None,
                                  mean=statistics.mean(latencies) if latencies else None,
                                  median=statistics.median(latencies) if latencies else None,
                                  p95=latencies[math.ceil(.95 * len(latencies)) - 1] if latencies else None,
                                  total=sum(latencies)))
    summary['ground_truth_rows'] = len(labels or {})
    summary['metrics'] = None
    if labels:
        eligible = [r for r in rows if r['id'] in labels and r['result'].get('decision') in {'PHISHING', 'LIKELY_SAFE', 'UNCERTAIN'}
                    and not r['result'].get('error') and r['result'].get('model_status') != 'failed']
        selective = [r for r in eligible if r['result']['decision'] != 'UNCERTAIN']
        summary['metrics'] = dict(
            phishing_detection=binary_metrics([labels[r['id']] for r in eligible], [int(r['result']['decision'] == 'PHISHING') for r in eligible]),
            decisive_only=binary_metrics([labels[r['id']] for r in selective], [int(r['result']['decision'] == 'PHISHING') for r in selective]),
            scored_coverage=len(eligible) / len(labels), decisive_coverage=len(selective) / len(labels),
            interpretation='Primary: UNCERTAIN counts as not detected. Selective: exclude UNCERTAIN and disclose coverage. Errors excluded and reported separately. Labels must have independent provenance.')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--serial', required=True)
    p.add_argument('--adb', default='adb')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--labels', type=Path, help='Independent CSV with line,label (phishing/benign).')
    p.add_argument('--rescore', action='store_true', help='Only rescore saved results after labels become available.')
    p.add_argument('--force-model', action='store_true', help='Diagnostic pass: score even URLs normally decided by a rule/list. Not production latency.')
    args = p.parse_args()
    directory = args.output
    directory.mkdir(parents=True, exist_ok=True)
    raw = args.input.read_bytes()
    urls = [(i, line.strip()) for i, line in enumerate(raw.decode('utf-8-sig').splitlines(), 1) if line.strip()]
    adb = [args.adb, '-s', args.serial]
    def command(*parts, **kw):
        return subprocess.run(adb + list(parts), capture_output=True, check=True, **kw).stdout
    if not args.rescore:
        (directory / 'input_snapshot.txt').write_bytes(raw)
        payload = ''.join(json.dumps(dict(id=i, url=url), ensure_ascii=True) + '\n' for i, url in urls).encode()
        command('shell', 'run-as', 'nids.app', 'tee', 'files/url_benchmark_input.jsonl', input=payload)
        print(f'Starting {len(urls)} sequential checks; no website requests.', flush=True)
        try:
            mode = 'rakshak_url_benchmark_raw' if args.force_model else 'rakshak_url_benchmark'
            run = subprocess.run(adb + ['shell', 'am', 'instrument', '-w', '-e', 'mode', mode,
                                 'nids.app.test/nids.app.ValidationInstrumentation'], capture_output=True, timeout=3600)
            (directory / 'instrumentation.log').write_bytes(run.stdout + run.stderr)
            run.check_returncode()
            report = command('exec-out', 'run-as', 'nids.app', 'cat', 'files/rakshak_validation/' + mode + '.json')
            native = json.loads(report)
            if not native.get('passed'):
                raise RuntimeError(str(native))
            (directory / 'native_summary.json').write_bytes(report)
            results = command('exec-out', 'run-as', 'nids.app', 'cat', 'files/rakshak_validation/url_benchmark_results.jsonl')
            (directory / 'results.jsonl').write_bytes(results)
            command('shell', 'run-as', 'nids.app', 'rm', '-f',
                    'files/rakshak_validation/url_benchmark_results.jsonl',
                    'files/rakshak_validation/url_benchmark_progress.json')
        finally:
            command('shell', 'run-as', 'nids.app', 'rm', '-f', 'files/url_benchmark_input.jsonl')
    rows = [json.loads(s) for s in (directory / 'results.jsonl').read_text(encoding='utf-8').splitlines() if s.strip()]
    if [r['id'] for r in rows] != [i for i, _ in urls]:
        raise RuntimeError('Result IDs/order do not match input lines.')
    labels = {}
    if args.labels:
        with args.labels.open(encoding='utf-8-sig', newline='') as f:
            for row in csv.DictReader(f):
                value = row['label'].strip().lower()
                if value in {'phishing', 'benign'}:
                    i = int(row['line'])
                    if i not in dict(urls) or i in labels:
                        raise ValueError('Unknown/duplicate label line.')
                    labels[i] = int(value == 'phishing')
    summary = summarize(rows, labels)
    raw_rows = [dict(row, result=dict(row['result'], decision=row['result'].get('model_outcome')))
                for row in rows if row['result'].get('model_outcome')]
    if raw_rows:
        summary['raw_model_analysis'] = summarize(raw_rows, {i: y for i, y in labels.items() if i in {r['id'] for r in raw_rows}})
    summary.update(input_sha256=hashlib.sha256(raw).hexdigest(), created_unix=time.time(),
                   unique_input_urls=len(set(url for _, url in urls)),
                   limitation='No accuracy/precision/recall without independent ground-truth labels. Counts are not accuracy.')
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    with (directory / 'results.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['line', 'url', 'label', 'decision', 'score', 'source', 'model_status', 'elapsed_ms', 'error'])
        by_id = dict(urls)
        for row in rows:
            r = row['result']; y = labels.get(row['id'])
            w.writerow([row['id'], by_id[row['id']], '' if y is None else ('phishing' if y else 'benign'), r.get('decision'),
                        r.get('risk_score'), r.get('source'), r.get('model_status'), row['elapsed_ms'], r.get('error')])
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
