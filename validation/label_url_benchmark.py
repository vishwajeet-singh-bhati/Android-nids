"""Evidence labels from exact URL matches in public phishing feeds; no benign inference."""
from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
from pathlib import Path
import time
import urllib.request

FEEDS = {
    'openphish': ('https://openphish.com/feed.txt', 'openphish.txt'),
    'phishtank': ('https://data.phishtank.com/data/online-valid.json.bz2', 'phishtank.json.bz2'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fetch', action='store_true', help='Download one current copy of each public feed. Never visits benchmark URLs.')
    args = parser.parse_args()
    directory = args.output
    evidence = directory / 'label_evidence'
    evidence.mkdir(parents=True, exist_ok=True)
    if args.fetch:
        fetch = {}
        for name, (url, filename) in FEEDS.items():
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'phishtank/rakshak-local-research'})
                with urllib.request.urlopen(request, timeout=45) as response:
                    data = response.read(100 * 1024 * 1024 + 1)
                    if len(data) > 100 * 1024 * 1024:
                        raise ValueError('Feed exceeds size limit')
                (evidence / filename).write_bytes(data)
                fetch[name] = dict(url=url, status='downloaded', bytes=len(data),
                                   sha256=hashlib.sha256(data).hexdigest(), retrieved_unix=time.time())
            except Exception as error:
                fetch[name] = dict(url=url, status='failed', error=str(error))
        (evidence / 'fetch.json').write_text(json.dumps(fetch, indent=2) + '\n', encoding='utf-8')
    fetch = json.loads((evidence / 'fetch.json').read_text(encoding='utf-8'))
    positive = {}
    feed_counts = {}
    for name, (_, filename) in FEEDS.items():
        if fetch.get(name, {}).get('status') != 'downloaded':
            continue
        data = (evidence / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != fetch[name]['sha256']:
            raise ValueError('Feed hash does not match saved provenance')
        if name == 'phishtank':
            records = json.loads(bz2.decompress(data))
            entries = [(r['url'], str(r['phish_id'])) for r in records
                       if r.get('verified') == 'yes' and r.get('online') == 'yes']
        else:
            entries = [(u.strip(), '') for u in data.decode('utf-8-sig').splitlines() if u.strip()]
        feed_counts[name] = len(entries)
        for url, identifier in entries:
            positive.setdefault(url, []).append((name, identifier))
    raw = args.input.read_bytes()
    rows = []
    for i, line in enumerate(raw.decode('utf-8-sig').splitlines(), 1):
        url = line.strip()
        if not url:
            continue
        matches = positive.get(url, [])
        rows.append(dict(line=i, url_sha256=hashlib.sha256(url.encode()).hexdigest(),
                         label='phishing' if matches else 'unknown',
                         source='; '.join(name + ': exact URL match' for name, _ in matches),
                         phish_id='; '.join(identifier for _, identifier in matches if identifier)))
    with (directory / 'labels.csv').open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=['line', 'url_sha256', 'label', 'source', 'phish_id'])
        writer.writeheader(); writer.writerows(rows)
    known = sum(r['label'] == 'phishing' for r in rows)
    report = dict(input_sha256=hashlib.sha256(raw).hexdigest(), rows=len(rows), feed_records=feed_counts,
                  exact_feed_confirmed_phishing=known, independently_confirmed_benign=0, unknown=len(rows) - known,
                  label_coverage=known / len(rows) if rows else 0,
                  limitation='No match is UNKNOWN, never benign. Feed matches may overlap the detector threat database; do not call its list-hit rate independent model accuracy.')
    (directory / 'label_summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
