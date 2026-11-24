"""Build a local URL lookup asset; never redistributes or visits feed URLs."""
from __future__ import annotations

import argparse
import ast
import bz2
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True, help='Explicit Android URL asset directory to update.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--empty', action='store_true', help='Build the distributable, empty/stale public database.')
    group.add_argument('--phishtank', type=Path, help='Your permitted online-valid JSON or JSON.bz2 snapshot.')
    group.add_argument('--download-phishtank', action='store_true', help='Fetch one public snapshot for local evaluation.')
    args = parser.parse_args()
    assets = args.assets.resolve()
    manifest_path = assets / 'MANIFEST.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    source = ROOT / 'components/phishing_url/python'
    tree = ast.parse((source / 'src/intelligence/local_database.py').read_text(encoding='utf-8'))
    schema = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == '_SCHEMA' for t in n.targets))
    snapshot = args.phishtank
    if args.download_phishtank:
        snapshot = ROOT / 'runs/runtime_feeds/online-valid.json.bz2'
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request('https://data.phishtank.com/data/online-valid.json.bz2',
                                        headers={'User-Agent': 'phishtank/rakshak-local-research'})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(100 * 1024 * 1024 + 1)
        if len(data) > 100 * 1024 * 1024:
            raise ValueError('Feed exceeds size limit')
        snapshot.write_bytes(data)
    temporary = assets / 'threat_intel.sqlite3.tmp'
    temporary.unlink(missing_ok=True)
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    rows = 0
    with closing(sqlite3.connect(temporary)) as db:
        db.executescript(schema)
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('schema_version', '1'))
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                   ('feeds_updated_at', '1970-01-01T00:00:00Z' if args.empty else stamp))
        if snapshot:
            sys.path.insert(0, str(source))
            from src.preprocessing.url_normalizer import normalize_url, private_registered_domain, InvalidURLError
            raw = snapshot.read_bytes()
            entries = json.loads(bz2.decompress(raw) if snapshot.suffix == '.bz2' else raw)
            popular = set((assets / 'popular.txt').read_text(encoding='utf-8').splitlines())
            redirectors = set((assets / 'redirectors.txt').read_text(encoding='utf-8').splitlines())
            expiry = (now + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
            for entry in entries:
                if entry.get('verified') != 'yes' or entry.get('online') != 'yes':
                    continue
                try:
                    n = normalize_url(entry['url'])
                    site = private_registered_domain(n.host)
                except (InvalidURLError, ValueError):
                    continue
                host_match = site not in popular and not {n.host, n.registered_domain, site} & redirectors
                db.execute('INSERT OR REPLACE INTO indicators VALUES (?,?,?,?,?,?,?,?,?)',
                           (n.model_string, n.host, site, int(host_match), 'phishtank', str(entry['phish_id']), stamp, stamp, expiry))
            rows = db.execute('SELECT COUNT(*) FROM indicators').fetchone()[0]
        db.commit()
    target = assets / 'threat_intel.sqlite3'
    temporary.replace(target)
    manifest['files']['threat_intel.sqlite3'] = dict(sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                                                    bytes=target.stat().st_size)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(rows=rows, empty_public_snapshot=args.empty, asset=str(target),
                         downloaded_urls_visited=0, redistribution='No feed snapshot should be committed or uploaded.')))


if __name__ == '__main__':
    main()
