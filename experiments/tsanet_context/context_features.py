"""Label-free, interval-safe context built from a training-only history bank."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from pathlib import Path
from datetime import datetime
from collections import Counter
import json
import time
import zipfile

import numpy as np
import pandas as pd
from numba import njit
from sklearn.preprocessing import StandardScaler

from experiments.tsanet_paper.data import atomic, sha

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'data/experiments/tsanet_paper_70_30'
CACHE = ROOT / 'data/experiments/tsanet_context_v1'
WINDOWS = (120., 300., 900.)
STAT_NAMES = (
    'flows', 'out_packets', 'in_packets', 'out_bytes', 'in_bytes',
    'distinct_peers', 'distinct_remote_ports', 'distinct_local_ports',
    'no_peer_packets_fraction', 'rst_fraction', 'syn_fraction',
    'tcp_fraction', 'udp_fraction',
)
CONTEXT_NAMES = [f'{int(w)}s_{role}_{stat}' for w in WINDOWS
                 for role in ('source', 'destination') for stat in STAT_NAMES]
META = ('Source IP', 'Destination IP', 'Source Port', 'Destination Port',
        'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'SYN Flag Count', 'RST Flag Count')


def timestamp_bounds(text):
    text = str(text).strip()
    precision = 1 if text.count(':') == 2 else 60
    fmt = '%d/%m/%Y %H:%M:%S' if precision == 1 else '%d/%m/%Y %H:%M'
    value = datetime.strptime(text, fmt)
    if 1 <= value.hour <= 7:
        value = value.replace(hour=value.hour + 12)
    if not 8 <= value.hour <= 19:
        raise ValueError('Unexpected publisher clock hour: ' + text)
    seconds = value.toordinal() * 86400 + value.hour * 3600 + value.minute * 60 + value.second
    return float(seconds), float(precision), value.weekday()


@njit(cache=True)
def change_event(i, delta, hosts, measures, keys, sums, occurrences, distinct):
    host = hosts[i]
    for k in range(10):
        sums[host, k] += delta * measures[i, k]
    for k in range(3):
        key = keys[i, k]
        before = occurrences[k, key]
        after = before + delta
        occurrences[k, key] = after
        if before == 0 and after > 0:
            distinct[host, k] += 1
        elif before > 0 and after == 0:
            distinct[host, k] -= 1


@njit(cache=True)
def window_context(lower, upper, hosts, measures, keys, lower_order,
                   query_times, query_hosts, query_order, window, n_hosts):
    # Events are sorted by upper completion bound. Lower ordering is separate.
    output = np.zeros((len(query_times), 26), np.float32)
    sums = np.zeros((n_hosts, 10), np.float64)
    distinct = np.zeros((n_hosts, 3), np.int64)
    occurrences = np.zeros((3, int(keys.max()) + 1), np.int64)
    active = np.zeros(len(hosts), np.bool_)
    entered = 0
    expired = 0
    for query in query_order:
        anchor = query_times[query]
        cutoff = anchor - window
        while expired < len(lower_order) and lower[lower_order[expired]] < cutoff:
            i = lower_order[expired]
            if active[i]:
                change_event(i, -1, hosts, measures, keys, sums, occurrences, distinct)
                active[i] = False
            expired += 1
        while entered < len(hosts) and upper[entered] < anchor:
            if lower[entered] >= cutoff:
                change_event(entered, 1, hosts, measures, keys, sums, occurrences, distinct)
                active[entered] = True
            entered += 1
        for role in range(2):
            host = query_hosts[query, role]
            offset = role * 13
            count = sums[host, 0]
            for k in range(5):
                output[query, offset + k] = np.log1p(max(0., sums[host, k]))
            for k in range(3):
                output[query, offset + 5 + k] = np.log1p(distinct[host, k])
            if count > 0:
                for k in range(5):
                    output[query, offset + 8 + k] = sums[host, 5 + k] / count
    return output


def build_context(meta, train_indices, progress=None):
    bank = np.asarray(train_indices)
    source, destination = meta['source'], meta['destination']
    bank_lower, bank_upper = meta['lower'][bank], meta['upper'][bank]
    lower = np.tile(bank_lower, 2)
    upper = np.tile(bank_upper, 2)
    hosts = np.concatenate((source[bank], destination[bank]))
    peers = np.concatenate((destination[bank], source[bank]))
    local_ports = np.concatenate((meta['sport'][bank], meta['dport'][bank]))
    remote_ports = np.concatenate((meta['dport'][bank], meta['sport'][bank]))
    m = meta['measures'][bank]
    reverse = m.copy()
    reverse[:, 1:5] = m[:, [2, 1, 4, 3]]
    reverse[:, 5] = (m[:, 1] == 0)
    measures = np.concatenate((m, reverse))
    n_hosts = int(max(source.max(), destination.max())) + 1
    raw_keys = (hosts.astype(np.int64) * n_hosts + peers,
                hosts.astype(np.int64) * 65536 + remote_ports,
                hosts.astype(np.int64) * 65536 + local_ports)
    keys = np.column_stack([np.unique(k, return_inverse=True)[1] for k in raw_keys])
    order = np.argsort(upper, kind='stable')
    lower, upper, hosts = lower[order], upper[order], hosts[order]
    measures, keys = measures[order], keys[order]
    lower_order = np.argsort(lower, kind='stable')
    query_times = meta['lower']
    query_hosts = np.column_stack((source, destination))
    query_order = np.argsort(query_times, kind='stable')
    context = np.empty((len(source), len(CONTEXT_NAMES)), np.float32)
    for k, window in enumerate(WINDOWS):
        began = time.monotonic()
        context[:, k * 26:(k + 1) * 26] = window_context(
            lower, upper, hosts, measures, keys, lower_order,
            query_times, query_hosts, query_order, window, n_hosts,
        )
        if progress:
            progress(window, time.monotonic() - began)
    if not np.isfinite(context).all():
        raise RuntimeError('Nonfinite context')
    return context


def read_metadata(base, archive_path, directory):
    train_ids = np.load(base / 'train_row_id.npy')
    test_ids = np.load(base / 'test_row_id.npy')
    unsorted = np.concatenate((train_ids, test_ids))
    order = np.argsort(unsorted)
    ids = unsorted[order]
    if np.any(ids[1:] == ids[:-1]):
        raise RuntimeError('Baseline row IDs overlap')
    n = len(ids)
    columns = {name: np.empty(n, dtype=object if name in ('Source IP', 'Destination IP', 'Timestamp') else np.float64)
               for name in META}
    seen = np.zeros(n, bool)
    source_reports = []
    with zipfile.ZipFile(archive_path) as archive:
        members = sorted(v for v in archive.namelist() if v.lower().endswith('.csv'))
        for source_id, member in enumerate(members):
            offset = 0
            with archive.open(member) as stream:
                reader = pd.read_csv(stream, usecols=lambda c: c.strip() in META,
                                     chunksize=100000, encoding='utf-8-sig',
                                     encoding_errors='replace', low_memory=False)
                for chunk in reader:
                    chunk.columns = chunk.columns.str.strip()
                    row_ids = (np.uint64(source_id) << np.uint64(32)) + np.arange(offset, offset + len(chunk), dtype=np.uint64)
                    positions = np.searchsorted(ids, row_ids)
                    clipped = np.minimum(positions, n - 1)
                    selected = (positions < n) & (ids[clipped] == row_ids)
                    positions = positions[selected]
                    for name in META:
                        values = chunk.loc[selected, name]
                        if columns[name].dtype != object:
                            values = pd.to_numeric(values, errors='coerce')
                        columns[name][positions] = values.to_numpy()
                    seen[positions] = True
                    offset += len(chunk)
            source_reports.append({'member': member, 'raw_rows_including_blanks': offset})
            print('METADATA_MEMBER', member, offset, flush=True)
    if not seen.all():
        raise RuntimeError('Baseline metadata rows missing')
    inverse = np.argsort(order)
    # Restore the exact train-then-test ordering of the frozen benchmark.
    columns = {name: values[inverse] for name, values in columns.items()}
    expected = np.concatenate((np.load(base / 'train_raw.npy'), np.load(base / 'test_raw.npy')))
    fields = {'Flow Duration': 0, 'Total Fwd Packets': 1, 'Total Backward Packets': 2,
              'Total Length of Fwd Packets': 3, 'Total Length of Bwd Packets': 4,
              'SYN Flag Count': 29, 'RST Flag Count': 30}
    for name, feature in fields.items():
        if not np.array_equal(columns[name].astype(np.float32), expected[:, feature]):
            raise RuntimeError('Baseline row alignment or numeric mismatch: ' + name)
    del expected
    numeric = np.column_stack([columns[name] for name in fields])
    if not np.isfinite(numeric).all():
        raise RuntimeError('Invalid context measures')
    for name in ('Source Port', 'Destination Port', 'Protocol'):
        values = columns[name]
        limit = 255 if name == 'Protocol' else 65535
        if not (np.isfinite(values).all() and np.all(values == np.floor(values))
                and np.all((values >= 0) & (values <= limit))):
            raise RuntimeError('Invalid port/protocol metadata: ' + name)
    if np.any(numeric[:, 1:] < 0):
        raise RuntimeError('Negative context counts')
    timestamp_map = {text: timestamp_bounds(text) for text in np.unique(columns['Timestamp'])}
    stamps = np.asarray([timestamp_map[v] for v in columns['Timestamp']])
    # Weekdays in a synthetic fixture can differ from filenames; full source dates are checked below.
    if archive_path.name == 'GeneratedLabelledFlows.zip':
        source_indices = unsorted >> np.uint64(32)
        for source_id, member in enumerate(members):
            weekday = next(i for i, day in enumerate(('Monday','Tuesday','Wednesday','Thursday','Friday')) if day.lower() in member.lower())
            if np.any(stamps[source_indices == source_id, 2] != weekday):
                raise RuntimeError('Timestamp date does not match source weekday')
    ip_values = np.concatenate((columns['Source IP'].astype(str), columns['Destination IP'].astype(str)))
    if np.any(np.char.str_len(ip_values.astype(str)) == 0) or np.any(ip_values == 'nan'):
        raise RuntimeError('Missing endpoint metadata')
    codes, unique_ips = pd.factorize(ip_values, sort=True)
    duration = columns['Flow Duration'] / 1e6
    lower = stamps[:, 0] + np.maximum(duration, 0.)
    forward = columns['Total Fwd Packets']
    backward = columns['Total Backward Packets']
    measures = np.column_stack((np.ones(n), forward, backward,
        columns['Total Length of Fwd Packets'], columns['Total Length of Bwd Packets'],
        backward == 0, columns['RST Flag Count'] > 0, columns['SYN Flag Count'] > 0,
        columns['Protocol'] == 6, columns['Protocol'] == 17)).astype(np.float64)
    meta = {'source': codes[:n].astype(np.int32), 'destination': codes[n:].astype(np.int32),
            'sport': columns['Source Port'].astype(np.int32), 'dport': columns['Destination Port'].astype(np.int32),
            'lower': lower, 'upper': lower + stamps[:, 1], 'measures': measures}
    report = {'rows': n, 'train_rows': len(train_ids), 'test_rows': len(test_ids),
              'row_alignment': 'exact selected metadata fields match frozen original 32-feature rows',
              'timestamp_precision_counts': dict(Counter(map(str, stamps[:, 1]))),
              'negative_durations_clamped_for_context_timing': int((duration < 0).sum()),
              'unique_endpoint_keys': len(unique_ips), 'source_members': source_reports}
    return meta, report


def prepare(directory, base=BASE, cache=CACHE, archive_path=None):
    directory, base, cache = Path(directory), Path(base), Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    archive_path = Path(archive_path or ROOT / 'data/external/CICIDS2017/GeneratedLabelledFlows.zip')
    contract = {'version': 1, 'features': CONTEXT_NAMES, 'windows_seconds': list(WINDOWS),
                'bank': 'training rows only, without labels; held-out rows never update state',
                'timing': 'whole bank completion interval within window before query lower completion bound',
                'baseline_ready_sha256': sha(base / 'ready.json'),
                'train_row_ids_sha256': sha(base / 'train_row_id.npy'),
                'test_row_ids_sha256': sha(base / 'test_row_id.npy'),
                'extractor_sha256': sha(Path(__file__))}
    if (cache / 'ready.json').exists():
        result = json.loads((cache / 'ready.json').read_text())
        assert result['contract'] == contract, 'Context cache changed; use a new directory'
        return result
    atomic(directory / 'status.json', {'state': 'extracting_metadata', 'updated_unix': time.time()})
    meta, report = read_metadata(base, archive_path, directory)
    n_train = report['train_rows']
    def progress(window, elapsed):
        print('CONTEXT_WINDOW_COMPLETE', window, elapsed, flush=True)
        atomic(directory / 'status.json', {'state': 'extracting_context', 'window': window,
                                         'seconds': elapsed, 'updated_unix': time.time()})
    context = build_context(meta, np.arange(n_train), progress)
    np.save(cache / 'query_anchor.npy', meta['lower'])
    scaler = StandardScaler().fit(context[:n_train])
    mean, scale = scaler.mean_.astype(np.float32), scaler.scale_.astype(np.float32)
    for split, values in (('train', context[:n_train]), ('test', context[n_train:])):
        np.save(cache / (split + '_raw.npy'), values)
        normalized = ((values - mean) / scale).astype(np.float32)
        if not np.isfinite(normalized).all():
            raise RuntimeError('Nonfinite normalized context')
        np.save(cache / (split + '_x.npy'), normalized)
    atomic(cache / 'normalization.json', {'mean': mean.tolist(), 'scale': scale.tolist(), 'fit': 'training only'})
    report.update({'contract': contract, 'context_dimension': len(CONTEXT_NAMES),
        'train_with_history': int((context[:n_train, [0,13,26,39,52,65]] > 0).any(axis=1).sum()),
        'test_with_history': int((context[n_train:, [0,13,26,39,52,65]] > 0).any(axis=1).sum()),
        'normalization_sha256': sha(cache / 'normalization.json')})
    atomic(cache / 'ready.json', report)
    return report
