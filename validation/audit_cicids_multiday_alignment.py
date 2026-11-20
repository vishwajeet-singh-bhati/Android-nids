"""Audit CICIDS weekday tuple/time label consistency without training or assigning labels."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import Counter, defaultdict
from pathlib import Path
import calendar, csv, datetime, io, json, time, zipfile

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data/external/CICIDS2017'
OUT = ROOT / 'validation/reports/cicids2017_multiday_alignment.json'
OFFSET = 3 * 3600  # Prior Friday clock audit; checked against each capture's first records.
DAYS = {
    'Monday': 'Monday-WorkingHours.pcap',
    'Tuesday': 'Tuesday-WorkingHours.pcap',
    'Wednesday': 'Wednesday-workingHours.pcap',
    'Thursday': 'Thursday-WorkingHours.pcap',
    'Friday': 'Friday-WorkingHours.pcap',
}

def canonical(proto, src, sport, dst, dport):
    a, b = (src, int(sport)), (dst, int(dport))
    return (int(proto), a, b) if a <= b else (int(proto), b, a)

def label_times(text):
    fmt = '%d/%m/%Y %H:%M:%S' if text.count(':') == 2 else '%d/%m/%Y %H:%M'
    dt = datetime.datetime.strptime(text.strip(), fmt)
    precision = 1 if text.count(':') == 2 else 60
    values = [dt]
    if dt.hour < 12:
        values.append(dt + datetime.timedelta(hours=12))
    elif dt.hour == 12:
        values.append(dt - datetime.timedelta(hours=12))
    return [(calendar.timegm(v.timetuple()) + OFFSET, precision) for v in values]

def load_day_labels(archive, day):
    member_names = [n for n in archive.namelist() if day.lower() in n.lower() and n.lower().endswith('.csv')]
    if not member_names:
        raise RuntimeError(f'No publisher CSV for {day}')
    index = defaultdict(list)
    class_counts = Counter()
    valid, invalid, blank = 0, 0, 0
    for name in member_names:
        with io.TextIOWrapper(archive.open(name), encoding='utf-8-sig', errors='replace', newline='') as stream:
            reader = csv.reader(stream)
            header = [v.strip() for v in next(reader)]
            ix = {v: i for i, v in enumerate(header)}
            needed = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Label']
            if any(v not in ix for v in needed):
                raise RuntimeError(f'Missing expected flow label fields in {name}')
            for row in reader:
                if not row or all(not v.strip() for v in row):
                    blank += 1
                    continue
                try:
                    get = lambda field: row[ix[field]].strip()
                    proto = int(get('Protocol'))
                    key = canonical(proto, get('Source IP'), get('Source Port'), get('Destination IP'), get('Destination Port'))
                    starts = label_times(get('Timestamp'))
                    duration = max(0.0, float(get('Flow Duration')) / 1_000_000)
                    label = get('Label').replace('\ufffd', '').strip()
                    index[key].append((starts, duration, label))
                    class_counts[label] += 1
                    valid += 1
                except (ValueError, IndexError):
                    invalid += 1
        print('LABEL_CSV_COMPLETE', day, name, 'rows', valid, 'unique_tuples', len(index), flush=True)
    return index, {'members': member_names, 'rows': valid, 'blank_rows': blank, 'invalid_rows': invalid,
                   'unique_bidirectional_tuples': len(index), 'labels': dict(class_counts)}

def check_day(day, pcap_path, labels):
    import sys
    sys.path.insert(0, str(ROOT))
    from reproducibility.packet_reader import iter_packets, ParseStats
    from reproducibility.packet_config import load_config
    config = load_config(str(ROOT / 'configs/data.yaml'))
    config.parse.max_packets_per_capture = 0
    config.parse.payload_bytes_kept = 0
    stats = ParseStats()
    buckets = {}
    first = None
    started = time.monotonic()
    for packet in iter_packets(pcap_path, config.parse, stats):
        if packet.ip_proto not in (6, 17):
            continue
        if first is None:
            first = packet.ts
        hour = max(0, int((packet.ts - first) // 3600))
        b = buckets.setdefault(hour, {'seen': set(), 'unique_tuples_sampled': 0, 'tuple_found': 0,
                                       'unique_time_label': 0, 'conflicting_time_labels': 0,
                                       'no_compatible_time_label': 0, 'matched_classes': Counter()})
        if b['unique_tuples_sampled'] >= 250:
            continue
        key = canonical(packet.ip_proto, packet.src_ip, packet.sport, packet.dst_ip, packet.dport)
        if key in b['seen']:
            continue
        b['seen'].add(key)
        b['unique_tuples_sampled'] += 1
        candidates = labels.get(key, ())
        if candidates:
            b['tuple_found'] += 1
        classes = set()
        for starts, duration, label in candidates:
            for start, precision in starts:
                if start - 1.0 <= packet.ts <= start + precision + duration + 1.0:
                    classes.add(label)
        if len(classes) == 1:
            label = next(iter(classes))
            b['unique_time_label'] += 1
            b['matched_classes'][label] += 1
        elif len(classes) > 1:
            b['conflicting_time_labels'] += 1
        else:
            b['no_compatible_time_label'] += 1
        if stats.total_records and stats.total_records % 1_000_000 == 0:
            print('PCAP_PROGRESS', day, stats.total_records, 'elapsed_s', round(time.monotonic() - started), flush=True)
    result = {'pcap': pcap_path.name, 'first_packet_utc': datetime.datetime.fromtimestamp(first, datetime.timezone.utc).isoformat() if first else None,
              'last_packet_utc': datetime.datetime.fromtimestamp(stats.last_ts, datetime.timezone.utc).isoformat() if stats.last_ts else None,
              'parser': stats.as_dict(), 'sampled_by_elapsed_hour': [], 'elapsed_seconds': time.monotonic() - started}
    total = Counter()
    for hour in sorted(buckets):
        b = buckets[hour]
        total.update({k: b[k] for k in ['unique_tuples_sampled', 'tuple_found', 'unique_time_label', 'conflicting_time_labels', 'no_compatible_time_label']})
        total.update({'label:' + k: v for k, v in b['matched_classes'].items()})
        result['sampled_by_elapsed_hour'].append({'hour': hour,
            'unique_tuples_sampled': b['unique_tuples_sampled'], 'tuple_found': b['tuple_found'],
            'unique_time_label': b['unique_time_label'], 'conflicting_time_labels': b['conflicting_time_labels'],
            'no_compatible_time_label': b['no_compatible_time_label'], 'matched_classes': dict(b['matched_classes'])})
    result['sampled_totals'] = dict(total)
    result['scope'] = 'up to 250 unique bidirectional protocol/IP/port tuples per elapsed capture hour; interval overlap under fixed +3h clock and both AM/PM candidates; diagnostic only, no label assigned or model fit'
    return result

def main():
    report = {'version': 1, 'offset_seconds': OFFSET,
              'offset_evidence': 'Existing Friday audit plus first timestamp/CSV agreement on Monday through Thursday; this run tests tuple/time agreement throughout each capture.',
              'days': {}, 'started_unix': time.time()}
    archive_path = DATA / 'GeneratedLabelledFlows.zip'
    with zipfile.ZipFile(archive_path) as archive:
        for day, filename in DAYS.items():
            labels, inventory = load_day_labels(archive, day)
            report['days'][day] = {'label_inventory': inventory,
                                   'alignment': check_day(day, DATA / filename, labels)}
            OUT.parent.mkdir(parents=True, exist_ok=True)
            tmp = OUT.with_suffix('.tmp')
            tmp.write_text(json.dumps(report, indent=2) + '\n')
            tmp.replace(OUT)
            del labels
            print('DAY_AUDIT_COMPLETE', day, flush=True)
    report['completed_unix'] = time.time()
    tmp = OUT.with_suffix('.tmp')
    tmp.write_text(json.dumps(report, indent=2) + '\n')
    tmp.replace(OUT)
    print('MULTIDAY_ALIGNMENT_COMPLETE', OUT, flush=True)

if __name__ == '__main__':
    main()
