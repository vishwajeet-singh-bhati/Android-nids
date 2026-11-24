import hashlib
import json
from pathlib import Path
import struct
import math

ROOT = Path(__file__).resolve().parents[1]


def test_current_sms_assets_match_their_manifest():
    root = ROOT / 'android/app/src/main/assets/sms'
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    for name in ['portable_model.json', 'ptq_int8_b1.pte', 'vocab.txt']:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == manifest[name]


def test_url_runtime_assets_are_attested_and_thresholds_are_frozen():
    root = ROOT / 'android/app/src/main/assets/url'
    manifest = json.loads((root / 'MANIFEST.json').read_text(encoding='utf-8'))['files']
    for name in ['ngram_lr.bin', 'popular.txt', 'public_suffix_list.dat', 'redirectors.txt',
                 'threat_intel.sqlite3', 'url_cnn.pte', 'url_model.json']:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == manifest[name]['sha256']
    config = json.loads((root / 'url_model.json').read_text(encoding='utf-8'))['calibrator']
    assert config['t_phishing'] == 0.6831367398836174
    assert config['t_safe'] == 0.09537270819287022


def test_selected_sms_checkpoint_and_archived_export_have_matching_provenance():
    proof = json.loads((ROOT / 'components/sms/provenance/ARCHIVED_EVALUATION.json').read_text(encoding='utf-8'))
    checkpoint = ROOT / 'components/sms/python/experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best/model.safetensors'
    assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == proof['best_checkpoint_sha256']
    with checkpoint.open('rb') as stream:
        size = struct.unpack('<Q', stream.read(8))[0]
        header = json.loads(stream.read(size))
    assert sum(math.prod(v['shape']) for k, v in header.items() if k != '__metadata__') == 22898947
    asset = ROOT / 'android/app/src/main/assets/sms/ptq_int8_b1.pte'
    assert hashlib.sha256(asset.read_bytes()).hexdigest() == proof['export_artifacts']['ptq_int8_b1.pte']['sha256']


def test_benchmark_report_does_not_invent_negative_labels():
    report = json.loads((ROOT / 'results/url_benchmark_20261124/results.json').read_text(encoding='utf-8'))
    assert report['label_summary']['independently_confirmed_benign'] == 0
    assert report['label_summary']['unknown'] == 1830
    assert report['deployed']['metrics']['phishing_detection']['precision'] is None
    assert report['known_positive_raw_outcomes'] == {'PHISHING': 172, 'UNCERTAIN': 30, 'LIKELY_SAFE': 16}
