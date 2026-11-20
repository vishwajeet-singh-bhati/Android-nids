
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_shipped_models_and_contract_match_manifests():
    folder=ROOT/'android/app/src/main/assets'
    for kind in ['gate','diagnosis']:
        manifest=json.loads((folder/f'aligned_v2_{kind}_manifest.json').read_text())
        assert hashlib.sha256((folder/f'aligned_v2_{kind}.pte').read_bytes()).hexdigest()==manifest['model_sha256']
        assert manifest['normalization_embedded'] and manifest['diagnosis_never_vetoes_gate']
        assert hashlib.sha256((folder/'aligned_v2_contract.json').read_bytes()).hexdigest()==manifest['feature_contract_sha256']


def test_frozen_extractor_and_runtime_are_intact():
    folder=ROOT/'models/current/extractor';m=json.loads((folder/'manifest.json').read_text())
    for name,key in [('core.jar','core_sha256'),('kotlin-stdlib.jar','runtime_sha256')]:
        assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==m[key]


def test_current_feature_architectures():
    import torch
    from experiments.phone_alignment_v2.models import build
    gate=build({'kind':'gate','width':96}).eval();diagnosis=build({'kind':'diagnosis','width':64}).eval()
    assert sum(p.numel() for p in gate.parameters())==18913
    assert sum(p.numel() for p in diagnosis.parameters())==173721
    # Software contract fixture only; not training examples or performance evidence.
    x=torch.zeros(2,147)
    assert gate(x).shape==(2,1) and diagnosis(x).shape==(2,7)


def test_misassigned_socket_proof_is_rejected():
    from experiments.phone_capture_v1.smoke import negative_label_checks
    assert all(negative_label_checks().values())
