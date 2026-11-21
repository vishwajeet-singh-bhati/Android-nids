"""Download a pinned, optional explanation benchmark model; production is untouched."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
REPO='software-mansion/SmolLM2-ExecuTorch'
REVISION='f3ae600d5e957d9a7f216f6c55788315a9fe2f3c'
MODEL='135m/xnnpack/smollm2_135m_xnnpack_8da8w.pte'
MODEL_SHA='9eac1f8076069fcd7583024d16dc412251d1ce3f13359991229526010a0ce380'
OUT=ROOT/'runs/performance_v1/small_explainer'


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(4*1024*1024),b''):h.update(block)
    return h.hexdigest()


def main():
    OUT.mkdir(parents=True,exist_ok=True);files={}
    for name in (MODEL,'135m/xnnpack/config.json','tokenizer.json','tokenizer_config.json','README.md'):
        target=OUT/Path(name).name
        url=f'https://huggingface.co/{REPO}/resolve/{REVISION}/{name}'
        if not target.exists():
            partial=target.with_suffix(target.suffix+'.partial')
            with urllib.request.urlopen(url,timeout=120) as response,partial.open('wb') as sink:
                size=0
                while block:=response.read(4*1024*1024):
                    size+=len(block);assert size<512*1024*1024
                    sink.write(block)
            partial.replace(target)
        digest=sha(target)
        if name==MODEL:assert digest==MODEL_SHA
        files[target.name]={'url':url,'sha256':digest,'bytes':target.stat().st_size}
        print('VERIFIED',target.name,target.stat().st_size,flush=True)
    manifest={'repository':REPO,'revision':REVISION,'license':'Apache-2.0',
        'model':'SmolLM2-135M-Instruct','quantization':'8da8w','backend':'XNNPACK CPU',
        'runtime_compatibility':'Published for ExecuTorch 1.4.1; local Android 1.5.1 compatibility must be tested, not assumed.',
        'files':files,'production_files_modified':False}
    (OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    public=ROOT/'validation/reports/performance_v1/small_model_provenance.json'
    public.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
