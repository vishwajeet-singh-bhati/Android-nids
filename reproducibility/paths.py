"""Machine-independent tool discovery; no credentials or device IDs are stored."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def adb_path():
    if os.environ.get('NIDS_ADB'):return os.environ['NIDS_ADB']
    sdk=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if sdk:
        p=Path(sdk)/'platform-tools'/('adb.exe' if os.name=='nt' else 'adb')
        if p.exists():return str(p)
    return shutil.which('adb') or shutil.which('adb.exe') or 'adb'


def java_path():
    if os.environ.get('NIDS_JAVA'):return os.environ['NIDS_JAVA']
    if os.environ.get('JAVA_HOME'):
        p=Path(os.environ['JAVA_HOME'])/'bin'/('java.exe' if os.name=='nt' else 'java')
        if p.exists():return str(p)
    return shutil.which('java') or 'java'


def runtime_path(path):
    value=str(Path(path).resolve())
    if java_path().lower().endswith('.exe') and value.startswith('/mnt/'):
        return value[5].upper()+':\\'+value[7:].replace('/','\\')
    return value


def classpath(paths):
    separator=';' if os.name=='nt' or java_path().lower().endswith('.exe') else ':'
    return separator.join(runtime_path(p) for p in paths)


def train_command(module,*args,smoke=False):
    backend=os.environ.get('NIDS_TRAIN_BACKEND','native')
    if backend=='wsl':
        python=os.environ.get('NIDS_WSL_PYTHON')
        if not python:raise RuntimeError('Set NIDS_WSL_PYTHON to the Linux training virtualenv Python path; see docs/REPRODUCING_RESULTS.md')
        root=subprocess.check_output(['wsl.exe','wslpath','-u',str(ROOT)],text=True).strip()
        return ['wsl.exe','-d',os.environ.get('NIDS_WSL_DISTRO','Ubuntu'),'--cd',root,'--','env',
            'NIDS_PHONE_TRAINING_SMOKE='+('1' if smoke else '0'),python,'-u','-m',module,*map(str,args)]
    return [os.environ.get('NIDS_TRAIN_PYTHON',sys.executable),'-u','-m',module,*map(str,args)]


@contextmanager
def exclusive_file_lock(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+b') as stream:
        stream.seek(0);stream.write(b'0');stream.flush();stream.seek(0)
        if os.name=='nt':
            import msvcrt
            try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            except OSError:raise RuntimeError('Another phone test/collection is running')
        else:
            import fcntl
            try:fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise RuntimeError('Another phone test/collection is running')
        try:yield
        finally:
            if os.name=='nt':stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
            else:fcntl.flock(stream,fcntl.LOCK_UN)


def bootstrap_reference_extractor():
    source=ROOT/'models/current/extractor';target=ROOT/'runs/phone_alignment_v2/extractor'
    manifest=json.loads((source/'manifest.json').read_text(encoding='utf-8'))
    target.mkdir(parents=True,exist_ok=True)
    for name,key in [('core.jar','core_sha256'),('kotlin-stdlib.jar','runtime_sha256')]:
        assert hashlib.sha256((source/name).read_bytes()).hexdigest()==manifest[key],name+' checksum failed'
    for name in ['core.jar','kotlin-stdlib.jar','manifest.json','spec.json']:
        if not (target/name).exists():shutil.copy2(source/name,target/name)
    public=ROOT/'validation/reports/phone_alignment_v2';public.mkdir(parents=True,exist_ok=True)
    if not (public/'feature_contract.json').exists():shutil.copy2(source/'spec.json',public/'feature_contract.json')
    run=ROOT/'runs/phone_alignment_v2'
    if not (run/'config.json').exists():shutil.copy2(ROOT/'models/current/training_config.json',run/'config.json')
    return target
