"""Offline regression: failed instrumentation must cancel Android and restore monitoring."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import run_performance_bench as controller


def main():
    calls=[];polls=[False,False,True]
    def adb(*args,**kwargs):
        calls.append(args)
        if args[:3]==('shell','pm','path'):return '/data/app/test/base.apk'
        if 'sha256sum ' in ' '.join(str(a) for a in args):return 'a'*64+' base.apk'
        if args[0]=='exec-out':return json.dumps({'passed':False,'error':'intentional instrumentation failure'})
        return ''
    def monitor():
        return {'enabled':polls.pop(0) if polls else True,'foreground':True,'schema':'phone-aligned-v2'}
    fake=SimpleNamespace(ADB=Path('fake-adb'),SERIAL='fake-pixel',select_phone=lambda:None,
        monitor_state=monitor,adb=adb,save=lambda p,v:p.write_text(json.dumps(v)))
    fake_process=SimpleNamespace(poll=lambda:0,returncode=0)
    with tempfile.TemporaryDirectory(prefix='nids-performance-smoke-') as folder:
        run=Path(folder)
        with patch.object(controller,'RUN',run),patch.object(controller,'lab',SimpleNamespace(lab=fake,attest=lambda:{})), \
             patch.object(controller.subprocess,'Popen',return_value=fake_process),patch.object(controller.time,'sleep'), \
             patch.object(sys,'argv',['benchmark','--suite','detector','--session','intentional_failure']):
            try:controller.main()
            except AssertionError as error:assert str(error)=='intentional instrumentation failure'
            else:raise AssertionError('Failed instrumentation was accepted')
        stop=next(i for i,c in enumerate(calls) if c[:4]==('shell','am','force-stop','nids.app'))
        restore=next(i for i,c in enumerate(calls) if c[:3]==('shell','am','start'))
        assert stop<restore
        assert json.loads((run/'status.json').read_text())['phase']=='failed_preserved'
        assert (run/'intentional_failure/report.json').exists()
        assert not polls,'Readiness handover wait was not exercised'
    result={'passed':True,'phone_connected_or_modified':False,'checks':[
        'Monitor readiness tolerates two asynchronous initialization polls',
        'Failed native report raises rather than passing',
        'Failure evidence and status preserved',
        'Android benchmark target cancelled before original monitoring restored']}
    path=controller.ROOT/'validation/reports/performance_v1/controller_smoke.json'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('CONTROLLER_FAILURE_SMOKE_PASS')


if __name__=='__main__':main()
