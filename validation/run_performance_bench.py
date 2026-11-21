"""Measure current on-phone inference with private fixtures, never attack traffic."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

import protocol_phone_test as lab

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'runs/performance_v1'

SAMPLE=r'''echo UPTIME; cat /proc/uptime; echo CPU; head -n 1 /proc/stat
for pid in $(pidof nids.app nids.app:llama tcpdump); do
 echo PROCESS $pid; echo CMD; tr "\000" " " < /proc/$pid/cmdline; echo
 echo STAT; cat /proc/$pid/stat; echo STATUS; cat /proc/$pid/status
 echo SMAPS; cat /proc/$pid/smaps_rollup; echo END_PROCESS
done
for key in current_now voltage_now charge_counter temp capacity; do
 echo BATTERY_$key; cat /sys/class/power_supply/battery/$key 2>/dev/null
done
for key in cur_freq utilization total_gpu_mem dma_buf_gpu_mem; do
 echo GPU_$key; cat /sys/class/misc/mali0/device/$key 2>/dev/null
done
for cpu in 0 1 2 3 4 5 6 7; do
 echo FREQ_$cpu; cat /sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_cur_freq 2>/dev/null
done
echo MEMINFO; head -n 12 /proc/meminfo
'''


def save(path,value):lab.lab.save(path,value)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite',choices=('detector','llama','llama_compare','detector_candidate','detector_pair','explanation_options','llama_boot_warmup','llama_token_budget'),required=True)
    parser.add_argument('--session',required=True)
    parser.add_argument('--install-test-apk',action='store_true')
    parser.add_argument('--profile',choices=('current','concise_prefix96','structured_tail48','guidance_only48'),default='current')
    parser.add_argument('--variant',choices=('hoisted_fp32','e8_blockmax_reconstructed','e8_rowsigma_reconstructed'),default='hoisted_fp32')
    parser.add_argument('--resource-period',type=float,default=2)
    args=parser.parse_args();assert re.fullmatch('[A-Za-z0-9_-]{1,80}',args.session);assert .5<=args.resource_period<=10
    if args.suite=='llama_compare' and args.profile=='current':args.profile='guidance_only48'
    lab.lab.select_phone();folder=RUN/args.session;folder.mkdir(parents=True,exist_ok=False)
    # A preceding instrumentation run restores the foreground service
    # asynchronously. Wait for readiness rather than failing that handover.
    ready_deadline=time.monotonic()+40
    while True:
        initial=lab.lab.monitor_state()
        if initial['enabled'] and initial['foreground'] and initial['schema']=='phone-aligned-v2':break
        assert time.monotonic()<ready_deadline,'Original monitor did not become ready'
        time.sleep(1)
    # Packet drops are a measured performance outcome here, not a reason to
    # discard a stress measurement. Attack-validity guards remain unchanged.
    save(folder/'initial_monitor.json',initial);save(folder/'model_sha256.json',lab.attest())
    for package in ('nids.app','nids.app.test'):
        (folder/(package+'_package.txt')).write_text(lab.lab.adb('shell','dumpsys','package',package),encoding='utf-8')
        installed=lab.lab.adb('shell','pm','path',package).strip().removeprefix('package:')
        assert installed.startswith('/data/app/') and installed.endswith('/base.apk')
        save(folder/(package+'_installed_apk.json'),{'path':installed,'sha256':lab.lab.adb('shell','su','-c',"'sha256sum "+installed+"'").split()[0]})
        if package=='nids.app.test' and args.install_test_apk:
            lab.lab.adb('pull',installed,str(folder/'previous-test.apk'))
    if args.install_test_apk:
        apk=ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'
        assert 'Success' in lab.lab.adb('install','-r',str(apk),timeout=120)
    if args.suite=='explanation_options':
        source=RUN/'small_explainer';destination='files/performance_v1/small_explainer'
        manifest=json.loads((source/'manifest.json').read_text(encoding='utf-8'))
        lab.lab.adb('shell','run-as','nids.app','mkdir','-p',destination)
        uid=lab.lab.adb('shell','run-as','nids.app','id','-u').strip();assert uid.isdigit()
        for name in ('smollm2_135m_xnnpack_8da8w.pte','tokenizer.json'):
            temporary='/data/local/tmp/nids_perf_'+name;target='/data/user/0/nids.app/'+destination+'/'+name
            assert lab.sha(source/name)==manifest['files'][name]['sha256']
            lab.lab.adb('push',str(source/name),temporary,timeout=180)
            lab.lab.adb('shell','su','-c',"'cp "+temporary+' '+target+' && chown '+uid+':'+uid+' '+target+' && chmod 600 '+target+"'")
            assert lab.lab.adb('shell','su','-c',"'sha256sum "+target+"'").split()[0]==manifest['files'][name]['sha256']
    if args.suite in ('detector_candidate','detector_pair'):
        source=RUN/'candidates/bundles'/args.variant;destination='files/performance_v1/candidates/'+args.variant
        lab.lab.adb('shell','run-as','nids.app','mkdir','-p',destination)
        uid=lab.lab.adb('shell','run-as','nids.app','id','-u').strip();assert uid.isdigit()
        staging='/data/local/tmp/nids_perf_'+args.variant
        lab.lab.adb('shell','mkdir','-p',staging)
        for file in source.iterdir():
            assert file.is_file() and re.fullmatch(r'aligned_v2_(gate|diagnosis)(_(manifest|selfcheck))?\.(pte|json)',file.name)
            temporary=staging+'/'+file.name;target='/data/user/0/nids.app/'+destination+'/'+file.name
            lab.lab.adb('push',str(file),temporary,timeout=120)
            lab.lab.adb('shell','su','-c',"'cp "+temporary+' '+target+' && chown '+uid+':'+uid+' '+target+' && chmod 600 '+target+"'")
            raw=lab.lab.adb('exec-out','run-as','nids.app','cat',destination+'/'+file.name,binary=True)
            assert __import__('hashlib').sha256(raw).hexdigest()==lab.sha(file)
    save(folder/'config.json',{'suite':args.suite,'session':args.session,'profile':args.profile,'variant':args.variant,'resource_period_seconds':args.resource_period,
        'resource_scope':'Device GPU/battery readings include other apps; process CPU/PSS/RSS read separately.',
        'main_app_apk_updated':False,'incident_or_attack_generated':False})
    remote='files/performance_v1/'+args.session
    command=[str(lab.lab.ADB),'-s',lab.lab.SERIAL,'shell','am','instrument','-w','-r','-e','mode','performance',
        '-e','suite',args.suite,'-e','session',args.session,'-e','profile',args.profile,'-e','variant',args.variant,'nids.app.test/nids.app.ValidationInstrumentation']
    begin=time.monotonic();last_phase=None;samples=0;valid_samples=0;process=None;completed=False
    try:
        with (folder/'instrumentation.log').open('w',encoding='utf-8') as output,(folder/'resources_raw.jsonl').open('w',encoding='utf-8') as resources:
            process=subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
            while process.poll() is None:
                if time.monotonic()-begin>1000:process.terminate();raise RuntimeError('Performance suite exceeded 1000-second bound')
                sample={'pc_unix':time.time(),'pc_elapsed_seconds':time.monotonic()-begin}
                try:
                    raw=lab.lab.adb('shell','su','-c',"'"+SAMPLE+"'",timeout=12)
                    phase=lab.lab.adb('exec-out','run-as','nids.app','cat',remote+'/phase.json',required=False,timeout=8)
                    sample.update(raw=raw,phase=json.loads(phase) if phase.strip().startswith('{') else None)
                    assert 'END_PROCESS' in raw and 'GPU_total_gpu_mem' in raw,'Incomplete external resource sample'
                    valid_samples+=1
                    name=(sample['phase'] or {}).get('phase')
                    if name!=last_phase:print('PERFORMANCE_PHASE',name,flush=True);last_phase=name
                except Exception as e:sample['sample_error']=repr(e)
                resources.write(json.dumps(sample)+'\n');resources.flush();samples+=1
                save(RUN/'status.json',{'session':args.session,'suite':args.suite,'phase':last_phase,'elapsed_seconds':round(time.monotonic()-begin,1),'samples':samples})
                time.sleep(args.resource_period)
            assert process.returncode==0,'Instrumentation transport failed; inspect its log'
        report=json.loads(lab.lab.adb('exec-out','run-as','nids.app','cat',remote+'/report.json'))
        save(folder/'report.json',report);assert report.get('passed'),report.get('error','Performance suite failed')
        assert valid_samples>=3,'Insufficient external CPU/RAM/GPU/battery samples; retain timings but repeat resource observation'
        for path in ('resources_v1.jsonl','resources_llama_v1.jsonl'):
            raw=lab.lab.adb('exec-out','run-as','nids.app','cat','files/'+path,required=False,binary=True)
            if raw:(folder/path).write_bytes(raw)
        print('PERFORMANCE_COMPLETE',args.session,'trials',len(report['trials']),'resource_samples',samples,flush=True)
        save(RUN/'status.json',{'session':args.session,'suite':args.suite,'phase':'complete','samples':samples,'valid_resource_samples':valid_samples})
        completed=True
    finally:
        if not completed:
            if process is not None and process.poll() is None:process.terminate()
            # Stopping the local adb client alone does not cancel native Android
            # instrumentation. Cancel only this benchmark target, then restore it.
            if process is not None:lab.lab.adb('shell','am','force-stop','nids.app',required=False)
            save(RUN/'status.json',{'session':args.session,'suite':args.suite,'phase':'failed_preserved','samples':samples,'valid_resource_samples':valid_samples})
        lab.lab.adb('shell','am','start','-n','nids.app/.LearnedNetworkActivity','--ez','start_monitor','true',required=False)
        save(folder/'final_model_sha256.json',lab.attest())


if __name__=='__main__':main()
