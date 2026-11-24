"""Single entry point; run `python reproduce.py --help` for the current snapshot."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
from reproducibility.paths import adb_path,java_path,bootstrap_reference_extractor,train_command


def run(command,**kwargs):
    print('RUN',subprocess.list2cmdline(list(map(str,command))),flush=True)
    subprocess.run(list(map(str,command)),cwd=ROOT,check=True,**kwargs)


def select_adb(serial):
    serial=serial or os.environ.get('NIDS_DEVICE_SERIAL')
    if not serial:raise RuntimeError('Choose your owned test device explicitly: --serial SERIAL from adb devices')
    return [adb_path(),'-s',serial]


def doctor(args):
    print('Project:',ROOT)
    for tool in [sys.executable,java_path(),adb_path()]:print('Tool:',tool)
    for package in ['numpy','pandas','scikit-learn','torch','executorch']:
        try:print(package,importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError:print(package,'not installed')
    if args.phone:
        adb=select_adb(args.serial)
        for command in [['getprop','ro.product.model'],['getprop','ro.build.version.release'],['getprop','ro.product.cpu.abi'],['su','-c','id']]:
            run(adb+['shell']+command)
        run(adb+['shell','/data/local/tmp/tcpdump','--version'])


def build(args):
    bootstrap_reference_extractor()
    sdk=args.sdk or os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk:raise RuntimeError('Set ANDROID_HOME or pass --sdk with Android SDK platform34 installed')
    (ROOT/'android/local.properties').write_text('sdk.dir='+Path(sdk).resolve().as_posix()+'\n',encoding='utf-8')
    gradle=['cmd.exe','/d','/c',str(ROOT/'android/gradlew.bat')] if os.name=='nt' else ['bash',str(ROOT/'android/gradlew')]
    tasks=[':core:alignedCheck',':core:alignedV2PolicyCheck',':core:captureDeliveryClockCheck',':app:assembleDebug',':app:assembleDebugAndroidTest',':trafficlab:assembleDebug',':datasetlab:assembleDebug',':datasettools:jar',':contractcheck:assembleDebug',':protocolcore:installDist',':protocollab:assembleDebug']
    run(gradle+['-p',str(ROOT/'android'),'--no-daemon','--console=plain']+(['--offline'] if args.offline else [])+tasks)


def install(args):
    adb=select_adb(args.serial)
    root=subprocess.check_output(adb+['shell','su','-c','id'],text=True)
    if 'uid=0' not in root:raise RuntimeError('Live capture requires an already-rooted test device; setup never roots/unlocks a bootloader')
    if args.tcpdump:
        path=Path(args.tcpdump).resolve();assert path.is_file()
        run(adb+['push',str(path),'/data/local/tmp/tcpdump'])
        run(adb+['shell','su','-c','chmod 755 /data/local/tmp/tcpdump'])
    help_text=subprocess.check_output(adb+['shell','/data/local/tmp/tcpdump','--help'],stderr=subprocess.STDOUT,text=True)
    if '--immediate-mode' not in help_text:raise RuntimeError('A trusted compatible ARM64 tcpdump with --immediate-mode is required')
    for module in ['app','trafficlab','datasetlab']:
        path=ROOT/'android'/module/'build/outputs/apk/debug'/(module+'-debug.apk')
        if not path.exists():raise RuntimeError('Build first: python reproduce.py build-android --sdk SDK_PATH')
        run(adb+['install','-r','-g',str(path)])
    if args.llama:
        source=Path(args.llama).resolve();manifest=json.loads((ROOT/'models/llama_download.json').read_text())
        run(adb+['shell','run-as','nids.app','mkdir','-p','files/llama'])
        for item in manifest['files']:
            path=source/item['name']
            if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('Llama asset checksum mismatch: '+item['name'])
            remote='/data/local/tmp/nids_model_'+item['name']
            run(adb+['push',str(path),remote])
            # Debug APK run-as writes into the application UID; no global storage permissions.
            run(adb+['shell','chmod','644',remote])
            run(adb+['shell','run-as','nids.app','cp',remote,'files/llama/'+item['name']])
            run(adb+['shell','run-as','nids.app','chmod','600','files/llama/'+item['name']])
            run(adb+['shell','rm','-f',remote])
    if args.start:run(adb+['shell','am','start','-n','nids.app/.LearnedNetworkActivity','--ez','start_monitor','true','--ez','validation_trace','true'])


def experiment(args):
    if os.name=='nt':raise RuntimeError('Paper/context training uses POSIX locking: run this command inside Linux/WSL; see docs/REPRODUCING_RESULTS.md')
    name='tsanet_paper' if args.name=='paper' else 'tsanet_context'
    directory=Path(args.directory).resolve() if args.directory else ROOT/'runs'/('tsanet_paper_smoke' if name=='tsanet_paper' and args.smoke else 'tsanet_context_smoke' if args.smoke else 'tsanet_paper_70_30' if name=='tsanet_paper' else 'tsanet_context_v1')
    run([sys.executable,'-u','-m','experiments.'+name+'.run','--directory',directory]+(['--smoke'] if args.smoke else []))


def aligned(args):
    bootstrap_reference_extractor()
    if args.action=='prepare':run([sys.executable,'-u','-m','experiments.phone_alignment_v2.prepare']);return
    if args.action=='evaluate':run([sys.executable,'-u','-m','experiments.phone_alignment_v2.evaluate']);return
    if args.action=='export':run([sys.executable,'-u','-m','experiments.phone_alignment_v2.export_mobile']);return
    from experiments.phone_alignment_v2.preflight import configuration
    from experiments.phone_alignment_v2.common import RUN,CACHE,atomic,sha
    assert (CACHE/'ready.json').exists(),'Prepare the external raw datasets first'
    config=configuration()
    config['code_sha256']={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/'experiments/phone_alignment_v2').glob('*.py')}
    if not (RUN/'config.json').exists() or not (RUN/'jobs').exists():atomic(RUN/'config.json',config)
    for job in config['jobs']:run([sys.executable,'-u','-m','experiments.phone_alignment_v2.train','--job',job['name']])
    run([sys.executable,'-u','-m','experiments.phone_alignment_v2.evaluate'])


def phone(args):
    bootstrap_reference_extractor()
    if args.serial:os.environ['NIDS_DEVICE_SERIAL']=args.serial
    if args.action=='pilot':
        run([sys.executable,'-u','-m','experiments.phone_capture_v1.collect','--session','pilot_development','--seed','1201']);return
    if args.action=='collect':run([sys.executable,'-u','-m','experiments.phone_capture_v1.campaign']);return
    run([sys.executable,'-u','-m','validation.controlled_phone_test','--profile',args.profile]+(['--preview'] if args.preview else []))


def download_llama(args):
    if not args.accept_license:raise RuntimeError('Review models/LLAMA_LICENSE.txt and pass --accept-license to request the optional upstream model download')
    from huggingface_hub import hf_hub_download
    manifest=json.loads((ROOT/'models/llama_download.json').read_text());out=ROOT/'external_models/llama';out.mkdir(parents=True,exist_ok=True)
    for item in manifest['files']:
        path=Path(hf_hub_download(manifest['repository'],item['name'],revision=manifest['revision'],local_dir=out))
        if hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('Upstream asset differs from verified app requirement: '+item['name'])
    print('Verified optional model directory:',out)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('doctor');p.add_argument('--phone',action='store_true');p.add_argument('--serial');p.set_defaults(function=doctor)
    p=sub.add_parser('build-android');p.add_argument('--sdk');p.add_argument('--offline',action='store_true');p.set_defaults(function=build)
    p=sub.add_parser('install-phone');p.add_argument('--serial');p.add_argument('--tcpdump');p.add_argument('--llama');p.add_argument('--start',action='store_true');p.set_defaults(function=install)
    for name in ['paper','context']:
        p=sub.add_parser(name);p.add_argument('--smoke',action='store_true');p.add_argument('--directory');p.set_defaults(function=experiment,name=name)
    p=sub.add_parser('aligned');p.add_argument('action',choices=['prepare','train','evaluate','export']);p.set_defaults(function=aligned)
    p=sub.add_parser('phone');p.add_argument('action',choices=['test','pilot','collect']);p.add_argument('--serial');p.add_argument('--profile',default='Benign');p.add_argument('--preview',action='store_true');p.set_defaults(function=phone)
    p=sub.add_parser('download-llama');p.add_argument('--accept-license',action='store_true');p.set_defaults(function=download_llama)
    args=parser.parse_args();args.function(args)


if __name__=='__main__':main()
