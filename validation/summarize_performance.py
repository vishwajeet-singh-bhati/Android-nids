"""Aggregate local benchmark timings and device/process telemetry; no device calls."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
from collections import defaultdict
import json
from pathlib import Path
import re
import statistics

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/'runs/performance_v1'
OUT=ROOT/'validation/reports/performance_v1'


def stats(values):
    values=[float(v) for v in values if v is not None]
    return {'samples':len(values),'min':min(values),'median':statistics.median(values),'max':max(values),'mean':statistics.mean(values)} if values else None


def parse(raw):
    # adb shell may return CRCRLF; normalize before matching marker records.
    raw='\n'.join(line for line in raw.replace('\r','').splitlines() if line.strip())
    def value(marker):
        m=re.search(r'^'+re.escape(marker)+r'\n([^\n]+)',raw,re.M)
        return m.group(1).strip() if m else None
    uptime=value('UPTIME');cpu=value('CPU')
    result={'uptime_seconds':float(uptime.split()[0]) if uptime else None,'cpu_ticks':[int(v) for v in cpu.split()[1:]] if cpu else [],'processes':[]}
    for pid,block in re.findall(r'^PROCESS (\d+)\n(.*?)\nEND_PROCESS',raw,re.M|re.S):
        cmd=re.search(r'^CMD\n(.*?)\nSTAT\n',block,re.M|re.S)
        stat=re.search(r'^STAT\n([^\n]+)',block,re.M)
        if not cmd or not stat:continue
        name=cmd.group(1).strip().split()[0]
        role='llama_worker' if name=='nids.app:llama' else 'app' if name=='nids.app' else 'root_capture' if 'tcpdump' in name else 'other'
        fields=stat.group(1)[stat.group(1).rfind(')')+1:].split()
        if len(fields)<13:continue
        def integer(key):
            m=re.search(r'^'+re.escape(key)+r':\s+(\d+)',block,re.M)
            return int(m.group(1)) if m else None
        result['processes'].append({'pid':int(pid),'role':role,'cpu_ticks':int(fields[11])+int(fields[12]),
            'rss_kib':integer('VmRSS'),'pss_kib':integer('Pss'),'swap_kib':integer('VmSwap'),
            'swap_pss_kib':integer('SwapPss'),'threads':integer('Threads')})
    for key in ('current_now','voltage_now','charge_counter','temp','capacity'):
        v=value('BATTERY_'+key)
        result['battery_'+key]=int(v) if v and re.fullmatch(r'-?\d+',v) else None
    for key in ('cur_freq','utilization','total_gpu_mem','dma_buf_gpu_mem'):
        v=value('GPU_'+key)
        result['device_gpu_'+key]=int(v) if v and v.isdigit() else None
    result['cpu_frequency_khz']=[int(v) for i in range(8) if (v:=value('FREQ_'+str(i))) and v.isdigit()]
    m=re.search(r'^MemAvailable:\s+(\d+)',raw,re.M);result['device_mem_available_kib']=int(m.group(1)) if m else None
    return result


def resources(path):
    groups=defaultdict(lambda:defaultdict(list));previous={};previous_device=None;errors=0;valid=0
    for line in path.read_text(encoding='utf-8').splitlines():
        row=json.loads(line)
        if row.get('sample_error') or not row.get('raw'):errors+=1;continue
        s=parse(row['raw']);phase=(row.get('phase') or {}).get('phase') or 'transition';g=groups[phase];valid+=1
        t=s['uptime_seconds'];total_pss=0;total_rss=0
        for process in s['processes']:
            role=process['role'];pid=process['pid']
            for key in ('rss_kib','pss_kib','swap_kib','swap_pss_kib','threads'):
                if process[key] is not None:g[role+'_'+key].append(process[key])
            if role in ('app','llama_worker'):
                total_pss+=process['pss_kib'] or 0;total_rss+=process['rss_kib'] or 0
            old=previous.get(pid)
            if old and old['phase']==phase and t>old['time'] and t-old['time']<=10:
                one_core=100*(process['cpu_ticks']-old['ticks'])/100/(t-old['time'])
                g[role+'_cpu_one_core_percent'].append(one_core);g[role+'_cpu_all8cores_percent'].append(one_core/8)
            previous[pid]={'phase':phase,'time':t,'ticks':process['cpu_ticks']}
        g['combined_app_worker_pss_kib'].append(total_pss);g['combined_app_worker_rss_kib'].append(total_rss)
        for key in ('device_gpu_cur_freq','device_gpu_utilization','device_gpu_total_gpu_mem','device_gpu_dma_buf_gpu_mem','device_mem_available_kib','battery_current_now','battery_voltage_now','battery_charge_counter','battery_temp','battery_capacity'):
            if s[key] is not None:g[key].append(s[key])
        if s['battery_current_now'] is not None and s['battery_voltage_now'] is not None:
            g['whole_device_battery_discharge_mw_estimate'].append(max(0,-s['battery_current_now']*s['battery_voltage_now']/1e9))
        if s['cpu_frequency_khz']:g['mean_cpu_frequency_khz'].append(statistics.mean(s['cpu_frequency_khz']))
        if previous_device and previous_device['phase']==phase:
            old=previous_device['cpu'];now=s['cpu_ticks']
            delta=sum(now[:8])-sum(old[:8]);idle=now[3]+now[4]-old[3]-old[4]
            if delta>0:g['whole_device_cpu_busy_percent'].append(100*(delta-idle)/delta)
        previous_device={'cpu':s['cpu_ticks'],'phase':phase}
    return {'valid_samples':valid,'sample_errors':errors,'phases':{phase:{key:stats(v) for key,v in values.items()} for phase,values in groups.items()},
        'scopes':{'cpu':'Process jiffies at CLK_TCK=100; one core 100%, normalized device capacity eight cores. Phase-crossing deltas excluded.',
        'gpu':'Pixel unified/shared GPU memory and utilization, whole device including UI/other apps; detector and Llama use CPU XNNPACK. Dedicated model VRAM is not applicable.',
        'battery':'Whole-device current/voltage estimate; not app-only energy, includes screen/radios/other applications.',
        'memory':'Sampled process PSS/RSS; maxima can miss sub-sampling transients. VmHWM fields in Llama worker reports are process-lifetime peaks.'}}


def main():
    OUT.mkdir(parents=True,exist_ok=True);sessions=[]
    for folder in sorted(RUN.iterdir()):
        if not folder.is_dir() or not (folder/'report.json').exists():continue
        report=json.loads((folder/'report.json').read_text(encoding='utf-8'))
        entry={'session':folder.name,'passed':report.get('passed',False),'trial_count':len(report.get('trials',[])),'trials':report.get('trials',[])}
        if (folder/'resources_raw.jsonl').exists():entry['resource_summary']=resources(folder/'resources_raw.jsonl')
        sessions.append(entry)
    summary={'sessions':sessions,'processing':'PC-only aggregation of original on-device results; no phone calls, fitting or retuning.'}
    (OUT/'measurements.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    for session in sessions:
        r=session.get('resource_summary',{});print(session['session'],'passed',session['passed'],'trials',session['trial_count'],'resource_samples',r.get('valid_samples'),'errors',r.get('sample_errors'))


if __name__=='__main__':main()
