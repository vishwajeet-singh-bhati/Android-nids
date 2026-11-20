"""Independent container-integrity audit; never salvages a partial capture."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import json,mmap,struct
from pathlib import Path

from experiments.phone_alignment_v2.common import ROOT,CACHE,PUBLIC,atomic,sha


def validate_capture(path):
    size=path.stat().st_size;records=0
    if size<24:raise ValueError('missing capture header')
    with path.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        magic=data[:4]
        formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),
                 b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
        if magic in formats:
            endian,resolution=formats[magic];at=24
            major,minor,_,_,snaplen,link=struct.unpack_from(endian+'HHIIII',data,4)
            if (major,minor)!=(2,4):raise ValueError('unsupported classic PCAP version')
            while at<size:
                if at+16>size:raise ValueError(f'truncated record header at byte {at}')
                sec,fraction,captured,original=struct.unpack_from(endian+'IIII',data,at)
                if captured>262144 or captured>snaplen or captured>original:
                    raise ValueError(f'invalid record length at byte {at}: captured={captured}, original={original}, snaplen={snaplen}')
                if fraction>=resolution:raise ValueError(f'invalid timestamp fraction at byte {at}')
                if at+16+captured>size:raise ValueError(f'truncated packet at byte {at}: need {captured}, have {size-at-16}')
                at+=16+captured;records+=1
        elif magic==b'\x0a\x0d\x0d\x0a':
            at=0;endian=None;interfaces=0
            while at<size:
                if at+12>size:raise ValueError(f'truncated PCAPNG block at byte {at}')
                section=data[at:at+4]==magic
                if section:
                    bom=data[at+8:at+12]
                    if bom not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'):raise ValueError('bad PCAPNG byte order')
                    endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>';interfaces=0
                if endian is None:raise ValueError('PCAPNG section missing')
                kind,length=struct.unpack_from(endian+'II',data,at)
                if length<12 or length>16777216 or length%4 or at+length>size:raise ValueError(f'invalid PCAPNG block length at byte {at}')
                if struct.unpack_from(endian+'I',data,at+length-4)[0]!=length:raise ValueError(f'PCAPNG block trailer mismatch at byte {at}')
                if section and length<28:raise ValueError('short PCAPNG section')
                if kind==1:
                    if length<20:raise ValueError('short interface block')
                    interfaces+=1
                elif kind==6:
                    if length<32:raise ValueError('short enhanced packet block')
                    iface,_,_,captured,original=struct.unpack_from(endian+'IIIII',data,at+8)
                    if iface>=interfaces or captured>length-32 or captured>original:raise ValueError('invalid enhanced packet bounds')
                    records+=1
                elif kind in (2,3):raise ValueError('unsupported PCAPNG packet block')
                at+=length
        else:raise ValueError('unrecognized capture magic '+magic.hex())
    return records


def audit_controls(source,captures):
    target=CACHE/'labels'/(source+'_integrity.json')
    inventory=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns} for p in captures]
    if target.exists():
        report=json.loads(target.read_text())
        if report['input_inventory']==inventory:
            rejected={v['path'] for v in report['excluded']}
            accepted=[p for p in captures if str(p.relative_to(ROOT)) not in rejected]
            if len(accepted)<20 or len(rejected)>max(2,len(captures)*.1):raise RuntimeError('Excessive Android control exclusions: '+source)
            atomic(PUBLIC/(source.lower()+'_capture_integrity.json'),report)
            return accepted
    excluded=[];accepted=[];records=0
    for path in captures:
        try:records+=validate_capture(path);accepted.append(path)
        except (ValueError,struct.error) as error:
            excluded.append({'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':sha(path),'reason':str(error)})
    report={'source':source,'policy':'Exclude the entire corrupt/unsupported capture before feature extraction; no partial salvage or record repair.',
            'input_inventory':inventory,'total_captures':len(captures),'accepted_captures':len(accepted),'accepted_records':records,'excluded':excluded}
    atomic(target,report);atomic(PUBLIC/(source.lower()+'_capture_integrity.json'),report)
    if len(accepted)<20 or len(excluded)>max(2,len(captures)*.1):raise RuntimeError('Excessive Android control exclusions: '+source)
    print('CAPTURE_INTEGRITY',source,len(accepted),'accepted',len(excluded),'excluded',flush=True)
    return accepted
