"""Correlate model flags with saved companion traffic; never infer attack truth."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import ipaddress
import struct
from pathlib import Path


def endpoint(value):
    try:
        host,port=value.rsplit(':',1)
        return (str(ipaddress.ip_address(host.strip('[]').split('%')[0])),int(port))
    except (ValueError,AttributeError):return None


def key(proto,first,second):
    return (proto,*sorted((first,second)))


def captured_tcp_tuples(path):
    """Exact IPv4 TCP endpoint/port pairs from current manual IPv4 test captures."""
    path=Path(path)
    if not path.exists():return None,'Companion PCAP unavailable'
    try:
        with path.open('rb') as stream:
            header=stream.read(24)
            if len(header)!=24:raise ValueError('Missing PCAP header')
            if header[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'):endian='<'
            elif header[:4] in (b'\xa1\xb2\xc3\xd4',b'\xa1\xb2\x3c\x4d'):endian='>'
            else:raise ValueError('Unsupported PCAP format')
            link=struct.unpack_from(endian+'I',header,20)[0];result=set();unsupported=0
            while True:
                record=stream.read(16)
                if not record:break
                if len(record)!=16:raise ValueError('Truncated PCAP record')
                size=struct.unpack_from(endian+'I',record,8)[0]
                if size>65536:raise ValueError('Oversized PCAP record')
                b=stream.read(size)
                if len(b)!=size:raise ValueError('Truncated PCAP frame')
                off={1:14,113:16,276:20,101:0}.get(link)
                if off is None:unsupported+=1;continue
                if link==1 and len(b)>=14:
                    et=struct.unpack_from('!H',b,12)[0]
                    while et in (0x8100,0x88a8,0x9100) and len(b)>=off+4:
                        et=struct.unpack_from('!H',b,off+2)[0];off+=4
                if len(b)<off+20 or b[off]>>4!=4:unsupported+=1;continue
                ihl=(b[off]&15)*4;tcp=off+ihl
                if ihl<20 or len(b)<tcp+4 or b[off+9]!=6:continue
                source=str(ipaddress.ip_address(b[off+12:off+16]));destination=str(ipaddress.ip_address(b[off+16:off+20]))
                sport,dport=struct.unpack_from('!HH',b,tcp)
                result.add(key(6,(source,sport),(destination,dport)))
        note=f'Exact IPv4 TCP tuple matching; {unsupported} unsupported records. A match establishes traffic association, not maliciousness or correct diagnosis.'
        return result,note
    except (ValueError,OSError,struct.error) as error:return None,str(error)


def correlate(flags,meta,path):
    captured,note=captured_tcp_tuples(path)
    try:expected={str(ipaddress.ip_address(meta['phone'])),str(ipaddress.ip_address(meta['controller']))}
    except (KeyError,ValueError,TypeError):expected=None
    reviewed=[];counts={'matched_test_capture':0,'outside_test_endpoints':0,'same_endpoints_not_in_capture':0,'unresolved':0}
    for flag in flags:
        owner=flag.get('attribution') or {};first=endpoint(owner.get('initiator'));second=endpoint(owner.get('responder'))
        transport={'TCP':6,'UDP':17}.get(owner.get('transport'));category='unresolved'
        if first and second and expected is not None:
            if {first[0],second[0]}!=expected:category='outside_test_endpoints'
            elif captured is not None and transport:
                category='matched_test_capture' if key(transport,first,second) in captured else 'same_endpoints_not_in_capture'
        counts[category]+=1;reviewed.append(dict(flag,traffic_correlation=category))
    return {'counts':counts,'flags':reviewed,'capture_tuple_count':len(captured) if captured is not None else None,
        'capture_available_for_matching':captured is not None,'scope':note}


def smoke():
    # A co-occurring localhost flag must never become a claimed remote SQL hit.
    from unittest.mock import patch
    meta={'phone':'172.16.89.83','controller':'172.16.88.233'}
    actual=key(6,('172.16.89.83',43190),('172.16.88.233',53017))
    rows=[{'attribution':{'initiator':'127.0.0.1:46094','responder':'127.0.0.1:27042','transport':'TCP'}},
          {'attribution':{'initiator':'172.16.88.233:53017','responder':'172.16.89.83:43190','transport':'TCP'}},
          {'attribution':{'initiator':'172.16.89.83:43190','responder':'172.16.88.233:53017','transport':'TCP'}},
          {'attribution':{'initiator':'172.16.88.233:1','responder':'172.16.89.83:2','transport':'TCP'}},{}]
    import sys
    with patch.object(sys.modules[__name__],'captured_tcp_tuples',return_value=({actual},'fixture')):
        result=correlate(rows,meta,'unused')
    assert result['counts']=={'matched_test_capture':2,'outside_test_endpoints':1,'same_endpoints_not_in_capture':1,'unresolved':1}
    return {'passed':True,'localhost_flag_not_remote_test_detection':True,'both_directions_match_same_tuple':True,'missing_evidence_unresolved':True,'phone_actions':0}


if __name__=='__main__':print(smoke())
