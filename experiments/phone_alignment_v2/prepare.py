"""Detached CPU preparation. All class coverage checks finish before GPU training."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import concurrent.futures,json,os,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from experiments.phone_alignment_v2.common import *
from experiments.phone_alignment_v2.data import freeze_extractor,extract_source,consolidate


def main():
    RUN.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    freeze_extractor()
    atomic(RUN/'preparation_status.json',{'phase':'raw_extraction','pid':os.getpid(),'completed_sources':[],'total_sources':len(SOURCES),'started_unix':time.time()})
    complete=[]
    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as pool:
        futures={pool.submit(extract_source,s):s for s in SOURCES}
        for future in concurrent.futures.as_completed(futures):
            future.result();complete.append(futures[future])
            atomic(RUN/'preparation_status.json',{'phase':'raw_extraction','pid':os.getpid(),'completed_sources':complete,'total_sources':len(SOURCES),'updated_unix':time.time()})
    atomic(RUN/'preparation_status.json',{'phase':'split_normalize_and_coverage','pid':os.getpid(),'completed_sources':complete,'updated_unix':time.time()})
    consolidate()
    atomic(RUN/'preparation_status.json',{'phase':'ready','pid':os.getpid(),'completed_sources':complete,'updated_unix':time.time()})
    print('ALL_RAW_INPUTS_READY',flush=True)


if __name__=='__main__':
    try:main()
    except BaseException as error:
        atomic(RUN/'preparation_status.json',{'phase':'failed','error':str(error),'pid':os.getpid(),'updated_unix':time.time()});raise
