"""Use the unchanged v2 architectures/training loop with a new isolated cache."""

import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from reproducibility.paths import adb_path,java_path,runtime_path,classpath,exclusive_file_lock,bootstrap_reference_extractor,train_command
import argparse
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
os.environ['NIDS_ALIGNED_RUN']=str(ROOT/'runs/phone_capture_training_v1')
os.environ['NIDS_ALIGNED_CACHE']=str(ROOT/'data/experiments/phone_capture_training_v1')
os.environ['NIDS_ALIGNED_PUBLIC']=str(ROOT/'validation/reports/phone_capture_training_v1')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--job',required=True);args=parser.parse_args()
    from experiments.phone_alignment_v2 import train as training
    training.SOURCES=(*training.SOURCES,'PHONE')
    training.train(args.job)


if __name__=='__main__':main()
