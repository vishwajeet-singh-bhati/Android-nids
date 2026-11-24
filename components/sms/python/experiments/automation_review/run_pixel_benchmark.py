"""Install and batch-test on one connected Android phone; preserve prior live logs."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "com.bharat.smsguard.app"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="ADB serial; optional if exactly one device is connected")
    parser.add_argument("--install", action="store_true", help="Update with the built debug APK; keeps app data")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    adb = Path(os.environ["LOCALAPPDATA"]) / "Temp/opencode/bharat_tools/android-sdk/platform-tools/adb.exe"
    def call(parts, check=True):
        return subprocess.run([str(adb), *parts], capture_output=True, check=check)
    devices = call(["devices"]).stdout.decode().splitlines()[1:]
    online = [line.split()[0] for line in devices if len(line.split()) == 2 and line.split()[1] == "device"]
    if args.serial and args.serial not in online:
        parser.error("Requested device is not online in ADB. Reconnect Wireless debugging first.")
    if not args.serial and len(online) != 1:
        parser.error("Connect exactly one device, or pass --serial. No changes made.")
    serial = args.serial or online[0]
    def device(parts, check=True): return call(["-s", serial, *parts], check)
    out = ROOT / "artifacts/reports/automation_review" / f"pixel-{time.time_ns()}"
    out.mkdir(parents=True)
    # Export before installing; tar stdout is written as bytes, never through shell redirection.
    saved = device(["exec-out", "run-as", PACKAGE, "tar", "cf", "-", "files/evaluations"], check=False)
    if saved.returncode == 0:
        (out / "preserved_live_evaluations.tar").write_bytes(saved.stdout)
        print("Preserved previous live SMS runs.", flush=True)
    else:
        (out / "preservation_status.json").write_text(json.dumps({"saved": False,
            "reason": "App or evaluations directory unavailable; existing data was not deleted"}))
    if args.install:
        apk = ROOT / "android-app/app/build/outputs/apk/debug/app-debug.apk"
        if not apk.exists(): parser.error("Build the APK before using --install")
        device(["install", "-r", str(apk)])
    package_info = device(["shell", "dumpsys", "package", PACKAGE]).stdout.decode("utf-8", errors="replace")
    version = re.search(r"versionName=([^\s]+)", package_info)
    if not version or version.group(1) != "0.5.0":
        raise SystemExit("Expected app 0.5.0. Build the current APK and rerun with --install; no batch started.")
    def report():
        result = device(["exec-out", "run-as", PACKAGE, "cat", "files/last_benchmark.json"], check=False)
        try: return json.loads(result.stdout) if result.returncode == 0 else None
        except json.JSONDecodeError: return None
    old = report()
    old_id = old.get("benchmark_id") if old else None
    device(["shell", "am", "start", "-S", "-n", PACKAGE + "/.MainActivity", "--ez", "run_benchmark", "true"])
    print("Keep the app open. Synthetic batch started; no SMS sends are required.", flush=True)
    deadline = time.monotonic() + args.timeout
    last_progress = None
    while time.monotonic() < deadline:
        current = report()
        if current and current.get("benchmark_id") != old_id:
            (out / "summary.json").write_text(json.dumps(current, indent=2), encoding="utf-8")
            print(json.dumps({k: current[k] for k in ["total", "tier2_called", "engine_failures", "scams", "scams_warned", "non_scams", "non_scams_warned"]}), flush=True)
            print("Saved: " + str(out / "summary.json"))
            return
        progress = device(["exec-out", "run-as", PACKAGE, "cat", "files/benchmark_progress.json"], check=False)
        if progress.returncode == 0 and progress.stdout != last_progress:
            last_progress = progress.stdout
            print(progress.stdout.decode("utf-8"), flush=True)
        time.sleep(5)
    # The phone keeps per-case JSONL files even if this desktop wait times out.
    partial = device(["exec-out", "run-as", PACKAGE, "tar", "cf", "-", "files/benchmarks"], check=False)
    if partial.returncode == 0: (out / "partial_benchmarks.tar").write_bytes(partial.stdout)
    raise SystemExit("No completed new report within timeout. Partial results preserved; this is not a pass.")

if __name__ == "__main__": main()
