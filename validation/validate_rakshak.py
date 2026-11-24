"""Android integration checks against bundled fixtures; no live attack or carrier SMS."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def find_adb(explicit: str | None) -> str:
    candidates = [explicit, shutil.which("adb")]
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(variable):
            candidates.append(str(Path(os.environ[variable]) / "platform-tools" / "adb.exe"))
    candidates += [str(Path.home() / "AppData/Local/Android/Sdk/platform-tools/adb.exe"),
                   "D:/AndroidStudioData/platform-tools/adb.exe"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("Set --adb or ANDROID_HOME to the Android SDK containing adb.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="Explicit adb serial, never auto-select a phone")
    parser.add_argument("--adb")
    parser.add_argument("--install", action="store_true", help="Upgrade app and install debug test APK")
    parser.add_argument("--include-service", action="store_true", help="Temporarily pause capture; run marked local fixture notifications, then restore capture")
    parser.add_argument("--modes", nargs="+", default=["rakshak_contract", "rakshak_urls", "rakshak_sms", "hybrid_contract", "aligned_v2_native"])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    allowed = {"rakshak_contract", "rakshak_urls", "rakshak_sms", "rakshak_service", "hybrid_contract", "aligned_v2_native"}
    if set(args.modes) - allowed:
        parser.error("Unsupported mode. This tool only runs offline integration fixtures.")
    modes = list(dict.fromkeys(args.modes + (["rakshak_service"] if args.include_service else [])))
    directory = args.output or ROOT / "runs" / "rakshak_validation" / time.strftime("%Y%m%d_%H%M%S")
    directory.mkdir(parents=True, exist_ok=True)
    adb = [find_adb(args.adb), "-s", args.serial]

    def command(*parts: str, timeout: int = 900) -> str:
        result = subprocess.run(adb + list(parts), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode:
            raise RuntimeError((result.stdout + result.stderr)[-2000:])
        return result.stdout

    if command("get-state").strip() != "device":
        raise SystemExit("Selected Android device is not ready. Unlock it and accept USB debugging.")
    if args.install:
        for apk in [ROOT / "android/app/build/outputs/apk/debug/app-debug.apk",
                    ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"]:
            print(command("install", "-r", str(apk)), flush=True)
    report = {"serial": args.serial, "started_unix": time.time(),
              "model": command("shell", "getprop", "ro.product.model").strip(),
              "abi": command("shell", "getprop", "ro.product.cpu.abi").strip(), "results": {}}
    package_paths = command("shell", "pm", "path", "nids.app").splitlines()
    base_apk = next((line[8:] for line in package_paths if line.startswith("package:") and line.endswith("/base.apk")), None)
    if base_apk is None:
        raise SystemExit("Selected device has no installed nids.app base APK.")
    report["installed_apk_sha256"] = command("shell", "sha256sum", base_apk).split()[0]
    for mode in modes:
        print("Running", mode, flush=True)
        started = time.monotonic()
        output = command("shell", "am", "instrument", "-w", "-e", "mode", mode,
                         "nids.app.test/nids.app.ValidationInstrumentation")
        (directory / (mode + ".log")).write_text(output, encoding="utf-8")
        payload = None
        for line in output.splitlines():
            for prefix in ("INSTRUMENTATION_RESULT: summary=", "INSTRUMENTATION_RESULT: report="):
                if line.startswith(prefix):
                    payload = json.loads(line[len(prefix):])
        if payload is None:
            payload = {"passed": False, "error": "No JSON result. Inspect the saved instrumentation log."}
        payload["test_wall_seconds"] = round(time.monotonic() - started, 3)
        report["results"][mode] = payload
        report["passed"] = all(item.get("passed") is True for item in report["results"].values())
        (directory / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(mode, "PASS" if payload.get("passed") else "FAIL", flush=True)
        if not payload.get("passed"):
            raise SystemExit("Validation failed; inspect " + str(directory))
    print("All selected checks passed. Results:", directory, flush=True)


if __name__ == "__main__":
    main()
