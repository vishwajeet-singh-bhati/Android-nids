"""Verify the packaged model/suite and compiled manifest without installing."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]

def main():
    apk = ROOT / "android-app/app/build/outputs/apk/debug/app-debug.apk"
    meta = json.loads((apk.parent / "output-metadata.json").read_text())
    assert meta["elements"][0]["versionName"] == "0.5.0"
    sha = lambda data: hashlib.sha256(data).hexdigest()
    pte = ROOT / "experiments/mobilebert/qat/artifacts/ptq_int8_b1.pte"
    checks = {}
    with zipfile.ZipFile(apk) as z:
        for name, local in [("assets/ptq_int8_b1.pte", pte),
            ("assets/vocab.txt", ROOT / "experiments/mobilebert/checkpoints/mobilebert22_lr5e5_bs16_e4/best/vocab.txt"),
            ("assets/portable_model.json", ROOT / "artifacts/model/portable/portable_model.json")]:
            assert z.read(name) == local.read_bytes(), name
            checks[name] = sha(z.read(name))
        suite = json.loads(z.read("assets/benchmark_suite.json"))
        local_suite = json.loads((ROOT / "experiments/automation_review/challenge.json").read_text(encoding="utf-8"))
        assert suite == local_suite and len(suite["cases"]) == 230
        native = sorted({n.split("/")[1] for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")})
    aapt = Path(os.environ["LOCALAPPDATA"]) / "Temp/opencode/bharat_tools/android-sdk/build-tools/36.0.0/aapt2.exe"
    badging = subprocess.run([str(aapt), "dump", "badging", str(apk)], capture_output=True, text=True, check=True).stdout
    permissions = [s for s in badging.splitlines() if s.startswith("uses-permission:")]
    assert not any("android.permission.INTERNET" in s for s in permissions)
    assert any("android.permission.RECEIVE_SMS" in s for s in permissions)
    assert any("android.permission.POST_NOTIFICATIONS" in s for s in permissions)
    result = {"build_success": True, "version": "0.5.0", "version_code": 8,
        "apk_bytes": apk.stat().st_size, "apk_mib": apk.stat().st_size / 1048576,
        "apk_sha256": sha(apk.read_bytes()), "pte_bytes": pte.stat().st_size, "asset_sha256": checks,
        "suite_cases": 230, "suite_sha256": suite["rows_sha256"], "native_abis": native,
        "permissions": permissions, "installed_on_pixel": False, "phone_batch_executed": False}
    (ROOT / "artifacts/reports/automation_review/apk_validation.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == "__main__": main()
