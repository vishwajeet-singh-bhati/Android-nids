"""Build isolated baseline/candidate JVM runners with the installed Kotlin compiler."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

def main():
    installed = Path(os.environ["LOCALAPPDATA"]) / "Temp/opencode/bharat_tools"
    java_home = installed / "jdk17/jdk-17.0.21+9"
    compiler = installed / "kotlin/kotlinc/lib/kotlin-compiler.jar"
    sources = sorted((ROOT / "tier1-kotlin/src/main/kotlin").rglob("*.kt")) + sorted((ROOT / "tier1-kotlin/src/test/kotlin").rglob("*.kt"))
    target = ROOT / "tier1-kotlin/build"
    target.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for mode in ("baseline", "candidate"):
        selected = [HERE / "baseline/CascadePolicy.kt" if mode == "baseline" and p.name == "CascadePolicy.kt" else p for p in sources]
        output = target / f"{mode}-batch.jar"
        subprocess.run([str(java_home / "bin/java.exe"), "-jar", str(compiler), *map(str, selected), "-include-runtime", "-d", str(output)], check=True)
        hashes[mode] = {"jar_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in selected}}
    subprocess.run([str(java_home / "bin/java.exe"), "-jar", str(target / "candidate-batch.jar"), "--cascade", str(ROOT / "artifacts/model/portable/portable_model.json")], check=True)
    out = ROOT / "artifacts/reports/automation_review"
    out.mkdir(parents=True, exist_ok=True)
    (out / "kotlin_build.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")

if __name__ == "__main__": main()
