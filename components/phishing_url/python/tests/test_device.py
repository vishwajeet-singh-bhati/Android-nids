"""Device tooling: parity check, package, machine description, thread sweep."""
import json
import zipfile

import numpy as np
import pytest

from src.deploy import package as package_mod
from src.deploy.package import PackageError, build_package, verify_package
from src.inference import parity
from src.inference.benchmark import bench_threads
from src.inference.machine import linux_env, machine_info, parse_cpuinfo
from src.inference.runtime import ModelRuntime
from src.preprocessing.url_normalizer import normalize_url
from tests.test_inference import tiny  # noqa: F401  (module fixture)

URLS = [f"https://site{i}.example.org/login/{i}?id={i}" for i in range(70)]

PHONE_CPUINFO = "\n\n".join(
    [f"processor\t: {i}\nBogoMIPS\t: 38.40\nCPU implementer\t: 0x41\nCPU part\t: 0xd05" for i in range(4)]
    + [f"processor\t: {i}\nCPU implementer\t: 0x41\nCPU part\t: 0xd41" for i in range(4, 7)]
    + ["processor\t: 7\nCPU implementer\t: 0x41\nCPU part\t: 0xd44", "Hardware\t: Qualcomm"])


def test_parse_cpuinfo_names_arm_cores():
    freq = {"0": "1800000", "1": "1800000", "2": "1800000", "3": "1800000", "7": "2840000"}
    assert parse_cpuinfo(PHONE_CPUINFO, freq.get) == {
        "Cortex-A55 @ 1800 MHz": 4, "Cortex-A78": 3, "Cortex-X1 @ 2840 MHz": 1}
    assert parse_cpuinfo("processor : 0\nmodel name : Some x86 CPU\n") == {"Some x86 CPU": 1}
    assert parse_cpuinfo("processor : 0\nCPU implementer : 0x51\nCPU part : 0x804\n") == {
        "implementer 0x51 part 0x804": 1}
    m = machine_info()
    assert {"system", "machine", "cpu_count", "torch", "torch_threads"} <= set(m)
    assert "hostname" not in json.dumps(m).lower()


def test_linux_env_sees_android_under_proot(tmp_path):
    # a Raspberry Pi: real kernel name, no Android system folder
    assert linux_env("6.12.25+rpt-rpi-2712", tmp_path) == {"proot": False, "android": False}
    # Debian in proot-distro on a phone: made-up kernel name, but Android's /system is visible
    (tmp_path / "system").mkdir()
    (tmp_path / "system" / "build.prop").write_text("", encoding="utf-8")
    assert linux_env("6.17.0-PRoot-Distro", tmp_path) == {"proot": True, "android": True}
    # a real Android kernel name is enough on its own
    assert linux_env("5.10.198-android13-4-g1", tmp_path / "missing")["android"]


def write_urls(path):
    path.write_text("# sample\n" + "\n".join(URLS) + "\n", encoding="utf-8")
    return path


def test_parity_save_and_check(tiny, tmp_path, monkeypatch, capsys):  # noqa: F811
    urls = write_urls(tmp_path / "urls.txt")
    base = ["--urls", str(urls), "--bundle", str(tiny["bundle"].path), "--out", str(tmp_path / "r")]
    assert parity.main(["save", *base]) == 0
    ref_path = tmp_path / "r" / f"parity_{tiny['bundle'].model_version}.json"
    ref = json.loads(ref_path.read_text(encoding="utf-8"))
    assert ref["count"] == 70 and len(ref["probability"]) == 70 and "site1.example" not in ref_path.read_text()
    assert parity.main(["check", *base]) == 0
    assert "PASS" in capsys.readouterr().out

    # another machine whose numbers drift a little: still a pass under the tolerance
    rt = ModelRuntime(tiny["bundle"])
    drift = dict(ref, probability=[p + 1e-7 for p in ref["probability"]])
    assert parity.compare(drift, rt, parity.read_urls(urls))["passed"]
    # a real difference, a flipped decision, the wrong URLs, the wrong model: fail
    bad = dict(ref, probability=[p + 0.01 for p in ref["probability"]])
    assert not parity.compare(bad, rt, parity.read_urls(urls))["passed"]
    flipped = dict(ref, outcome=["PHISHING" if o != "PHISHING" else "LIKELY_SAFE" for o in ref["outcome"]])
    r = parity.compare(flipped, rt, parity.read_urls(urls))
    assert not r["passed"] and len(r["decision_flips"]) == 70
    assert "distance_to_threshold" in r["decision_flips"][0]
    assert not parity.compare(ref, rt, parity.read_urls(urls)[:-1])["passed"]
    assert "model version" in parity.compare(dict(ref, model_version="x"), rt, URLS)["problems"][0]
    ref_path.write_text(json.dumps(bad), encoding="utf-8")
    assert parity.main(["check", *base]) == 1


def test_package_is_complete_and_self_checking(tiny, tmp_path):  # noqa: F811
    root = tmp_path / "repo"
    for folder in ("src", "tests"):
        (root / folder / "pkg").mkdir(parents=True)
        (root / folder / "pkg" / "mod.py").write_text("x = 1\n", encoding="utf-8")
        (root / folder / "pkg" / "__pycache__").mkdir()
        (root / folder / "pkg" / "__pycache__" / "mod.cpython-311.pyc").write_bytes(b"\0")
    (root / "config").mkdir()
    (root / "config" / "cache.json").write_text("{}", encoding="utf-8")
    (root / "config" / "redirectors_local.txt").write_text("qr.example\n", encoding="utf-8")
    import shutil
    shutil.copytree(tiny["bundle"].path, root / "models" / "full_url")
    (root / "data" / "processed").mkdir(parents=True)
    urls = write_urls(root / "data" / "processed" / "benchmark_urls.txt")
    with pytest.raises(PackageError, match="parity"):
        build_package(root, threat_db=None)
    rt = ModelRuntime(root / "models" / "full_url")
    (root / "reports").mkdir()
    (root / "reports" / f"parity_{rt.model_version}.json").write_text(
        json.dumps(parity.save(rt, parity.read_urls(urls))), encoding="utf-8")
    with pytest.raises(PackageError, match="threat"):
        build_package(root)                                       # no database built here
    zpath = build_package(root, threat_db=None)
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("MANIFEST.json"))
        readme = zf.read("DEVICE_README.txt").decode()
        zf.extractall(tmp_path / "device")
    assert {"src/pkg/mod.py", "tests/pkg/mod.py", "config/cache.json", "config/redirectors_local.txt",
            "models/full_url/version.json", "models/full_url/popular.txt", "data/processed/benchmark_urls.txt",
            f"reports/parity_{rt.model_version}.json", "requirements-device.txt", "DEVICE_README.txt",
            "MANIFEST.json"} <= names
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)
    assert manifest["model_version"] == rt.model_version and not manifest["threat_db_included"]
    assert "download.pytorch.org/whl/cpu" in readme and "package verify" in readme
    assert "download.pytorch.org/whl/cpu" in (tmp_path / "device" / "requirements-device.txt").read_text()
    assert verify_package(tmp_path / "device") == []
    (tmp_path / "device" / "models" / "full_url" / "cnn.pt").write_bytes(b"changed")
    assert verify_package(tmp_path / "device") == ["models/full_url/cnn.pt"]

    (root / "config" / ".env").write_text("SAFE_BROWSING_API_KEY=x", encoding="utf-8")
    with zipfile.ZipFile(build_package(root, threat_db=None)) as zf:
        assert not any(".env" in n for n in zf.namelist())       # never collected
    (root / "config" / "secrets.json").write_text("{}", encoding="utf-8")
    with pytest.raises(PackageError, match="secret"):
        build_package(root, threat_db=None)


def test_package_verify_needs_only_the_standard_library():
    import subprocess
    import sys
    code = ("import sys; import src.deploy.package; "
            "print(sorted(m for m in ('numpy', 'torch', 'sklearn') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


def test_thread_sweep_restores_the_setting(tiny):  # noqa: F811
    import torch
    before = torch.get_num_threads()
    rt = ModelRuntime(tiny["bundle"])
    out = bench_threads(rt, [normalize_url(u) for u in URLS], (1, 2), min_batches=2, max_seconds=1)
    assert [(x["threads"], x["batch_size"]) for x in out] == [(1, 1), (1, 64), (2, 1), (2, 64)]
    assert torch.get_num_threads() == before and all(x["urls_per_second"] > 0 for x in out)
    assert np.isfinite([x["ms_per_url"] for x in out]).all()
    assert "whl/cpu" in package_mod.REQUIREMENTS
