"""Read-only device/source checks before the command-sheet network tests.

Uses authorized ADB and pinned-key SSH for diagnostics. No test target, attack,
listener, firewall change, app installation or history clear is performed.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "validation"))
import controlled_phone_test as lab


def check_protocol_sources(protocol, phone, controller):
    if len(protocol.PEERS) != 2 or len({host for _, host, _ in protocol.PEERS}) != 2:
        raise RuntimeError("Configure two distinct owned SSH sources; see docs/NETWORK_TEST_PROCEDURE.md")
    prepared = protocol.preparation()
    contract = prepared["contract"]
    if (contract["phone"], contract["controller"]) != (phone, controller):
        raise RuntimeError("Phone/controller addresses changed; run protocol Prepare again")
    sources = []
    for name, host, expected in protocol.PEERS:
        if host not in contract["allowed_sources"]:
            raise RuntimeError("SSH source changed; run protocol Prepare again")
        actual = protocol.remote(host, "hostname").strip()
        if actual.casefold() != expected.casefold():
            raise RuntimeError(f"Pinned SSH source {name} hostname does not match configuration")
        sources.append({"name": name, "ssh_reachable": True, "hostname_verified": True})
    return sources


def run(suite):
    # Diagnose absent multi-PC setup before spending time on the single-PC cases.
    protocol = None
    if suite in {"All", "Protocol"}:
        import protocol_phone_test as protocol
        # The portable harness reads ssh_config.json. The original work-PC
        # harness can expose the same verified peers from its retained private
        # setup; both still undergo fresh pinned-key hostname checks below.
        if not protocol.PEERS:
            raise RuntimeError("Missing private SSH configuration; follow docs/NETWORK_TEST_PROCEDURE.md, then protocol Prepare")
        if len(protocol.PEERS) != 2:
            raise RuntimeError("Exactly two verified SSH PCs are required for this protocol suite")
    lab.select_phone()
    phone, controller = lab.endpoints()
    if "uid=0" not in lab.adb("shell", "su", "-c", "id"):
        raise RuntimeError("Shell root is not granted; the network lab requires an already-rooted test phone")
    state = lab.monitor_state()
    if not state["enabled"] or not state["foreground"]:
        raise RuntimeError("Enable Rakshak network monitoring before running tests; preflight does not override Pause")
    if state["history_age_seconds"] is None or state["history_age_seconds"] < 300:
        raise RuntimeError("Connection history is not ready; leave monitoring running for at least 300 seconds")
    tools = lab.adb("shell", "su", "-c", "/data/local/tmp/tcpdump --help")
    if "--immediate-mode" not in tools:
        raise RuntimeError("A compatible ARM64 tcpdump with --immediate-mode is required")
    for package in ("nids.app", "nids.trafficlab") + (("nids.protocollab",) if protocol else ()):
        if "package:" not in lab.adb("shell", "pm", "path", package):
            raise RuntimeError("Required package is not installed: " + package)
    free_pc = shutil.disk_usage(ROOT).free
    minimum = 2 * 1024**3
    if free_pc < minimum:
        raise RuntimeError("At least 2 GiB free on the controller is required for captures")
    df = lab.adb("shell", "df", "-k", "/data/local/tmp").splitlines()
    try:
        free_phone = int(df[-1].split()[3]) * 1024
    except (ValueError, IndexError):
        raise RuntimeError("Could not read phone capture storage; inspect adb shell df -k /data/local/tmp")
    if free_phone < minimum:
        raise RuntimeError("At least 2 GiB free on the phone is required for captures")
    # Hash-check installed models without scoring any traffic or altering their state.
    import hashlib
    for kind in ("gate", "diagnosis"):
        manifest = json.loads((ROOT / f"android/app/src/main/assets/aligned_v2_{kind}_manifest.json").read_text())
        data = lab.adb("exec-out", "run-as", "nids.app", "cat", f"files/aligned_v2_{kind}.pte", binary=True)
        if hashlib.sha256(data).hexdigest() != manifest["model_sha256"]:
            raise RuntimeError("Installed network model differs from this checkout: " + kind)
    sources = check_protocol_sources(protocol, phone, controller) if protocol else []
    return {"passed": True, "suite": suite, "selected_phone_authorized": True,
            "phone_wlan_and_controller_route": True, "root_granted": True,
            "monitor_running": True, "history_ready": True, "models_match": True,
            "capture_storage_checked": True, "sources": sources,
            "test_requests_sent": 0, "listeners_started": 0,
            "scope": "Read-only ADB/SSH diagnostics; actual target paths are checked again by each case. Keep the phone unlocked."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("All", "Controlled", "Protocol"), default="All")
    args = parser.parse_args()
    try:
        result = run(args.suite)
    except Exception as error:
        print("PREFLIGHT STOPPED: " + str(error), file=sys.stderr)
        raise SystemExit(1)
    folder = ROOT / "runs/network_test_suite"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "preflight.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
