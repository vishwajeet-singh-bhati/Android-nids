"""Read the historical PowerShell command sheet without evaluating shell text."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "controlled": {"Benign", "PortScan", "SlowScan", "PasswordGuessing", "SQLInjection",
                   "XSS", "ConnectionExhaustion", "HTTPFlood", "Beacon"},
    "protocol": {"Benign", "FTPBruteForce", "SSHBruteForce", "BotBehavior", "DoS", "DDoS"},
}


def parse_plan(text, suite="All"):
    if suite not in {"All", "Controlled", "Protocol"}:
        raise ValueError("Unknown suite")
    plan = []
    for line_number, original in enumerate(text.splitlines(), 1):
        line = original.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "Start-Sleep -Seconds 305":
            if suite != "Protocol":
                plan.append({"kind": "wait", "seconds": 305, "source_line": line_number})
            continue
        match = re.fullmatch(r"\.\\validation\\Run-(Controlled|Protocol)PhoneTest\.ps1 -Profile ([A-Za-z]+)", line)
        if not match:
            raise ValueError(f"Unsupported command on line {line_number}; no commands executed")
        kind, profile = match[1].lower(), match[2]
        if profile not in PROFILES[kind]:
            raise ValueError(f"Unsupported {kind} profile on line {line_number}")
        if suite == "All" or suite.lower() == kind:
            plan.append({"kind": kind, "profile": profile, "source_line": line_number})
    while plan and plan[-1]["kind"] == "wait":
        plan.pop()
    if not any(item["kind"] != "wait" for item in plan):
        raise ValueError("No test cases selected")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("All", "Controlled", "Protocol"), default="All")
    args = parser.parse_args()
    plan = parse_plan((ROOT / "tests/NIDS_tests.sh").read_text(encoding="utf-8-sig"), args.suite)
    print(json.dumps({"suite": args.suite, "plan": plan,
                      "cases": sum(item["kind"] != "wait" for item in plan),
                      "preview_only": True, "phone_actions": 0, "test_requests_sent": 0}))


if __name__ == "__main__":
    main()
