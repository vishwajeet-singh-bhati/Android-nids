from pathlib import Path
from types import SimpleNamespace

import pytest

from validation.network_test_plan import parse_plan
from validation.network_test_preflight import check_protocol_sources

ROOT = Path(__file__).resolve().parents[1]


def test_published_command_sheet_preserves_the_thirteen_case_sequence():
    text = (ROOT / "tests/NIDS_tests.sh").read_text()
    plan = parse_plan(text)
    assert [(r["kind"], r["profile"]) for r in plan if r["kind"] != "wait"] == [
        ("controlled", p) for p in ["Benign", "PortScan", "PasswordGuessing", "SQLInjection",
                                    "XSS", "ConnectionExhaustion", "HTTPFlood"]
    ] + [("protocol", p) for p in ["Benign", "FTPBruteForce", "SSHBruteForce", "BotBehavior", "DoS", "DDoS"]]
    assert sum(r["kind"] == "wait" for r in plan) == 8
    assert all(r["seconds"] == 305 for r in plan if r["kind"] == "wait")
    assert len(parse_plan(text, "Protocol")) == 6
    assert parse_plan(text, "Controlled")[-1]["profile"] == "HTTPFlood"


@pytest.mark.parametrize("line", ["Remove-Item -Recurse .", "Start-Sleep -Seconds 0",
                                 r".\validation\Run-ControlledPhoneTest.ps1 -Profile Clean",
                                 r".\validation\Run-ProtocolPhoneTest.ps1 -Profile DDoS; whoami"])
def test_command_sheet_rejects_arbitrary_shell_or_history_clearing(line):
    with pytest.raises(ValueError):
        parse_plan(line)


def protocol_fixture(remote):
    contract = {"phone": "10.0.0.10", "controller": "10.0.0.11", "allowed_sources": ["10.0.0.20", "10.0.0.21"]}
    return SimpleNamespace(PEERS=[("PC1", "10.0.0.20", "first"), ("PC2", "10.0.0.21", "second")],
                           preparation=lambda: {"contract": contract}, remote=remote)


def test_unreachable_source_stops_before_a_suite_can_start():
    calls = []
    def unreachable(host, command):
        calls.append((host, command))
        raise RuntimeError("SSH unavailable")
    with pytest.raises(RuntimeError, match="SSH unavailable"):
        check_protocol_sources(protocol_fixture(unreachable), "10.0.0.10", "10.0.0.11")
    assert calls == [("10.0.0.20", "hostname")]


def test_source_identity_and_stale_phone_are_rejected():
    with pytest.raises(RuntimeError, match="hostname"):
        check_protocol_sources(protocol_fixture(lambda *_: "wrong-PC"), "10.0.0.10", "10.0.0.11")
    with pytest.raises(RuntimeError, match="addresses changed"):
        check_protocol_sources(protocol_fixture(lambda *_: "unused"), "10.0.0.99", "10.0.0.11")


def test_both_pinned_sources_are_checked_without_attack_commands():
    calls = []
    def remote(host, command):
        calls.append(command)
        return {"10.0.0.20": "FIRST", "10.0.0.21": "SECOND"}[host]
    rows = check_protocol_sources(protocol_fixture(remote), "10.0.0.10", "10.0.0.11")
    assert len(rows) == 2 and all(row["hostname_verified"] for row in rows)
    assert calls == ["hostname", "hostname"]
