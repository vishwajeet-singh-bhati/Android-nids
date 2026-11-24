import json

from sms_detection.cli import main


def test_schema_command_writes_schema_without_model(tmp_path):
    path = tmp_path / "schema.json"
    exit_code = main(["schema", "--output", str(path)])

    assert exit_code == 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["title"] == "SMS detection result"
