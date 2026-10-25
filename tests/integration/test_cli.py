import json
from pathlib import Path

import pytest

from ratelimit_forensics import cli
from ratelimit_forensics.redact import RedactionError

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_cli_headers_text_output(capsys: pytest.CaptureFixture[str]):
    code = cli.main(["analyze", "--headers", str(FIXTURES / "cloudflare_1015.txt")])
    out = capsys.readouterr().out
    assert code == 0
    assert "edge-cdn" in out
    assert "cloudflare" in out
    assert "0.92" in out
    assert "Reset:" in out


def test_cli_json_output(capsys: pytest.CaptureFixture[str]):
    code = cli.main(["analyze", "--curl-dump", str(FIXTURES / "openai_429.txt"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["layer"] == "upstream"
    assert payload["vendor"] == "openai"
    assert payload["window"]["unit"] == "delta-seconds"
    assert payload["insufficient_evidence"] is False


def test_cli_har_input(capsys: pytest.CaptureFixture[str]):
    code = cli.main(["analyze", "--har", str(FIXTURES / "sample.har"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["vendor"] == "cloudflare"


def test_cli_unparseable_input_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    bad = tmp_path / "bad.txt"
    bad.write_text("not a response", encoding="utf-8")
    assert cli.main(["analyze", "--headers", str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_missing_file_exits_2(tmp_path: Path):
    assert cli.main(["analyze", "--headers", str(tmp_path / "nope.txt")]) == 2


def test_cli_bad_rules_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    code = cli.main(
        ["analyze", "--headers", str(FIXTURES / "cloudflare_1015.txt"), "--rules", str(rules)]
    )
    assert code == 2
    assert "cannot load rules" in capsys.readouterr().err


def test_cli_redaction_failure_exits_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def boom(_text: str) -> None:
        raise RedactionError("simulated leak")

    monkeypatch.setattr(cli, "assert_clean", boom)
    code = cli.main(["analyze", "--headers", str(FIXTURES / "cloudflare_1015.txt")])
    assert code == 3
    assert "redaction failed" in capsys.readouterr().err
