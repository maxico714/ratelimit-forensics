import base64
import json
from pathlib import Path

import pytest

from ratelimit_forensics.adapters import (
    ParseError,
    parse_access_log_line,
    parse_har,
    parse_http_response,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_parse_full_response():
    captured = parse_http_response((FIXTURES / "cloudflare_1015.txt").read_text(encoding="utf-8"))
    assert captured.status == 429
    assert captured.headers["server"] == "cloudflare"
    assert captured.headers["retry-after"] == "30"
    assert "Error 1015" in captured.body


def test_parse_headers_only_defaults_to_429():
    captured = parse_http_response("Retry-After: 5\nX-Test: 1\n")
    assert captured.status == 429
    assert captured.headers["x-test"] == "1"


def test_duplicate_headers_are_joined():
    captured = parse_http_response("A: one\nA: two\n\n")
    assert captured.headers["a"] == "one, two"


def test_non_header_input_is_rejected():
    with pytest.raises(ParseError):
        parse_http_response("just a sentence\n")


def test_empty_input_is_rejected():
    with pytest.raises(ParseError):
        parse_http_response("\n\n")


def test_parse_har_picks_the_429_entry():
    captured = parse_har((FIXTURES / "sample.har").read_text(encoding="utf-8"))
    assert captured.status == 429
    assert captured.headers["server"] == "cloudflare"
    assert "1015" in captured.body


def test_parse_har_without_429_fails():
    payload = {"log": {"entries": [{"response": {"status": 200}}]}}
    with pytest.raises(ParseError):
        parse_har(payload)


def test_parse_har_invalid_json_fails():
    with pytest.raises(ParseError):
        parse_har("{not json")


def test_parse_har_base64_body():
    payload = {
        "log": {
            "entries": [
                {
                    "response": {
                        "status": 429,
                        "headers": [{"name": "x-test", "value": "1"}],
                        "content": {
                            "text": base64.b64encode(b"rate limit").decode(),
                            "encoding": "base64",
                        },
                    }
                }
            ]
        }
    }
    assert parse_har(payload).body == "rate limit"


def test_access_log_line_notes():
    assert parse_access_log_line('1.2.3.4 - - [25/Oct/2026] "GET /x HTTP/1.1" 429 12') != ()
    assert parse_access_log_line('1.2.3.4 - - "GET /x HTTP/1.1" 200 12') == ()

    notes = parse_access_log_line(
        '1.2.3.4 - - [25/Oct/2026] "GET /x HTTP/1.1" 429 12 "-" "curl" cf-ray'
    )
    assert any("access log" in note for note in notes)


def test_access_log_line_credentials_are_redacted():
    notes = parse_access_log_line(
        "1.2.3.4 429 GET /x api_key=supersecretvalue Authorization: Bearer sk-live-abcdefghijklmnop"
    )
    joined = " ".join(notes)
    assert "supersecretvalue" not in joined
    assert "sk-live-abcdefghijklmnop" not in joined
    assert "[REDACTED]" in joined


def test_har_json_roundtrip_via_bytes():
    data = json.loads((FIXTURES / "sample.har").read_text(encoding="utf-8"))
    assert parse_har(json.dumps(data).encode()).status == 429
