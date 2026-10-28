import pytest

from ratelimit_forensics.redact import RedactionError, assert_clean, redact


def test_bearer_token_is_redacted():
    clean, count = redact("Authorization: Bearer example-bearer-token\nHost: x")
    assert count == 1
    assert "example-bearer-token" not in clean
    assert "[REDACTED]" in clean
    assert_clean(clean)


def test_sk_key_is_redacted_anywhere():
    clean, _ = redact('{"key": "sk-live-abcdefgh12345678"}')
    assert "sk-live" not in clean
    assert clean.count("[REDACTED]") == 1


def test_api_key_assignment_is_redacted():
    clean, _ = redact("api_key=supersecretvalue&page=1")
    assert "supersecretvalue" not in clean
    assert "page=1" in clean


def test_quoted_json_secret_is_redacted():
    clean, _ = redact('{"password": "hunter2", "user": "alice"}')
    assert "hunter2" not in clean
    assert '"user": "alice"' in clean


def test_clean_text_is_unchanged():
    text = "HTTP/1.1 429 Too Many Requests\nRetry-After: 30\n"
    clean, count = redact(text)
    assert clean == text
    assert count == 0


def test_leak_check_raises_on_surviving_secret():
    with pytest.raises(RedactionError):
        assert_clean("x-api-key: example-bearer-token")
