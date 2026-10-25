from ratelimit_forensics.bodies import classify


def test_cloudflare_1015():
    assert (
        classify("<html><h1>Error 1015</h1>You are being rate limited.</html>") == "cloudflare-1015"
    )


def test_openai_error():
    body = '{"error": {"message": "Rate limit reached for gpt-4o", "type": "rate_limit_exceeded"}}'
    assert classify(body) == "openai"


def test_anthropic_error():
    body = '{"type": "error", "error": {"type": "rate_limit_error"}}'
    assert classify(body) == "anthropic"


def test_google_quota_error():
    assert classify('{"error": {"status": "RESOURCE_EXHAUSTED"}}') == "google"


def test_generic_json_rate_limit():
    assert classify('{"error": "Too Many Requests", "detail": "rate limit"}') == "generic-json"


def test_other_json_and_invalid_json():
    assert classify('{"ok": true}') == "json-other"
    assert classify('{"broken":') == "json-invalid"


def test_html_empty_and_text():
    assert classify("<!DOCTYPE html><html></html>") == "html"
    assert classify("") == "empty"
    assert classify("Too Many Requests") == "text"
    assert classify("unrelated") == "other"
