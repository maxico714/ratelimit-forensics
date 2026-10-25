# ratelimit-forensics

**Point it at a captured HTTP 429 and it tells you which layer enforced the limit, why, and when it resets — offline.**

Rate limits are enforced at several layers at once: CDN edge, API gateway, application middleware, and the upstream provider. When a 429 arrives, each layer's headers drift independently — GitLab's issue [#378212](https://gitlab.com/gitlab-org/gitlab/-/issues/378212) shows `RateLimit-Remaining: 1757` next to an immediate Cloudflare 429. Existing tools either see only their own layer (framework debug logs, Envoy RLS) or normalize headers without attributing them.

`ratelimit-forensics` reads a HAR file, a `curl -i` dump, or a raw header block and returns a layer, a vendor, a confidence score, the evidence that fired, the reset window, and any contradictions it found. It never makes a network call.

## Status

v0.1.0, source release. Not on PyPI yet. Everything below is exercised by the test suite in this repository.

## Install from source

```bash
git clone https://github.com/maxico714/ratelimit-forensics.git
cd ratelimit-forensics
python -m pip install -e .
```

Requires Python 3.10+ and `PyYAML` (installed automatically).

## Quickstart

```bash
# from a HAR capture (the first 429 entry is analyzed)
ratelimit-forensics analyze --har incident.har

# from a curl -i dump
ratelimit-forensics analyze --curl-dump response.txt

# from a headers-only file
ratelimit-forensics analyze --headers headers.txt --json
```

Real output for `tests/fixtures/cloudflare_1015.txt`:

```text
Layer:      edge-cdn (cloudflare) [confidence: 0.92]
Evidence:   body matches a Cloudflare 1015 rate-limit page
            matched rule 'cloudflare-1015'
            RateLimit-* counters are absent (typical of an edge-layer 429)
            Retry-After is present
Policy:     unknown
Reset:      30s (delta-seconds, Retry-After)
```

And for a response where the app counter contradicts the edge verdict (`tests/fixtures/conflicting_layers.txt`):

```text
Layer:      edge-cdn (cloudflare) [confidence: 0.82]
Evidence:   body matches a Cloudflare 1015 rate-limit page
            matched rule 'cloudflare-1015'
            conflicting evidence lowered the confidence
Policy:     unknown
Reset:      unknown
Note:       X-RateLimit-Remaining=1757 contradicts a 429 attributed to edge-cdn (the app counter says requests remain)
```

## What it understands

| Surface | Examples |
|---|---|
| `X-RateLimit-*` | `Limit`, `Remaining`, `Reset`, `Used`, `Resource` |
| IETF draft `RateLimit` / `RateLimit-Policy` | `RateLimit: "default";r=0;t=30`, `RateLimit-Policy: "default";q=100;w=60` |
| `Retry-After` | delta-seconds (`30`) and HTTP-date (`Wed, 25 Nov 2026 07:28:00 GMT`) |
| OpenAI | dual-dimension `x-ratelimit-*-requests` and `-tokens`, `rate_limit_exceeded` bodies |
| Anthropic | `anthropic-ratelimit-*` headers and `rate_limit_error` bodies |
| Google | `RESOURCE_EXHAUSTED` / quota bodies |
| Cloudflare | error 1015 pages and the "counters absent" edge signal |
| Generic | rate-limit JSON, text, and HTML bodies |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | An attribution was produced (possibly `insufficient_evidence`) |
| 2 | Input could not be parsed, or the rules could not be loaded |
| 3 | Redaction failed — a credential-shaped value survived and output was refused |

Ambiguity is explicit: low-confidence results set `insufficient_evidence: true` instead of guessing.

## Custom rules

Attribution is data, not code. Rules live in [`src/ratelimit_forensics/rules/default.yaml`](src/ratelimit_forensics/rules/default.yaml). Pass `--rules path/to/file-or-dir` to replace the packaged set:

```yaml
rules:
  - id: our-gateway
    layer: gateway
    vendor: kong
    confidence: 0.9
    when:
      all:
        - status: 429
        - header_equals: {server: kong}
    evidence:
      - "Server header names Kong"
```

Supported predicates: `status`, `header_present`, `header_absent`, `header_equals`, `header_matches`, `body_kind`, `body_contains`, `retry_after_present`. See [docs/TECHNICAL.md](docs/TECHNICAL.md).

## Privacy

- No network access; there is no telemetry.
- Authorization headers, `sk-…` keys, `ghp_…` tokens, `x-api-key`, and `api_key=`/`password=` assignments are redacted **before** parsing, and a post-redaction leak check refuses to print the report.
- Files are read locally and never uploaded.

## Honest limitations

- This is diagnosis, not enforcement: it will not limit, retry, or probe anything.
- Attribution is heuristic. Confidence and evidence are always shown; a mismatch between the body and the headers is reported as a conflict and lowers confidence rather than being hidden.
- v0.1 handles HTTP only, and expects a captured response. Live traffic capture is out of scope.
- The default rules are tuned on documented vendor behavior and synthetic fixtures; real-world captures may need a project-specific rule.

## Comparison

| Tool | Does | Missing here |
|---|---|---|
| `express-rate-limit` DEBUG | deep middleware state | sees only the app layer |
| Envoy RLS debug | gateway state | sees only Envoy |
| Datadog / vendor dashboards | live metrics and alerting | their own APIs; commercial |
| Header-parsing libraries | normalize header formats | no attribution or conflict analysis |

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
```

The suite covers parsers, body classifiers, rule evaluation, adapters, the CLI, and adversarial cases (conflicting layers, 10,000-entry HAR under two seconds, secret redaction).

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
