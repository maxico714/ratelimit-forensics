# TECHNICAL — ratelimit-forensics

## Architecture (C4 containers, Mermaid)

```mermaid
graph TB
    subgraph CLI
        A[CLI entrypoint<br/>ratelimit-forensics analyze]
    end
    subgraph Core
        B[Input adapters<br/>HAR / headers.txt / curl-dump]
        C[Redaction engine<br/>strip secrets before parse]
        D[Header parser<br/>X-RateLimit-* / RateLimit-* / Retry-After]
        E[Body classifier<br/>Cloudflare 1015 / OpenAI / Anthropic / Google / generic JSON]
        F[Rules engine<br/>YAML attribution rules + confidence scorer]
    end
    subgraph Output
        G[Attribution report<br/>layer + evidence + confidence + reset]
        H[JSON/SARIF export]
    end
    A --> B --> C --> D --> E --> F --> G
    F --> H
```

## Data model

### Input: captured 429
- Headers: key-value map (case-insensitive)
- Body: text/bytes (classified by pattern)
- Optional: one access-log line (tiebreaker)

### Attribution rule (YAML, rules-as-data)
```yaml
- id: cloudflare-edge-absence
  when:
    status: 429
    headers_absent: [RateLimit-Limit, RateLimit-Remaining, X-RateLimit-Limit]
    body_matches: cloudflare-error-1015
  then:
    layer: edge-cdn
    vendor: cloudflare
    confidence: 0.92
    evidence:
      - "body matches Cloudflare error 1015"
      - "RateLimit-* headers absent (Cloudflare edge 429s typically carry no counters)"
```

### Output: attribution report
```json
{
  "layer": "edge-cdn",
  "vendor": "cloudflare",
  "confidence": 0.92,
  "evidence": ["...", "..."],
  "policy": null,
  "window": {"reset": 30, "unit": "delta-seconds", "source": "Retry-After"},
  "conflicts": ["app-layer RateLimit-Remaining: 1757 contradicts edge 429"],
  "insufficient_evidence": false
}
```

## Public interfaces

- CLI: `ratelimit-forensics analyze --har|--headers|--curl-dump [--json]`
- Python API: `from ratelimit_forensics import analyze; analyze(headers=..., body=...) -> Attribution`
- Node API: `const { analyze } = require('ratelimit-forensics')`

## Error model

- Exit 0: attribution produced (any confidence, including "insufficient evidence")
- Exit 2: input unparseable (bad HAR, missing headers)
- Exit 3: redaction failure (secret detected but could not strip)
- Never: wrong confident verdict — ambiguous → `insufficient_evidence: true`

## Configuration model

- Rules dir: `~/.config/ratelimit-forensics/rules/` (user-overridable)
- Redaction patterns: built-in (Authorization, api_key, Bearer, sk-*, etc.) + user YAML
- No network calls, ever (offline-first)

## Performance budget

- 10k-line HAR analyzed in <2s (target)
- Memory: bounded by HAR size (streaming parse if >50MB)

## Threat model (STRIDE-lite)

- **Tampering**: rules-as-data could be tampered → ship signed default rules; user rules isolated
- **Information disclosure**: logs may contain API keys → redaction engine runs BEFORE parse; A8 checklist
- **Denial of service**: huge HAR → streaming parse + size cap
- **Elevation**: none (no network, no privileges)

## Privacy model

- Zero telemetry, zero network
- Redaction of secrets from all outputs by default
- Local-only processing

## Testing strategy (verification ladder)

- **L1 Unit**: each parser (X-RateLimit, RateLimit draft-8, Retry-After delta vs HTTP-date, OpenAI dual-dim, Anthropic), each body classifier, redaction patterns, confidence scorer
- **L2 Integration**: synthetic 429 fixtures from local Express/Flask/nginx/Envoy + mocklimit provider templates (MIT, vendored with attribution); full analyze pipeline
- **L4 Clean environment**: Docs-verifier follows README from fresh clone
- **L5 Adversarial**: malformed headers, HTTP-date Retry-After, conflicting status/header/body (tianpan.co pattern), huge HAR, secret-in-log redaction, ambiguous "insufficient evidence" cases

## Tech choices

- **Python 3.10+** (stdlib-first: urllib.parse, json, re, argparse; zero hard deps for v0.1)
  - Rejected: Go (no host toolchain), Node (secondary target later), Rust (no host toolchain)
- Rules-as-data: PyYAML (MIT) for attribution rules
- Testing: pytest + Hypothesis (property tests for Retry-After disambiguation)
- Rationale: most contributor-friendly for the LLM/dev-tools audience; mocklimit fixtures are Python

## Repository layout

```
ratelimit-forensics/
├── AGENTS.md
├── README.md
├── LICENSE (MIT)
├── pyproject.toml
├── src/ratelimit_forensics/
│   ├── __init__.py
│   ├── cli.py
│   ├── adapters/ (har.py, headers.py, curl_dump.py)
│   ├── redact.py
│   ├── parsers/ (x_ratelimit.py, ietf_draft8.py, retry_after.py, openai.py, anthropic.py)
│   ├── bodies/ (cloudflare.py, openai.py, anthropic.py, google.py)
│   ├── rules/ (engine.py, *.yaml)
│   └── report.py
├── tests/ (unit/, integration/, adversarial/, fixtures/)
└── docs/ (PRODUCT.md, TECHNICAL.md, ROADMAP.md, EVIDENCE.md)
```

## Coding conventions

- Python: type hints, ruff lint, pytest; rules-as-data (no hardcoded attribution in Python)
- Every README snippet = doc-test in CI
- Conventional Commits
