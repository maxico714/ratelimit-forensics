# PRODUCT — ratelimit-forensics

## Problem

When an HTTP API returns 429, operators cannot determine which enforcement layer tripped (app middleware, gateway, CDN edge, or upstream provider). Headers drift across layers: GitLab #378212 shows `RateLimit-Remaining: 1757` with an immediate Cloudflare 429. Diagnosis today = manual correlation across dashboards, logs, and vendor docs. GitLab maintains an internal multi-page handbook + runbook for this. Microsoft admits "no metric warns ahead of time."

## Target users (personas)

1. **Platform/SRE engineer** debugging production 429s across nginx + Cloudflare + app middleware + upstream (OpenAI/Anthropic/GitHub).
2. **LLM/agent developer** hitting dual-dimension (requests+tokens) rate limits from OpenAI/Anthropic/OpenRouter with inconsistent 429 shapes.
3. **API consumer integrator** debugging third-party provider 429s whose headers follow vendor-specific formats.

## Jobs-to-be-done

- "Given this 429 I captured, which layer sent it and what's the reset window?"
- "Why did I get 429 when RateLimit-Remaining said 1757?"
- "Is this Retry-After a delta-seconds or an HTTP-date?"
- "Which of my 4 layers is the actual bottleneck?"

## Value proposition (one sentence)

Deterministically attribute any captured 429 to its enforcing layer with matched evidence and a confidence score — something no existing tool does (parsers stop at normalization; per-library DEBUG sees only itself).

## Non-goals

- Live probing of real providers (ToS/risk) — offline-first.
- Being a rate limiter (enforcement is out of scope).
- Guaranteeing "forensic verdict" accuracy — outputs confidence + evidence trace + explicit "insufficient evidence."

## MVP scope (MoSCoW)

**Must (v0.1):**
- Parse captured 429 from HAR / headers.txt / curl -i dump
- Support header surfaces: X-RateLimit-*, RateLimit-* (split + IETF draft-8), Retry-After (delta vs HTTP-date), OpenAI dual-dimension, Anthropic anthropic-ratelimit-*, Cloudflare absence-signal
- Body pattern matching: Cloudflare error 1015, OpenAI/Anthropic/Google structured errors
- Attribution: edge/CDN vs gateway/proxy vs app vs upstream provider, with confidence score + evidence trace
- Rules-as-data (versioned YAML attribution rules)
- Redaction of secrets/API keys from logs before processing
- Explicit "insufficient evidence" state

**Should (v0.2):**
- Recurring hook: proxy mode / CI check / Slack-alert (stated as actual product, not bullet)
- IETF RateLimit-Policy header parsing
- Access-log line correlation (tiebreaker when headers conflict)

**Could:**
- Watch mode on live traffic (opt-in, local only)
- Prometheus metrics export of attribution outcomes

**Won't (v1):**
- Live provider probing
- Multi-node distributed diagnosis
- Non-HTTP protocols (gRPC/WebSocket)

## Success criteria (measurable, testable)

1. Synthetic 429 fixtures from local Express/Flask/nginx/Envoy + mocklimit provider templates: attribution correct ≥90% across fixture matrix (L2 integration).
2. Ambiguous/malformed headers produce "insufficient evidence" — never a wrong confident verdict (L5 adversarial).
3. Redaction: no API keys/tokens appear in output or logs (L5 security pass).
4. README quickstart works from clean clone (L4).
5. Analysis of a 10k-line HAR completes in <2s (performance budget).

## Honest comparison with existing tools

| Tool | Better at | Weaker at |
|---|---|---|
| express-rate-limit DEBUG | deep middleware internals | one layer only |
| Envoy RLS debug | Envoy-internal state | one layer only |
| Datadog | live dashboards, alerting | Datadog's own APIs only; commercial |
| ratelimit-header-parser | multi-format normalization | no attribution |
| llm-limits-tracker | live LLM provider monitoring | monitoring, not incident forensics |
| GitLab handbook (prose) | org-specific runbook | manual, not a tool |

## Name check

`ratelimit-forensics` — [VERIFIED] free on PyPI + npm (all 404, 2026-10-13). No trademark conflicts found. Searchable, pronounceable.

## License

MIT. Dependencies must be MIT/Apache-2.0/BSD-compatible. mocklimit fixtures (MIT) may be vendored with attribution.

## Risk register

| Risk | Type | Mitigation |
|---|---|---|
| Wrong attribution worse than none (automation bias) | Technical | Confidence score mandatory; "insufficient evidence" first-class; never claim forensic verdict |
| Header format detection-rot (providers change bodies) | Maintenance | Rules-as-data (versioned YAML); fixture-driven regression tests |
| Offline = one-shot-per-incident (vitamin adoption) | Adoption | v0.2 recurring hook is the actual product path, not a bullet |
| Log ingestion = PII/secret surface | Security | Redaction from day one; A8 checklist |
| Doctor-slot contention (D-43, A2) | Portfolio | Scheduling constraint in ADR-006: defer if operator picks a doctor at G1 |
| Cloudflare adds RateLimit headers to 429s upstream | Competitor | Absence-signal is one heuristic among many; body patterns + multi-layer evidence remain |
