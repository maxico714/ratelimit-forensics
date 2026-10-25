# EVIDENCE — ratelimit-forensics

Access date for all: 2026-10-13. Protocol: A1 (no claim without evidence), A4 (ground truth order).

## Demand evidence (load-bearing)

| Artifact | Source | Reliability |
|---|---|---|
| GitLab #378212: RateLimit-Remaining=1757 then immediate Cloudflare 429 | gitlab.com/gitlab-org/gitlab/-/issues/378212 [VERIFIED fetched] | 5 |
| Microsoft: "no metric warns ahead of time — known limitation" (Azure OpenAI capacity throttling) | learn.microsoft.com Q&A 2026-01-26 [VERIFIED] | 4 (Azure-OpenAI-specific — note in README) |
| GitLab handbook: multi-layer diagnosis complicated; Cloudflare returns no RateLimit-*; internal runbook exists | handbook.gitlab.com [VERIFIED] | 5 |
| OpenAI community: "429 without reaching rate limit" 11.1k views | community.openai.com [reported by M2] | 4 |
| HN Tell HN id=41248542: GSC shows 5xx but Cloudflare edge returned 429 | news.ycombinator.com [reported by M2] | 4 |
| tianpan.co blog 2026-06: status/headers/body drift independently across layers | engineering blog [reported by M2] | 3 |

## Gap evidence (existence)

| Check | Result | Date |
|---|---|---|
| GitHub search "429 forensics" | 0 results | 2026-10-13 |
| GitHub "429 debugger/analyzer/attribution/rate limit forensics" | No repo owning cross-layer 429 attribution | 2026-10-13 |
| PyPI: 429-debugger, ratelimit-forensics, ratelimit-diagnose, ratelimit-inspector | All 404 | 2026-10-13 |
| npm: same set | All 404 | 2026-10-13 |
| Adjacent parsers (building blocks, not competitors): express-rate-limit/ratelimit-header-parser (npm MIT active), mre/rate-limits (Rust 16★ MIT), forbear (npm), ratelimit-headers (PyPI), limsy (Py 1★ prober), mocklimit (fixture source), llm-limits-tracker (8-provider monitoring), pitstop-check (static analysis) | Exist, none do attribution | 2026-10-13 |

## Feasibility evidence (host)

| Check | Result | Status |
|---|---|---|
| Synthetic 429s: local Express/Flask with rate limiting | Feasible offline (express-rate-limit DEBUG built-in) | [ASSUMED until Gate 0 spike] |
| Provider-accurate 429 fixtures: mocklimit (MIT, PyPI 0.6.0) | Ships OpenAI/Anthropic/Google error-body templates + per-limit header groups | [VERIFIED via M2] |
| Header surface: X-RateLimit-*, RateLimit-* + IETF draft-8, Retry-After delta vs HTTP-date, OpenAI dual-dim, Anthropic anthropic-ratelimit-*, Cloudflare absence | Verified across sources | [VERIFIED via M2] |
| Redaction: secrets in logs | A8 checklist applies; engine before parse | [ASSUMED until Gate 0 spike] |
| No Docker on host (D-001) | nginx/Envoy fixtures degraded; use pure-Express/Flask | [VERIFIED host constraint] |

## Verification level targets (per feature, A6)

- Parsers (X-RateLimit, RateLimit draft-8, Retry-After): **L1** unit + **L5** adversarial (HTTP-date edge cases)
- Body classifiers: **L1** unit + **L2** integration (mocklimit fixtures)
- Attribution engine: **L2** integration (fixture matrix) + **L5** (ambiguous → insufficient evidence)
- Redaction: **L5** security (secret-in-log adversarial)
- CLI + README: **L4** clean environment
- HAR performance: budget <2s for 10k lines

## Name check

`ratelimit-forensics` free on PyPI + npm (all 404, 2026-10-13). No trademark conflicts found.

## Known limitations (honest)

- Microsoft "known limitation" quote is Azure-OpenAI capacity-specific, not general rate-limit metrics — weaker fit; note in README.
- Attribution accuracy has no ground truth on this host (no Docker for full nginx/Envoy chain; no labeled corpus) — scope claim = "classify with confidence," never "forensic verdict."
- Offline = one-shot-per-incident unless v0.2 recurring hook ships (stated as actual product path in ROADMAP).
- Doctor-slot scheduling constraint: defer if operator picks D-43 or A2 at G1 (ADR-006).

## Skeptic findings (accepted, with conditions)

Source: ses_ecb37a058ffeNH... (2026-10-13)
- Wrong verdict worse than none → confidence + insufficient-evidence mandatory (adopted as conditions 2/5)
- Header stripping by intermediaries → absence-signal is one heuristic among many (adopted)
- Offline vs recurring-hook tension → v0.2 hook is actual product, not bullet (adopted as condition 3)
- Doctor-adjacent → scheduling constraint (adopted as condition 1)
