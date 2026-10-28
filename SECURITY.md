# Security policy

## Supported versions

The latest `0.1.x` source release is supported with security fixes. Older
versions are not maintained.

## Reporting a vulnerability

Do not include credentials, production captures, or exploit details in a public
issue. Open a minimal issue asking the maintainer for a private channel, or use
the repository's **Security → Report a vulnerability** form when private
vulnerability reporting is enabled.

Include the affected version/commit, a synthetic reproducer, impact and any
known mitigation. Never send a real API key, cookie, Authorization header or
personal data.

## Security model and limitations

- The CLI processes untrusted local files. Redaction runs before parsing, and
  the rendered report is checked again before printing.
- v0.1 is offline: it opens no network listener and makes no outbound requests.
- Rules are data and unsigned. Treat third-party rule files as code you must
  review.
- Inputs are parsed in memory; there is no streaming parser or explicit
  large-file cap yet. Do not feed it untrusted multi-gigabyte captures.
- Attribution is diagnostic, not an enforcement or access-control mechanism.
- This is an MIT-licensed volunteer project maintained on a best-effort basis;
  no response-time SLA is promised.
