# Security Policy

## Reporting a vulnerability

Please report suspected security issues privately rather than opening a public
issue. Use GitHub's **[Report a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
feature on this repository (Security → Advisories → Report a vulnerability).

Please include steps to reproduce, the impact you observed, and any relevant
configuration (with secrets redacted). You will receive an acknowledgement, and
a fix or mitigation will be coordinated before any public disclosure.

## Scope

This project handles inbound email bytes and calls AWS S3 and SES. Reports that
concern message handling, header rewriting, configuration parsing, or IAM
guidance in the README are in scope.

## Known advisories (accepted risk)

CI runs `cargo audit` on every push and fails on any advisory that is not
explicitly listed, with rationale, in [`.cargo/audit.toml`](.cargo/audit.toml).
The ignores are per-advisory-ID, so a new or different advisory still fails the
build.

Currently ignored:

- **RUSTSEC-2026-0098, RUSTSEC-2026-0099, RUSTSEC-2026-0104** - all in
  `rustls-webpki 0.101.7`, a transitive dependency of the AWS SDK's HTTP layer
  (`aws-smithy-http-client`, whose latest published release still pins the old
  `hyper-rustls 0.24` → `rustls 0.21` → `rustls-webpki 0.101.7`). The affected
  code is `rustls-webpki`'s **server-side** certificate handling; this Lambda is
  a TLS **client** connecting to AWS endpoints, so that path is not exercised.
  These ignores will be removed once the AWS SDK ships an HTTP layer that drops
  the old `rustls` line.
