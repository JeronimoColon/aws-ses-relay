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

Currently ignored: none. The AWS SDK's legacy `hyper-rustls 0.24` /
`rustls 0.21` chain, the source of every earlier ignore, is no longer part of
the build.
