# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-06

### Added

- Rust AWS Lambda that forwards inbound SES email: reads the raw message from
  S3, rewrites the headers SES requires (`From` → verified sender, `Reply-To` →
  original sender, strips `Return-Path`/`Sender`/`Message-ID`/`DKIM-Signature`,
  optional `Subject` prefix) byte-for-byte, and re-sends via SESv2.
- Environment-variable configuration with aggregated validation (`FROM_EMAIL`,
  `EMAIL_BUCKET`, `FORWARD_MAPPING`, and optional `SUBJECT_PREFIX`,
  `ALLOW_PLUS_SIGN`, `DROP_SPAM`, `DROP_UNSCANNED`, `IDEMPOTENCY_BUCKET`).
- Destination resolution with precedence (full address → domain → mailbox →
  catch-all), plus-tag stripping, and a per-key destination cap.
- Verdict gate: drops on virus `FAIL` (always) and spam `FAIL` (with
  `DROP_SPAM`); fail-open by default with a visible `WARN`, and `DROP_UNSCANNED`
  to fail closed.
- Opt-in duplicate suppression via S3 conditional writes (`IDEMPOTENCY_BUCKET`).
- Operator documentation: `README.md`, a from-scratch deploy runbook
  (`docs/DEPLOY.md`) with ready-to-apply IAM and S3 policies under `deploy/`.
- CI (build, test, clippy, format, coverage floor, dependency audit) and a
  tag-triggered release pipeline that publishes the ARM64 Lambda package.

[0.1.0]: https://github.com/JeronimoColon/aws-ses-relay/releases/tag/v0.1.0
