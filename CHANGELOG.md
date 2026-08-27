# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-08-26

### Changed

- Updated dependencies to current releases: thiserror 2.0.20, plus the
  test-only http 1.5.0 and aws-smithy-types 1.6.2.
- Updated the transitive h2 0.4 line to 0.4.19, fixing RUSTSEC-2026-0258
  (unbounded empty DATA frames) in the HTTP/2 stack the function actually
  uses. The legacy h2 0.3.27, part of the AWS SDK's dormant hyper-rustls 0.24
  chain that is never constructed at runtime and has no fixed 0.3.x release,
  is documented as an accepted risk alongside the existing rustls-webpki
  advisories (see SECURITY.md).
- Bumped cargo-lambda to 1.9.2 in CI and the release pipeline so ARM64
  cross-compiles work on Rust 1.98, and refreshed pinned CI actions
  (Swatinem/rust-cache 2.9.2, dtolnay/rust-toolchain,
  taiki-e/install-action 2.86.7).

## [0.1.3] - 2026-07-27

### Changed

- Updated dependencies to current releases: aws-sdk-sesv2 1.125.0, tokio
  1.53.1, and serde_json 1.0.151, plus the test-only aws-smithy-runtime 1.12.1.
- Refreshed pinned CI actions: actions/checkout 7.0.1 and taiki-e/install-action
  2.85.2.

## [0.1.2] - 2026-07-26

### Changed

- Updated dependencies to current releases: aws-sdk-s3 1.138.1, tokio 1.53.0,
  serde 1.0.229, thiserror 2.0.19, and refreshed two pinned CI action SHAs
  (dtolnay/rust-toolchain, taiki-e/install-action 2.83.4).
- Moved the transitive `spin` crate off the yanked 0.10.0 to 0.10.1 (pulled in
  via aws-sdk-s3 -> aws-smithy-checksums -> crc-fast), clearing the yanked-crate
  warning from cargo audit and cargo deny.

## [0.1.1] - 2026-07-13

### Added

- The function logs its crate version as the first line of every cold start,
  so a deployed code swap is verifiable from CloudWatch alone.

### Changed

- Updated the AWS SDK crate family (aws-config 1.9.0, aws-sdk-s3 1.138.0,
  aws-sdk-sesv2 1.124.0, and their smithy dependencies) and lambda_runtime
  (1.3.0) to current releases. The crates move in lockstep, so the update
  lands as one set; Dependabot now groups them into a single weekly PR.
- Replaced the README's Mermaid diagrams with hand-drawn SVGs that follow
  GitHub's light and dark themes.

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

[0.1.3]: https://github.com/JeronimoColon/aws-ses-relay/releases/tag/v0.1.3
[0.1.2]: https://github.com/JeronimoColon/aws-ses-relay/releases/tag/v0.1.2
[0.1.1]: https://github.com/JeronimoColon/aws-ses-relay/releases/tag/v0.1.1
[0.1.0]: https://github.com/JeronimoColon/aws-ses-relay/releases/tag/v0.1.0
