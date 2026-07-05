# Contributing to aws-ses-relay

Thanks for your interest in improving aws-ses-relay. This document covers how to
build, test, and propose changes.

## Getting started

Requirements:

- Rust (stable) — install via [rustup](https://rustup.rs).
- For a Lambda cross-compile: `cargo-lambda` and `zig`
  (`pip install cargo-lambda ziglang`), plus the `aarch64-unknown-linux-gnu`
  target (`rustup target add aarch64-unknown-linux-gnu`). The exact versions CI
  pins are in [`.github/workflows/release.yml`](.github/workflows/release.yml).

Build, test, and lint the way CI does:

```sh
cargo test                                  # unit tests live inline in each module
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI also enforces a line-coverage floor. To reproduce it locally, install
`cargo-llvm-cov` (`brew install cargo-llvm-cov` or `cargo install cargo-llvm-cov`)
and the `llvm-tools-preview` component, then:

```sh
cargo llvm-cov --fail-under-lines 90 --ignore-filename-regex 'main\.rs$'
```

Cross-compile for the runtime:

```sh
cargo lambda build --release --arm64
```

## Making changes

- **Tests ship with the code.** Every behavior change comes with a test in the
  same change. CI runs tests, clippy, formatting, the coverage floor, and a
  dependency audit — all must pass.
- **Conventional Commits.** Prefix messages with `feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`, `ci:`, etc. Keep each commit to one logical
  change.
- **Style.** Idiomatic Rust with `cargo fmt` defaults; prefer clear over clever,
  and full words over abbreviations.
- **No real identifiers.** Use `example.com` / `example.net` and `YOUR_*`
  placeholders everywhere — never a real address, domain, or bucket name.

## Proposing a change

1. For anything non-trivial, open an issue first so the approach can be discussed.
2. Fork, branch, and make your change with tests.
3. Open a pull request, fill in the template, and make sure CI is green.

## Security

Please do **not** open public issues for security problems — see
[SECURITY.md](SECURITY.md) for private reporting.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating you are expected to uphold it.
