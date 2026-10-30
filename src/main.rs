//! Lambda bootstrap: initialize logging, load configuration and build the AWS
//! clients once at cold start, then serve invocations.

// Lambda builds link through Zig (via cargo-lambda), which ignores the -Wl,-O1
// that rustc passes to the linker for optimized builds and says so on stderr,
// so every release build reports it as a linker_messages warning. The flag has
// no effect on the binary.
//
// The allow covers the whole aarch64-unknown-linux-gnu target, so it hides every
// linker message for that target: the Lambda build, and also a native build on
// an ARM Linux machine. Builds for any other target keep the lint. A narrower
// scope is not available: `expect` cannot see linker messages, and setting
// RUSTFLAGS or target rustflags would replace cargo-lambda's own -C target-cpu.
// Remove once cargo-lambda ships a cargo-zigbuild that filters the flag
// (rust-cross/cargo-zigbuild#486, released in cargo-zigbuild 0.24.0).
#![cfg_attr(
    all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"),
    allow(linker_messages)
)]

mod config;
mod event;
mod forward;
mod handler;
mod idempotency;

use lambda_runtime::{run, service_fn, Error, LambdaEvent};

use crate::config::Config;
use crate::event::SesEvent;
use crate::handler::{handle_event, S3MessageStore, SesEmailSender};
use crate::idempotency::S3IdempotencyStore;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    init_tracing();

    // First line of every cold start: which build is running. Deploy swaps are
    // then verifiable from CloudWatch alone, without comparing code hashes.
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "aws-ses-relay starting"
    );

    // Load and validate configuration once. A configuration problem should fail
    // the cold start loudly rather than surface per-invocation.
    let config = Config::from_process_env().map_err(|error| {
        tracing::error!(%error, "invalid configuration; refusing to start");
        Error::from(error.to_string())
    })?;

    // Build the AWS clients once; they are reused across warm invocations. One
    // S3 client backs both the message store and the (opt-in) idempotency store.
    let aws_config = aws_config_loader().load().await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);
    let store = S3MessageStore::new(s3_client.clone());
    let idempotency = S3IdempotencyStore::new(s3_client, config.idempotency_bucket.clone());
    let sender = SesEmailSender::new(aws_sdk_sesv2::Client::new(&aws_config));

    run(service_fn(|event: LambdaEvent<SesEvent>| async {
        handle_event(event.payload, &config, &store, &sender, &idempotency)
            .await
            .map_err(|error| {
                // Log the failure with its full context (messageId, bucket, key,
                // recipient count) AND the underlying cause chain - the top-level
                // Display does not walk `#[source]`, so the real reason (e.g. an
                // S3 AccessDenied) would otherwise be lost.
                tracing::error!(
                    error = %error,
                    cause_chain = %error_cause_chain(&error),
                    "handler failed"
                );
                Error::from(error)
            })
    }))
    .await
}

/// The shared AWS configuration the S3 and SES clients are built from. The SDK
/// attaches its HTTPS client here, through the `default-https-client` feature.
fn aws_config_loader() -> aws_config::ConfigLoader {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
}

/// Join an error with its `source()` chain into a single `a: b: c` string.
fn error_cause_chain(error: &dyn std::error::Error) -> String {
    let mut chain = error.to_string();
    let mut current = error.source();
    while let Some(cause) = current {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        current = cause.source();
    }
    chain
}

/// Structured (JSON) logging. The level is read from `RUST_LOG`, defaulting to
/// `info`. Message bodies and raw events are never logged (see the handler).
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use aws_config::retry::RetryConfig;
    use aws_config::Region;
    use aws_sdk_s3::config::Credentials;
    use aws_sdk_s3::error::SdkError;

    use super::aws_config_loader;

    /// A local port nothing listens on, so a request ends in a refused
    /// connection and never reaches the network.
    const CLOSED_LOCAL_ENDPOINT: &str = "http://127.0.0.1:1";

    /// The production configuration, pointed at the closed local port, with
    /// fixed test credentials and no retries.
    async fn production_config_aimed_at_a_closed_port() -> aws_config::SdkConfig {
        let test_credentials = Credentials::new(
            "test-access-key-id",
            "test-secret-access-key",
            None,
            None,
            "test",
        );
        aws_config_loader()
            .region(Region::new("us-east-1"))
            .credentials_provider(test_credentials)
            .retry_config(RetryConfig::disabled())
            .endpoint_url(CLOSED_LOCAL_ENDPOINT)
            .load()
            .await
    }

    /// A refused connection proves a real HTTP client tried to connect. Without
    /// one, the SDK also reports a dispatch failure, but as "No HTTP client was
    /// available", which is not an I/O failure.
    fn assert_real_connection_was_attempted<E: Debug, R: Debug>(error: &SdkError<E, R>) {
        match error {
            SdkError::DispatchFailure(failure) => assert!(
                failure.is_io(),
                "expected an I/O failure from a real connection attempt, got: {failure:?}"
            ),
            other => panic!("expected a dispatch failure, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn s3_client_from_the_production_config_attempts_a_real_connection() {
        let shared_config = production_config_aimed_at_a_closed_port().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&shared_config)
            .force_path_style(true)
            .build();
        let client = aws_sdk_s3::Client::from_conf(s3_config);

        let error = client
            .get_object()
            .bucket("test-bucket")
            .key("test-key")
            .send()
            .await
            .expect_err("nothing listens on the closed local port");

        assert_real_connection_was_attempted(&error);
    }

    #[tokio::test]
    async fn ses_client_from_the_production_config_attempts_a_real_connection() {
        let shared_config = production_config_aimed_at_a_closed_port().await;
        let client = aws_sdk_sesv2::Client::new(&shared_config);

        let error = client
            .get_account()
            .send()
            .await
            .expect_err("nothing listens on the closed local port");

        assert_real_connection_was_attempted(&error);
    }
}
