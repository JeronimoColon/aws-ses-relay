//! Lambda bootstrap: initialize logging, load configuration and build the AWS
//! clients once at cold start, then serve invocations.

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
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
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
