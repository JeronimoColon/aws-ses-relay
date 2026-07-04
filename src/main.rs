//! Lambda bootstrap: initialize logging, load configuration and build the AWS
//! clients once at cold start, then serve invocations.

mod config;
mod forward;
mod handler;

use aws_lambda_events::event::ses::SimpleEmailEvent;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};

use crate::config::Config;
use crate::handler::{handle_event, S3MessageStore, SesEmailSender};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    init_tracing();

    // Load and validate configuration once. A configuration problem should fail
    // the cold start loudly rather than surface per-invocation.
    let config = Config::from_process_env().map_err(|error| {
        tracing::error!(%error, "invalid configuration; refusing to start");
        Error::from(error.to_string())
    })?;

    // Build the AWS clients once; they are reused across warm invocations.
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let store = S3MessageStore::new(aws_sdk_s3::Client::new(&aws_config));
    let sender = SesEmailSender::new(aws_sdk_sesv2::Client::new(&aws_config));

    run(service_fn(|event: LambdaEvent<SimpleEmailEvent>| async {
        handle_event(event.payload, &config, &store, &sender)
            .await
            .map_err(Error::from)
    }))
    .await
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
