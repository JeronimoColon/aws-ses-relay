//! Opt-in duplicate suppression.
//!
//! SES invokes Lambda at least once, so a lost response or a mid-flight
//! termination after a successful send can cause the same message to be
//! forwarded twice. When an idempotency bucket is configured, each message is
//! "claimed" by conditionally creating a small marker object keyed by its
//! `messageId`; a duplicate delivery finds the marker already present and is
//! skipped. The claim uses S3's atomic `If-None-Match: *` conditional write, so
//! it needs no extra service. (A DynamoDB-backed store with native TTL is a
//! reasonable future alternative; this trait is the seam for it.)
//!
//! When no bucket is configured the store is disabled and every message is
//! treated as new — preserving the plain at-least-once behavior.

use crate::handler::BoxError;

/// Object-key prefix under which idempotency markers are written.
const MARKER_PREFIX: &str = "idempotency/";

/// The result of attempting to claim a message id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// Newly claimed — proceed to process the message.
    New,
    /// Already claimed by a prior delivery — this is a duplicate; skip it.
    AlreadyProcessed,
}

/// Records which messages have been processed so duplicates can be skipped.
#[allow(async_fn_in_trait)]
pub trait IdempotencyStore {
    /// Attempt to claim `message_id`.
    async fn claim(&self, message_id: &str) -> Result<ClaimOutcome, BoxError>;

    /// Release a claim so a retry can re-process the message. Called only after
    /// a failure between a successful `New` claim and a successful send.
    async fn release(&self, message_id: &str) -> Result<(), BoxError>;
}

/// Whether a failed conditional put signals an existing marker (a duplicate).
/// True when the HTTP status is `412` or the modeled error code is
/// `PreconditionFailed`. Any other failure is a genuine error, so a real
/// duplicate is never mistaken for success — the failure direction is safe.
fn is_precondition_failed(status: Option<u16>, code: Option<&str>) -> bool {
    status == Some(412) || code == Some("PreconditionFailed")
}

/// [`IdempotencyStore`] backed by S3 conditional writes. When `bucket` is
/// `None` the store is disabled (every claim is `New`, release is a no-op).
pub struct S3IdempotencyStore {
    client: aws_sdk_s3::Client,
    bucket: Option<String>,
}

impl S3IdempotencyStore {
    pub fn new(client: aws_sdk_s3::Client, bucket: Option<String>) -> Self {
        Self { client, bucket }
    }

    fn marker_key(message_id: &str) -> String {
        format!("{MARKER_PREFIX}{message_id}")
    }
}

impl IdempotencyStore for S3IdempotencyStore {
    async fn claim(&self, message_id: &str) -> Result<ClaimOutcome, BoxError> {
        let Some(bucket) = self.bucket.as_deref() else {
            return Ok(ClaimOutcome::New);
        };

        let key = Self::marker_key(message_id);
        let result = self
            .client
            .put_object()
            .bucket(bucket)
            .key(&key)
            // Atomic create-if-absent: succeeds only when no marker exists.
            .if_none_match("*")
            .body(aws_sdk_s3::primitives::ByteStream::from_static(b""))
            .send()
            .await;

        match result {
            Ok(_) => Ok(ClaimOutcome::New),
            Err(error) => {
                use aws_sdk_s3::error::ProvideErrorMetadata;
                // A `412 Precondition Failed` means the marker already exists —
                // i.e. this message was already claimed, so it is a duplicate.
                // Check both the HTTP status and the modeled error code.
                let status = error
                    .raw_response()
                    .map(|response| response.status().as_u16());
                let code = error.code();
                if is_precondition_failed(status, code) {
                    Ok(ClaimOutcome::AlreadyProcessed)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    async fn release(&self, message_id: &str) -> Result<(), BoxError> {
        let Some(bucket) = self.bucket.as_deref() else {
            return Ok(());
        };
        let key = Self::marker_key(message_id);
        self.client
            .delete_object()
            .bucket(bucket)
            .key(&key)
            .send()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_runtime::client::http::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    const BUCKET: &str = "idempotency-bucket-example";

    #[tokio::test]
    async fn disabled_store_treats_every_message_as_new() {
        // With no bucket configured the disabled path returns early and never
        // touches S3, so an offline client is sufficient.
        let store = S3IdempotencyStore::new(offline_client(), None);
        assert_eq!(store.claim("anything").await.unwrap(), ClaimOutcome::New);
        assert_eq!(store.claim("anything").await.unwrap(), ClaimOutcome::New);
        store.release("anything").await.unwrap();
    }

    #[tokio::test]
    async fn claim_is_new_when_conditional_put_succeeds() {
        // A 200 from the conditional put means the marker did not exist, so the
        // message is newly claimed.
        let http = StaticReplayClient::new(vec![ReplayEvent::new(any_request(), ok_response())]);
        let store = S3IdempotencyStore::new(s3_client_with(http.clone()), Some(BUCKET.to_string()));

        assert_eq!(store.claim("msg-1").await.unwrap(), ClaimOutcome::New);

        // Verify it was an atomic create of the prefixed marker key.
        let sent = http.actual_requests().next().expect("a request was sent");
        assert_eq!(sent.method(), "PUT");
        assert!(
            sent.uri().contains("/idempotency/msg-1"),
            "unexpected uri: {}",
            sent.uri()
        );
        assert_eq!(sent.headers().get("if-none-match"), Some("*"));
    }

    #[tokio::test]
    async fn claim_is_already_processed_on_precondition_failed() {
        // A 412 means the marker already exists — a duplicate delivery.
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            any_request(),
            error_response(412, "PreconditionFailed"),
        )]);
        let store = S3IdempotencyStore::new(s3_client_with(http), Some(BUCKET.to_string()));

        assert_eq!(
            store.claim("dupe").await.unwrap(),
            ClaimOutcome::AlreadyProcessed
        );
    }

    #[tokio::test]
    async fn claim_propagates_other_errors() {
        // Any non-412 failure is a genuine error, never mistaken for success.
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            any_request(),
            error_response(500, "InternalError"),
        )]);
        let store = S3IdempotencyStore::new(s3_client_with(http), Some(BUCKET.to_string()));

        assert!(store.claim("boom").await.is_err());
    }

    #[tokio::test]
    async fn release_deletes_the_marker() {
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            any_request(),
            http::Response::builder()
                .status(204)
                .body(SdkBody::empty())
                .unwrap(),
        )]);
        let store = S3IdempotencyStore::new(s3_client_with(http.clone()), Some(BUCKET.to_string()));

        store.release("msg-1").await.unwrap();

        let sent = http.actual_requests().next().expect("a request was sent");
        assert_eq!(sent.method(), "DELETE");
        assert!(
            sent.uri().contains("/idempotency/msg-1"),
            "unexpected uri: {}",
            sent.uri()
        );
    }

    #[tokio::test]
    async fn release_propagates_errors() {
        let http = StaticReplayClient::new(vec![ReplayEvent::new(
            any_request(),
            error_response(500, "InternalError"),
        )]);
        let store = S3IdempotencyStore::new(s3_client_with(http), Some(BUCKET.to_string()));

        assert!(store.release("msg-1").await.is_err());
    }

    #[test]
    fn marker_key_is_prefixed() {
        assert_eq!(S3IdempotencyStore::marker_key("abc"), "idempotency/abc");
    }

    #[test]
    fn precondition_failed_is_detected_by_status_or_code() {
        // 412 by HTTP status.
        assert!(is_precondition_failed(Some(412), None));
        // By modeled error code.
        assert!(is_precondition_failed(None, Some("PreconditionFailed")));
        // Either signal alone is enough.
        assert!(is_precondition_failed(Some(412), Some("Something")));
        // Any other failure is NOT a duplicate (fails safe -> real error).
        assert!(!is_precondition_failed(Some(500), Some("InternalError")));
        assert!(!is_precondition_failed(None, None));
        assert!(!is_precondition_failed(Some(403), Some("AccessDenied")));
    }

    /// An S3 client whose HTTP layer is the given replay client, so the real
    /// claim/release code runs without touching AWS. Retries and timeouts are
    /// disabled so each call consumes exactly one replay event and needs no
    /// async timer.
    fn s3_client_with(http_client: StaticReplayClient) -> aws_sdk_s3::Client {
        use aws_sdk_s3::config::retry::RetryConfig;
        use aws_sdk_s3::config::timeout::TimeoutConfig;
        use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
        let credentials = Credentials::new("AKIDTEST", "secretTest", None, None, "test");
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(credentials)
            .retry_config(RetryConfig::disabled())
            .timeout_config(TimeoutConfig::disabled())
            .http_client(http_client)
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// An S3 client built from static config — no network, no credential or
    /// region resolution. It is never actually called by the disabled path.
    fn offline_client() -> aws_sdk_s3::Client {
        use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
        let credentials = Credentials::new("AKIDTEST", "secretTest", None, None, "test");
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(credentials)
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// The replay client returns responses by sequence, so the request it is
    /// paired with is a placeholder — the assertions inspect the *actual*
    /// request the SDK sent, via `actual_requests`.
    fn any_request() -> http::Request<SdkBody> {
        http::Request::builder()
            .uri("https://s3.amazonaws.com/")
            .body(SdkBody::empty())
            .unwrap()
    }

    fn ok_response() -> http::Response<SdkBody> {
        http::Response::builder()
            .status(200)
            .body(SdkBody::empty())
            .unwrap()
    }

    /// A well-formed S3 error response with the given HTTP status and code.
    fn error_response(status: u16, code: &str) -> http::Response<SdkBody> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>{code}</Code><Message>test</Message></Error>"
        );
        http::Response::builder()
            .status(status)
            .body(SdkBody::from(body.into_bytes()))
            .unwrap()
    }
}
