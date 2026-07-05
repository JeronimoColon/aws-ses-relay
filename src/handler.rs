//! Orchestration: parse the SES event, apply the verdict gate, resolve
//! destinations, claim the message for idempotency, fetch the raw message from
//! S3, rewrite it, and send it.
//!
//! S3, SES, and the idempotency store are reached only through the
//! [`MessageStore`], [`EmailSender`], and [`IdempotencyStore`] traits, so the
//! whole flow is tested with in-memory fakes — no network and no AWS
//! credentials.
//!
//! A **drop** (a message we deliberately do not forward: no match, a failed
//! verdict, or a duplicate delivery) is a success: the handler returns
//! `Ok(())`. Errors are reserved for genuine failures (bad event, S3/SES
//! failure, oversize/empty/From-less message) so Lambda's retry / OnFailure
//! machinery engages only for real problems.

use thiserror::Error;
use tracing::{info, warn};

use crate::config::Config;
use crate::event::{SesEvent, SesReceipt, SesRecord};
use crate::forward::{
    evaluate_verdicts, resolve_destinations, rewrite_message, verdict_is_concerning, DropReason,
    ForwardError, GateDecision, ResolvedForward,
};
use crate::idempotency::{ClaimOutcome, IdempotencyStore};

/// Largest raw message we will fetch and forward. SES caps a send at 40 MB
/// *after* base64 encoding, which inflates the raw size by roughly one third,
/// so ~30 MB of raw bytes is the safe ceiling.
const MAX_RAW_MESSAGE_BYTES: usize = 30 * 1024 * 1024;

/// Boxed error carried out of the storage/sender/idempotency traits. Concrete
/// AWS SDK errors satisfy these bounds and convert with `?`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Exactly what we hand to SES, captured as a plain value so tests can assert
/// the outgoing request byte-for-byte.
#[derive(Clone, PartialEq, Eq)]
pub struct SendRawEmailRequest {
    pub from_email_address: String,
    pub to_addresses: Vec<String>,
    pub raw_message: Vec<u8>,
}

// Custom Debug that never prints the raw message body — only its length — so a
// stray `{:?}` on this value can never dump message content into a log.
impl std::fmt::Debug for SendRawEmailRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SendRawEmailRequest")
            .field("from_email_address", &self.from_email_address)
            .field("to_addresses", &self.to_addresses)
            .field("raw_message_len", &self.raw_message.len())
            .finish()
    }
}

/// The outcome of a size-bounded fetch.
pub enum FetchResult {
    /// The message was within the size limit.
    Message(Vec<u8>),
    /// The object exceeds the limit; its size is reported without buffering it.
    TooLarge { size: u64 },
}

// Native async fn in traits yields a non-`Send`-annotated future in the trait
// signature; every concrete implementation here (AWS SDK clients and the test
// fakes) produces a `Send` future, so the real Lambda future is `Send`.
#[allow(async_fn_in_trait)]
/// Reads the raw stored message from object storage, bounded by a size cap.
pub trait MessageStore {
    /// Fetch the raw message, refusing to buffer more than `max_bytes`.
    async fn fetch_raw_message(
        &self,
        bucket: &str,
        key: &str,
        max_bytes: usize,
    ) -> Result<FetchResult, BoxError>;
}

#[allow(async_fn_in_trait)]
/// Sends a raw (already-encoded) email. Takes the request by value so the
/// (potentially ~30 MB) body is moved into the SDK, not copied.
pub trait EmailSender {
    async fn send_raw_email(&self, request: SendRawEmailRequest) -> Result<(), BoxError>;
}

/// Everything that can go genuinely wrong while handling an event. Drops are
/// *not* errors — they return `Ok(())`.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("event contained no records; expected exactly one aws:ses record")]
    NoRecords,
    #[error("event contained {0} records; expected exactly one aws:ses record")]
    TooManyRecords(usize),
    #[error("event source `{event_source}` is not `aws:ses`")]
    SourceMismatch { event_source: String },
    #[error("event was missing a required field: {0}")]
    MissingField(&'static str),
    #[error(
        "messageId `{message_id}` is not a valid object-key token \
         (allowed: letters, digits, '.', '_', '-')"
    )]
    InvalidMessageId { message_id: String },
    #[error(
        "receipt.action provides only one of bucketName/objectKey; an S3 action \
         must carry both or neither"
    )]
    PartialS3Action,
    #[error(
        "event objectKey `{object_key}` is not a safe object key \
         (empty, leading '/', a '..' segment, or control characters)"
    )]
    InvalidObjectKey { object_key: String },
    #[error(
        "event S3 bucket `{event_bucket}` does not match configured EMAIL_BUCKET \
         `{configured_bucket}`; refusing to read from an unlisted bucket"
    )]
    BucketMismatch {
        event_bucket: String,
        configured_bucket: String,
    },
    #[error("stored message `{message_id}` is empty; refusing to send an empty message")]
    EmptyMessage { message_id: String },
    #[error("message `{message_id}` has no From header to rewrite; refusing to forward")]
    NoFromHeader { message_id: String },
    #[error(
        "stored message is {size} bytes, exceeding the {limit}-byte limit \
         (SES 40 MB post-base64 send cap; base64 inflates ~33%)"
    )]
    MessageTooLarge { size: u64, limit: usize },
    #[error(transparent)]
    Resolve(#[from] ForwardError),
    #[error("failed to claim idempotency marker for message `{message_id}`")]
    Idempotency {
        message_id: String,
        #[source]
        source: BoxError,
    },
    #[error("failed to read message from S3 (bucket `{bucket}`, key `{key}`)")]
    S3 {
        bucket: String,
        key: String,
        #[source]
        source: BoxError,
    },
    #[error("failed to send message `{message_id}` to {recipient_count} recipient(s) via SES")]
    Ses {
        message_id: String,
        recipient_count: usize,
        #[source]
        source: BoxError,
    },
}

/// Handle one SES invocation end to end.
pub async fn handle_event<S, E, I>(
    event: SesEvent,
    config: &Config,
    store: &S,
    sender: &E,
    idempotency: &I,
) -> Result<(), HandlerError>
where
    S: MessageStore,
    E: EmailSender,
    I: IdempotencyStore,
{
    // 1. Parse: exactly one record, from aws:ses. Absent/foreign source fails
    //    closed (defense in depth behind the SES-scoped invoke policy).
    let record = single_record(&event)?;
    match record.event_source.as_deref() {
        Some(source) if source.eq_ignore_ascii_case("aws:ses") => {}
        other => {
            return Err(HandlerError::SourceMismatch {
                event_source: other.unwrap_or("<absent>").to_string(),
            });
        }
    }
    let receipt = &record.ses.receipt;
    let message_id = record.ses.mail.message_id.clone().unwrap_or_default();

    // 2. Verdict gate.
    let spam_verdict = receipt.spam_verdict.status.as_deref();
    let virus_verdict = receipt.virus_verdict.status.as_deref();
    // Drift signal: a real-looking receipt with no verdicts at all suggests
    // scanning is off or the event schema changed — surface it rather than let a
    // silently-absent gate look like a clean PASS.
    if !receipt.recipients.is_empty() && spam_verdict.is_none() && virus_verdict.is_none() {
        warn!(
            message_id = %message_id,
            "receipt carries no spam or virus verdicts; scanning may be disabled \
             on the rule or the event schema may have changed"
        );
    }
    if let GateDecision::Drop(reason) = evaluate_verdicts(
        spam_verdict,
        virus_verdict,
        config.drop_spam,
        config.drop_unscanned,
    ) {
        let reason = match reason {
            DropReason::Virus => "virus verdict FAIL",
            DropReason::Spam => "spam verdict FAIL with DROP_SPAM enabled",
            DropReason::UnscannedVirus => {
                "virus verdict PROCESSING_FAILED with DROP_UNSCANNED enabled"
            }
        };
        info!(
            message_id = %message_id,
            reason,
            "dropping message per verdict gate (message remains in S3)"
        );
        return Ok(());
    }

    // 3. Resolve destinations. A no-match is a drop with zero downstream calls.
    let resolved = resolve_destinations(
        &receipt.recipients,
        &config.forward_mapping,
        config.allow_plus_sign,
    )?;
    if resolved.destinations.is_empty() {
        info!(
            message_id = %message_id,
            recipient_count = receipt.recipients.len(),
            "no destination matched any recipient; dropping (no S3/SES calls)"
        );
        return Ok(());
    }

    // We are actually going to forward now. A fail-open forward (a verdict that
    // is present but not PASS/DISABLED) is logged here — after the match — so
    // the warning only fires for messages we really send on.
    if verdict_is_concerning(virus_verdict) || verdict_is_concerning(spam_verdict) {
        warn!(
            message_id = %message_id,
            spam_verdict = ?spam_verdict,
            virus_verdict = ?virus_verdict,
            "forwarding despite a non-PASS spam/virus verdict; \
             scanning may be inconclusive or disabled on the receipt rule"
        );
    }

    // 4. We are going to forward: require a usable messageId (it keys both the
    //    S3 object in the fallback path and the idempotency marker).
    if message_id.is_empty() {
        return Err(HandlerError::MissingField("mail.messageId"));
    }
    if !is_valid_message_id(&message_id) {
        return Err(HandlerError::InvalidMessageId {
            message_id: message_id.clone(),
        });
    }

    // 5. Claim the message. A duplicate delivery is a drop; a fresh claim is
    //    released if the forward fails, so a retry can re-process it.
    match idempotency
        .claim(&message_id)
        .await
        .map_err(|source| HandlerError::Idempotency {
            message_id: message_id.clone(),
            source,
        })? {
        ClaimOutcome::AlreadyProcessed => {
            info!(
                message_id = %message_id,
                "duplicate delivery; already processed, skipping (no S3/SES calls)"
            );
            return Ok(());
        }
        ClaimOutcome::New => {}
    }

    let forward_result =
        forward_message(&message_id, receipt, config, store, sender, resolved).await;
    if forward_result.is_err() {
        if let Err(release_error) = idempotency.release(&message_id).await {
            // A stuck marker will make SES's retry look like a duplicate and drop
            // the message — a silent-loss risk — so this is error-level, not a
            // warning. A short lifecycle-rule TTL on the marker prefix lets it
            // self-heal (see the README).
            tracing::error!(
                message_id = %message_id,
                error = %release_error,
                "FAILED to release idempotency marker after a processing error; \
                 the stored marker may suppress the retry of this message until it \
                 expires (ensure a lifecycle-rule TTL is configured)"
            );
        }
    }
    forward_result
}

/// Fetch, rewrite, and send. Factored out so the idempotency claim can be
/// released on any failure here.
async fn forward_message<S, E>(
    message_id: &str,
    receipt: &SesReceipt,
    config: &Config,
    store: &S,
    sender: &E,
    resolved: ResolvedForward,
) -> Result<(), HandlerError>
where
    S: MessageStore,
    E: EmailSender,
{
    let (bucket, key) = resolve_s3_location(receipt, config, message_id)?;

    let raw = match store
        .fetch_raw_message(&bucket, &key, MAX_RAW_MESSAGE_BYTES)
        .await
        .map_err(|source| HandlerError::S3 {
            bucket: bucket.clone(),
            key: key.clone(),
            source,
        })? {
        FetchResult::TooLarge { size } => {
            return Err(HandlerError::MessageTooLarge {
                size,
                limit: MAX_RAW_MESSAGE_BYTES,
            });
        }
        FetchResult::Message(bytes) => bytes,
    };

    if raw.is_empty() {
        return Err(HandlerError::EmptyMessage {
            message_id: message_id.to_string(),
        });
    }

    let rewrite = rewrite_message(&raw, &config.from_email, config.subject_prefix.as_deref());
    if !rewrite.from_rewritten {
        return Err(HandlerError::NoFromHeader {
            message_id: message_id.to_string(),
        });
    }

    let matched: Vec<String> = resolved
        .matched_recipients
        .iter()
        .map(|recipient| recipient.incoming.clone())
        .collect();
    let request = SendRawEmailRequest {
        from_email_address: config.from_email.clone(),
        to_addresses: resolved.destinations,
        raw_message: rewrite.message,
    };
    let recipient_count = request.to_addresses.len();
    // Moved (not cloned) into the sender so the ~30 MB body is not copied.
    sender
        .send_raw_email(request)
        .await
        .map_err(|source| HandlerError::Ses {
            message_id: message_id.to_string(),
            recipient_count,
            source,
        })?;

    info!(
        message_id = %message_id,
        recipient_count,
        matched_recipients = ?matched,
        "forwarded message"
    );
    Ok(())
}

/// Return the single SES record, or an error naming the shape problem.
fn single_record(event: &SesEvent) -> Result<&SesRecord, HandlerError> {
    match event.records.as_slice() {
        [record] => Ok(record),
        [] => Err(HandlerError::NoRecords),
        many => Err(HandlerError::TooManyRecords(many.len())),
    }
}

/// SES message ids are short alphanumeric tokens. Validating the shape stops a
/// hostile `messageId` from being used as an arbitrary S3 object key.
fn is_valid_message_id(message_id: &str) -> bool {
    !message_id.is_empty()
        && message_id.len() <= 256
        && message_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

/// Decide which S3 bucket and object key hold the raw message.
///
/// AWS's event schema carries `bucketName`/`objectKey` only for an
/// **S3-action** event; the direct SES→Lambda flow delivers a **Lambda-action**
/// event whose `receipt.action` has no S3 fields. So:
///
/// - When the event provides both S3 fields, use them — but enforce the
///   allowlist by refusing any bucket other than the configured `EMAIL_BUCKET`.
/// - When it provides neither, fall back to `EMAIL_BUCKET` and SES's documented
///   storage convention: the object key equals the `messageId` (this requires
///   the S3 receipt-rule action to use no key prefix).
/// - Exactly one of the two present is a malformed action and is rejected.
fn resolve_s3_location(
    receipt: &SesReceipt,
    config: &Config,
    message_id: &str,
) -> Result<(String, String), HandlerError> {
    let action = &receipt.action;
    match (&action.bucket_name, &action.object_key) {
        (Some(event_bucket), Some(object_key)) => {
            if event_bucket != &config.email_bucket {
                return Err(HandlerError::BucketMismatch {
                    event_bucket: event_bucket.clone(),
                    configured_bucket: config.email_bucket.clone(),
                });
            }
            // Validate the event-supplied key the same way the fallback path
            // validates the messageId — an invoker must not be able to point the
            // fetch at an arbitrary object via a crafted objectKey.
            if !is_safe_object_key(object_key) {
                return Err(HandlerError::InvalidObjectKey {
                    object_key: object_key.clone(),
                });
            }
            Ok((event_bucket.clone(), object_key.clone()))
        }
        (None, None) => Ok((config.email_bucket.clone(), message_id.to_string())),
        _ => Err(HandlerError::PartialS3Action),
    }
}

/// A defensively-safe S3 object key: non-empty, bounded, no control characters,
/// no leading `/`, and no `..` path segment.
fn is_safe_object_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && !key.starts_with('/')
        && !key.chars().any(|character| character.is_control())
        && !key.split('/').any(|segment| segment == "..")
}

// ---------------------------------------------------------------------------
// Real AWS adapters
// ---------------------------------------------------------------------------

/// [`MessageStore`] backed by the real S3 client.
pub struct S3MessageStore {
    client: aws_sdk_s3::Client,
}

impl S3MessageStore {
    pub fn new(client: aws_sdk_s3::Client) -> Self {
        Self { client }
    }
}

impl MessageStore for S3MessageStore {
    async fn fetch_raw_message(
        &self,
        bucket: &str,
        key: &str,
        max_bytes: usize,
    ) -> Result<FetchResult, BoxError> {
        let output = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await?;

        // Reject before downloading the body when the size is already known —
        // this bounds memory rather than buffering an oversized object first.
        if let Some(length) = output.content_length() {
            if length > max_bytes as i64 {
                return Ok(FetchResult::TooLarge {
                    size: length as u64,
                });
            }
        }

        // Collect to bytes — never a lossy UTF-8 string — so non-UTF-8 mail is
        // preserved exactly. S3 GetObject responses always carry Content-Length,
        // so the pre-download check above is the effective memory bound; this
        // second check only covers the rare case of an absent/incorrect length,
        // in which the body has already been buffered.
        let aggregated = output.body.collect().await?;
        let bytes = aggregated.into_bytes();
        if bytes.len() > max_bytes {
            return Ok(FetchResult::TooLarge {
                size: bytes.len() as u64,
            });
        }
        Ok(FetchResult::Message(bytes.to_vec()))
    }
}

/// [`EmailSender`] backed by the real SESv2 client.
pub struct SesEmailSender {
    client: aws_sdk_sesv2::Client,
}

impl SesEmailSender {
    pub fn new(client: aws_sdk_sesv2::Client) -> Self {
        Self { client }
    }
}

impl EmailSender for SesEmailSender {
    async fn send_raw_email(&self, request: SendRawEmailRequest) -> Result<(), BoxError> {
        use aws_sdk_sesv2::primitives::Blob;
        use aws_sdk_sesv2::types::{Destination, EmailContent, RawMessage};

        // Move the body into the Blob rather than cloning it.
        let raw = RawMessage::builder()
            .data(Blob::new(request.raw_message))
            .build()?;
        let content = EmailContent::builder().raw(raw).build();
        let destination = Destination::builder()
            .set_to_addresses(Some(request.to_addresses))
            .build();

        self.client
            .send_email()
            .from_email_address(request.from_email_address)
            .destination(destination)
            .content(content)
            .send()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::event::SesRecord;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // --- fakes ----------------------------------------------------------

    struct FakeStore {
        body: Vec<u8>,
        fail: bool,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl FakeStore {
        fn returning(body: &[u8]) -> Self {
            Self {
                body: body.to_vec(),
                fail: false,
                calls: Mutex::new(Vec::new()),
            }
        }
        fn failing() -> Self {
            Self {
                body: Vec::new(),
                fail: true,
                calls: Mutex::new(Vec::new()),
            }
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        fn last_call(&self) -> (String, String) {
            self.calls.lock().unwrap().last().cloned().unwrap()
        }
    }

    impl MessageStore for FakeStore {
        async fn fetch_raw_message(
            &self,
            bucket: &str,
            key: &str,
            max_bytes: usize,
        ) -> Result<FetchResult, BoxError> {
            self.calls
                .lock()
                .unwrap()
                .push((bucket.to_string(), key.to_string()));
            if self.fail {
                return Err("simulated S3 failure".into());
            }
            if self.body.len() > max_bytes {
                return Ok(FetchResult::TooLarge {
                    size: self.body.len() as u64,
                });
            }
            Ok(FetchResult::Message(self.body.clone()))
        }
    }

    struct FakeSender {
        fail: bool,
        requests: Mutex<Vec<SendRawEmailRequest>>,
    }

    impl FakeSender {
        fn new() -> Self {
            Self {
                fail: false,
                requests: Mutex::new(Vec::new()),
            }
        }
        fn failing() -> Self {
            Self {
                fail: true,
                requests: Mutex::new(Vec::new()),
            }
        }
        fn call_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
        fn last_request(&self) -> SendRawEmailRequest {
            self.requests.lock().unwrap().last().cloned().unwrap()
        }
    }

    impl EmailSender for FakeSender {
        async fn send_raw_email(&self, request: SendRawEmailRequest) -> Result<(), BoxError> {
            self.requests.lock().unwrap().push(request);
            if self.fail {
                return Err("simulated SES failure".into());
            }
            Ok(())
        }
    }

    struct FakeIdempotency {
        outcome: ClaimOutcome,
        fail_claim: bool,
        releases: Mutex<Vec<String>>,
    }

    impl FakeIdempotency {
        fn new() -> Self {
            Self {
                outcome: ClaimOutcome::New,
                fail_claim: false,
                releases: Mutex::new(Vec::new()),
            }
        }
        fn duplicate() -> Self {
            Self {
                outcome: ClaimOutcome::AlreadyProcessed,
                fail_claim: false,
                releases: Mutex::new(Vec::new()),
            }
        }
        fn failing_claim() -> Self {
            Self {
                outcome: ClaimOutcome::New,
                fail_claim: true,
                releases: Mutex::new(Vec::new()),
            }
        }
        fn release_count(&self) -> usize {
            self.releases.lock().unwrap().len()
        }
    }

    impl IdempotencyStore for FakeIdempotency {
        async fn claim(&self, _message_id: &str) -> Result<ClaimOutcome, BoxError> {
            if self.fail_claim {
                return Err("simulated idempotency failure".into());
            }
            Ok(self.outcome)
        }
        async fn release(&self, message_id: &str) -> Result<(), BoxError> {
            self.releases.lock().unwrap().push(message_id.to_string());
            Ok(())
        }
    }

    // --- fixtures -------------------------------------------------------

    fn test_config() -> Config {
        let mut forward_mapping = HashMap::new();
        forward_mapping.insert(
            "info@example.com".to_string(),
            vec!["dest@example.net".to_string()],
        );
        Config {
            from_email: "relay@example.com".to_string(),
            email_bucket: "inbound-bucket-example".to_string(),
            forward_mapping,
            subject_prefix: None,
            allow_plus_sign: true,
            drop_spam: false,
            drop_unscanned: false,
            idempotency_bucket: None,
        }
    }

    fn lambda_action() -> String {
        r#"{ "type": "Lambda", "invocationType": "Event",
             "functionArn": "arn:aws:lambda:us-east-1:000000000000:function:relay" }"#
            .to_string()
    }

    fn s3_action(bucket: &str, key: &str) -> String {
        format!(r#"{{ "type": "S3", "bucketName": "{bucket}", "objectKey": "{key}" }}"#)
    }

    /// Build a documented-shape SES event (with many fields the code ignores).
    fn event(
        recipients: &[&str],
        spam: &str,
        virus: &str,
        message_id: &str,
        action_json: &str,
    ) -> SesEvent {
        event_with_source("aws:ses", recipients, spam, virus, message_id, action_json)
    }

    fn event_with_source(
        source: &str,
        recipients: &[&str],
        spam: &str,
        virus: &str,
        message_id: &str,
        action_json: &str,
    ) -> SesEvent {
        let recipients_json = serde_json::to_string(recipients).unwrap();
        let json = format!(
            r#"{{
              "Records": [{{
                "eventSource": "{source}",
                "eventVersion": "1.0",
                "ses": {{
                  "mail": {{
                    "timestamp": "2026-01-01T00:00:00.000Z",
                    "source": "sender@example.net",
                    "messageId": "{message_id}",
                    "destination": {recipients_json},
                    "headersTruncated": false,
                    "headers": [],
                    "commonHeaders": {{
                      "from": ["Original Sender <sender@example.net>"],
                      "to": {recipients_json}
                    }}
                  }},
                  "receipt": {{
                    "timestamp": "2026-01-01T00:00:00.000Z",
                    "processingTimeMillis": 5,
                    "recipients": {recipients_json},
                    "spamVerdict": {{ "status": "{spam}" }},
                    "virusVerdict": {{ "status": "{virus}" }},
                    "spfVerdict": {{ "status": "PASS" }},
                    "dkimVerdict": {{ "status": "PASS" }},
                    "dmarcVerdict": {{ "status": "PASS" }},
                    "action": {action_json}
                  }}
                }}
              }}]
            }}"#
        );
        serde_json::from_str(&json).expect("valid SES event JSON")
    }

    // --- tests ----------------------------------------------------------

    #[tokio::test]
    async fn happy_path_fetches_then_sends_with_exact_input() {
        let config = test_config();
        let input =
            b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\nSubject: Hi\r\n\r\nBody.\r\n";
        let store = FakeStore::returning(input);
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-123",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("happy path succeeds");

        assert_eq!(store.call_count(), 1);
        assert_eq!(
            store.last_call(),
            ("inbound-bucket-example".to_string(), "msg-123".to_string())
        );

        assert_eq!(sender.call_count(), 1);
        let request = sender.last_request();
        assert_eq!(request.from_email_address, "relay@example.com");
        assert_eq!(request.to_addresses, vec!["dest@example.net"]);
        let expected_raw = b"From: Bob <relay@example.com>\r\nTo: info@example.com\r\nSubject: Hi\r\nReply-To: Bob <bob@example.net>\r\n\r\nBody.\r\n";
        assert_eq!(request.raw_message, expected_raw.to_vec());
    }

    #[tokio::test]
    async fn no_match_makes_zero_s3_and_ses_calls() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["nobody@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("no match is a drop, not an error");

        assert_eq!(store.call_count(), 0, "no S3 fetch on no-match");
        assert_eq!(sender.call_count(), 0, "no SES send on no-match");
    }

    #[tokio::test]
    async fn virus_fail_drops_with_zero_calls() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "FAIL",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("virus FAIL is a drop, not an error");

        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn spam_fail_with_drop_spam_drops_with_zero_calls() {
        let mut config = test_config();
        config.drop_spam = true;
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "FAIL",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("spam FAIL with DROP_SPAM is a drop");

        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn drop_unscanned_drops_processing_failed_virus_with_zero_calls() {
        let mut config = test_config();
        config.drop_unscanned = true;
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PROCESSING_FAILED",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("unscanned drop is not an error");

        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn processing_failed_virus_still_forwards_by_default() {
        let config = test_config();
        let store = FakeStore::returning(
            b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\n\r\nbody",
        );
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PROCESSING_FAILED",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("fail-open by default");

        assert_eq!(
            sender.call_count(),
            1,
            "forwarded despite the unscannable verdict"
        );
    }

    #[tokio::test]
    async fn foreign_event_source_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event_with_source(
            "aws:sns",
            &["info@example.com"],
            "PASS",
            "PASS",
            "m1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("non-ses source must error");
        assert!(matches!(error, HandlerError::SourceMismatch { .. }));
        assert_eq!(store.call_count(), 0);
    }

    #[tokio::test]
    async fn bucket_mismatch_errors_with_no_calls() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let action = s3_action("someone-elses-bucket", "some-key");
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", &action);

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("bucket mismatch must error");
        assert!(matches!(error, HandlerError::BucketMismatch { .. }));
        assert_eq!(
            store.call_count(),
            0,
            "must not read from an unlisted bucket"
        );
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn s3_action_event_uses_event_bucket_and_key() {
        let config = test_config();
        let store = FakeStore::returning(
            b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\n\r\nbody",
        );
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let action = s3_action("inbound-bucket-example", "prefix/custom-key");
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", &action);

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("matching S3-action event succeeds");

        assert_eq!(
            store.last_call(),
            (
                "inbound-bucket-example".to_string(),
                "prefix/custom-key".to_string()
            ),
            "uses the event's bucket and object key when provided"
        );
    }

    #[tokio::test]
    async fn hostile_s3_action_object_key_is_rejected() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        // Correct bucket, but a traversal-shaped object key.
        let action = s3_action("inbound-bucket-example", "../secrets/private");
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", &action);

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("unsafe object key must be rejected");
        assert!(matches!(error, HandlerError::InvalidObjectKey { .. }));
        assert_eq!(store.call_count(), 0, "never fetch with an unsafe key");
    }

    #[tokio::test]
    async fn absent_event_source_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        // A single record with no eventSource field must fail closed.
        let json = r#"{
          "Records": [{
            "ses": {
              "mail": { "messageId": "m1" },
              "receipt": {
                "recipients": ["info@example.com"],
                "spamVerdict": { "status": "PASS" },
                "virusVerdict": { "status": "PASS" },
                "action": { "type": "Lambda" }
              }
            }
          }]
        }"#;
        let event: SesEvent = serde_json::from_str(json).unwrap();

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("absent eventSource must fail closed");
        assert!(matches!(error, HandlerError::SourceMismatch { .. }));
        assert_eq!(store.call_count(), 0);
    }

    #[tokio::test]
    async fn partial_s3_action_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        // Only bucketName, no objectKey.
        let action = r#"{ "type": "S3", "bucketName": "inbound-bucket-example" }"#;
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", action);

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("half-populated S3 action must error");
        assert!(matches!(error, HandlerError::PartialS3Action));
        assert_eq!(store.call_count(), 0);
    }

    #[tokio::test]
    async fn oversize_object_errors_before_send() {
        let config = test_config();
        let oversize = vec![b'x'; MAX_RAW_MESSAGE_BYTES + 1];
        let store = FakeStore::returning(&oversize);
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("oversize must error");
        assert!(matches!(error, HandlerError::MessageTooLarge { .. }));
        assert_eq!(sender.call_count(), 0, "no send for an oversize message");
    }

    #[tokio::test]
    async fn empty_object_errors_before_send() {
        let config = test_config();
        let store = FakeStore::returning(b"");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("empty object must error");
        assert!(matches!(error, HandlerError::EmptyMessage { .. }));
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn message_with_no_from_header_errors_before_send() {
        let config = test_config();
        // Leading blank line -> the whole message is body, no header From.
        let store = FakeStore::returning(b"\r\nFrom: attacker@evil.example\r\n\r\nbody");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("no From to rewrite must error");
        assert!(matches!(error, HandlerError::NoFromHeader { .. }));
        assert_eq!(sender.call_count(), 0, "never forward an un-rewritten From");
    }

    #[tokio::test]
    async fn empty_message_id_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(&["info@example.com"], "PASS", "PASS", "", &lambda_action());

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("empty messageId must error");
        assert!(matches!(error, HandlerError::MissingField(_)));
        assert_eq!(store.call_count(), 0);
    }

    #[tokio::test]
    async fn hostile_message_id_is_rejected() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        // A slash would otherwise become an arbitrary object key within the bucket.
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "secrets/private-object",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("slash in messageId must be rejected");
        assert!(matches!(error, HandlerError::InvalidMessageId { .. }));
        assert_eq!(store.call_count(), 0, "never fetch with a hostile key");
    }

    #[tokio::test]
    async fn no_records_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = SesEvent { records: vec![] };

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("zero records must error");
        assert!(matches!(error, HandlerError::NoRecords));
    }

    #[tokio::test]
    async fn too_many_records_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = SesEvent {
            records: vec![SesRecord::default(), SesRecord::default()],
        };

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("two records must error");
        assert!(matches!(error, HandlerError::TooManyRecords(2)));
    }

    #[tokio::test]
    async fn duplicate_delivery_is_dropped_with_zero_calls() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::duplicate();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("a duplicate is a drop, not an error");

        assert_eq!(store.call_count(), 0, "no fetch for a duplicate");
        assert_eq!(sender.call_count(), 0, "no send for a duplicate");
    }

    #[tokio::test]
    async fn claim_is_released_when_send_fails() {
        let config = test_config();
        let store = FakeStore::returning(
            b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\n\r\nbody",
        );
        let sender = FakeSender::failing();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("send failure propagates");
        assert!(matches!(error, HandlerError::Ses { .. }));
        assert_eq!(
            idempotency.release_count(),
            1,
            "the claim must be released so a retry can re-process"
        );
    }

    #[tokio::test]
    async fn idempotency_claim_failure_errors_before_fetch() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::failing_claim();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("claim failure must error");
        assert!(matches!(error, HandlerError::Idempotency { .. }));
        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn s3_failure_propagates_as_error() {
        let config = test_config();
        let store = FakeStore::failing();
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("S3 failure must propagate");
        assert!(matches!(error, HandlerError::S3 { .. }));
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn ses_failure_propagates_as_error() {
        let config = test_config();
        let store = FakeStore::returning(
            b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\n\r\nbody",
        );
        let sender = FakeSender::failing();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect_err("SES failure must propagate");
        assert!(matches!(error, HandlerError::Ses { .. }));
    }

    #[tokio::test]
    async fn end_to_end_multipart_produces_exact_outgoing_message() {
        let mut config = test_config();
        config.subject_prefix = Some("[EXT] ".to_string());

        let input = concat!(
            "Return-Path: <bounce@example.net>\r\n",
            "Received: from mx.example.net (mx.example.net [203.0.113.7])\r\n",
            "\tby inbound-smtp.us-east-1.amazonaws.com with SMTP id abc123\r\n",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=sel;\r\n",
            "\tbh=abcdef; b=signaturedata\r\n",
            "From: Alice Example <alice@example.net>\r\n",
            "To: info@example.com\r\n",
            "Subject: Quarterly report\r\n",
            "Message-ID: <orig-123@example.net>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b1\"\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: text/plain; charset=UTF-8\r\n",
            "\r\n",
            "Hello, this is the plain text part.\r\n",
            "--b1\r\n",
            "Content-Type: text/html; charset=UTF-8\r\n",
            "\r\n",
            "<p>Hello, this is the HTML part.</p>\r\n",
            "--b1--\r\n",
        );

        let expected = concat!(
            "Received: from mx.example.net (mx.example.net [203.0.113.7])\r\n",
            "\tby inbound-smtp.us-east-1.amazonaws.com with SMTP id abc123\r\n",
            "From: Alice Example <relay@example.com>\r\n",
            "To: info@example.com\r\n",
            "Subject: [EXT] Quarterly report\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative; boundary=\"b1\"\r\n",
            "Reply-To: Alice Example <alice@example.net>\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: text/plain; charset=UTF-8\r\n",
            "\r\n",
            "Hello, this is the plain text part.\r\n",
            "--b1\r\n",
            "Content-Type: text/html; charset=UTF-8\r\n",
            "\r\n",
            "<p>Hello, this is the HTML part.</p>\r\n",
            "--b1--\r\n",
        );

        let store = FakeStore::returning(input.as_bytes());
        let sender = FakeSender::new();
        let idempotency = FakeIdempotency::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-e2e",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender, &idempotency)
            .await
            .expect("end-to-end succeeds");

        let request = sender.last_request();
        assert_eq!(request.from_email_address, "relay@example.com");
        assert_eq!(request.to_addresses, vec!["dest@example.net"]);
        assert_eq!(
            String::from_utf8(request.raw_message).unwrap(),
            expected,
            "outgoing raw message must match byte-for-byte"
        );
    }
}
