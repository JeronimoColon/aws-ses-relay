//! Orchestration: parse the SES event, apply the verdict gate, resolve
//! destinations, fetch the raw message from S3, rewrite it, and send it.
//!
//! S3 and SES are reached only through the [`MessageStore`] and [`EmailSender`]
//! traits, so the whole flow is tested with in-memory fakes — no network and no
//! AWS credentials.
//!
//! A **drop** (a message we deliberately do not forward) is a success: the
//! handler returns `Ok(())`. Errors are reserved for genuine failures (bad
//! event, S3/SES failure, oversize message) so Lambda's retry / OnFailure
//! machinery engages only for real problems.

use aws_lambda_events::event::ses::{SimpleEmailEvent, SimpleEmailReceipt, SimpleEmailRecord};
use thiserror::Error;
use tracing::info;

use crate::config::Config;
use crate::forward::{evaluate_verdicts, resolve_destinations, rewrite_message, ForwardError};
use crate::forward::{DropReason, GateDecision};

/// Largest raw message we will fetch and forward. SES caps a send at 40 MB
/// *after* base64 encoding, which inflates the raw size by roughly one third,
/// so ~30 MB of raw bytes is the safe ceiling.
const MAX_RAW_MESSAGE_BYTES: usize = 30 * 1024 * 1024;

/// Boxed error carried out of the storage/sender traits. Concrete AWS SDK
/// errors satisfy these bounds and convert with `?`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Exactly what we hand to SES, captured as a plain value so tests can assert
/// the outgoing request byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRawEmailRequest {
    pub from_email_address: String,
    pub to_addresses: Vec<String>,
    pub raw_message: Vec<u8>,
}

// Native async fn in traits yields a non-`Send`-annotated future in the trait
// signature; every concrete implementation here (AWS SDK clients and the test
// fakes) produces a `Send` future, so the real Lambda future is `Send`.
#[allow(async_fn_in_trait)]
/// Reads the raw stored message from object storage.
pub trait MessageStore {
    async fn get_raw_message(&self, bucket: &str, key: &str) -> Result<Vec<u8>, BoxError>;
}

#[allow(async_fn_in_trait)]
/// Sends a raw (already-encoded) email.
pub trait EmailSender {
    async fn send_raw_email(&self, request: &SendRawEmailRequest) -> Result<(), BoxError>;
}

/// Everything that can go genuinely wrong while handling an event. Drops are
/// *not* errors — they return `Ok(())`.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("event contained no records; expected exactly one aws:ses record")]
    NoRecords,
    #[error("event contained {0} records; expected exactly one aws:ses record")]
    TooManyRecords(usize),
    #[error("event was missing a required field: {0}")]
    MissingField(&'static str),
    #[error(
        "event S3 bucket `{event_bucket}` does not match configured EMAIL_BUCKET \
         `{configured_bucket}`; refusing to read from an unlisted bucket"
    )]
    BucketMismatch {
        event_bucket: String,
        configured_bucket: String,
    },
    #[error(
        "stored message is {size} bytes, exceeding the {limit}-byte limit \
         (SES 40 MB post-base64 send cap; base64 inflates ~33%)"
    )]
    MessageTooLarge { size: usize, limit: usize },
    #[error(transparent)]
    Resolve(#[from] ForwardError),
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
pub async fn handle_event<S, E>(
    event: SimpleEmailEvent,
    config: &Config,
    store: &S,
    sender: &E,
) -> Result<(), HandlerError>
where
    S: MessageStore,
    E: EmailSender,
{
    // 1. Parse: exactly one SES record.
    let record = single_record(&event)?;
    let mail = &record.ses.mail;
    let receipt = &record.ses.receipt;
    let message_id = mail.message_id.clone().unwrap_or_default();

    // 2. Verdict gate.
    let spam_verdict = receipt.spam_verdict.status.as_deref();
    let virus_verdict = receipt.virus_verdict.status.as_deref();
    if let GateDecision::Drop(reason) =
        evaluate_verdicts(spam_verdict, virus_verdict, config.drop_spam)
    {
        let reason = match reason {
            DropReason::Virus => "virus verdict FAIL",
            DropReason::Spam => "spam verdict FAIL with DROP_SPAM enabled",
        };
        info!(
            message_id = %message_id,
            reason,
            "dropping message per verdict gate (message remains in S3)"
        );
        return Ok(());
    }

    // 3. Resolve destinations. A no-match is a drop with zero S3/SES calls.
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
    let matched: Vec<&str> = resolved
        .matched_recipients
        .iter()
        .map(|matched| matched.incoming.as_str())
        .collect();

    // 4. Locate and fetch the raw message from S3.
    let (bucket, key) = resolve_s3_location(receipt, config, &message_id)?;
    let raw = store
        .get_raw_message(&bucket, &key)
        .await
        .map_err(|source| HandlerError::S3 {
            bucket: bucket.clone(),
            key: key.clone(),
            source,
        })?;
    if raw.len() > MAX_RAW_MESSAGE_BYTES {
        return Err(HandlerError::MessageTooLarge {
            size: raw.len(),
            limit: MAX_RAW_MESSAGE_BYTES,
        });
    }

    // 5. Rewrite headers on bytes.
    let rewritten = rewrite_message(&raw, &config.from_email, config.subject_prefix.as_deref());

    // 6. Send.
    let request = SendRawEmailRequest {
        from_email_address: config.from_email.clone(),
        to_addresses: resolved.destinations,
        raw_message: rewritten,
    };
    let recipient_count = request.to_addresses.len();
    sender
        .send_raw_email(&request)
        .await
        .map_err(|source| HandlerError::Ses {
            message_id: message_id.clone(),
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
fn single_record(event: &SimpleEmailEvent) -> Result<&SimpleEmailRecord, HandlerError> {
    match event.records.as_slice() {
        [record] => Ok(record),
        [] => Err(HandlerError::NoRecords),
        many => Err(HandlerError::TooManyRecords(many.len())),
    }
}

/// Decide which S3 bucket and object key hold the raw message.
///
/// Plan §7 assumed the event's `receipt.action` always carries `bucketName` and
/// `objectKey`. AWS's actual event schema only does so for an **S3-action**
/// event; the direct SES→Lambda flow delivers a **Lambda-action** event whose
/// `receipt.action` has no S3 fields. So:
///
/// - When the event provides S3 fields, use them — but enforce the allowlist by
///   refusing any bucket other than the configured `EMAIL_BUCKET`.
/// - Otherwise fall back to `EMAIL_BUCKET` and SES's documented storage
///   convention: the object key equals the `messageId` (this requires the S3
///   receipt-rule action to use no key prefix).
fn resolve_s3_location(
    receipt: &SimpleEmailReceipt,
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
            Ok((event_bucket.clone(), object_key.clone()))
        }
        _ => {
            if message_id.is_empty() {
                return Err(HandlerError::MissingField(
                    "mail.messageId (needed as the S3 object key when the event carries no S3 action fields)",
                ));
            }
            Ok((config.email_bucket.clone(), message_id.to_string()))
        }
    }
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
    async fn get_raw_message(&self, bucket: &str, key: &str) -> Result<Vec<u8>, BoxError> {
        let output = self
            .client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await?;
        // Collect to bytes — never a lossy UTF-8 string — so non-UTF-8 mail is
        // preserved exactly.
        let aggregated = output.body.collect().await?;
        Ok(aggregated.into_bytes().to_vec())
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
    async fn send_raw_email(&self, request: &SendRawEmailRequest) -> Result<(), BoxError> {
        use aws_sdk_sesv2::primitives::Blob;
        use aws_sdk_sesv2::types::{Destination, EmailContent, RawMessage};

        let raw = RawMessage::builder()
            .data(Blob::new(request.raw_message.clone()))
            .build()?;
        let content = EmailContent::builder().raw(raw).build();
        let destination = Destination::builder()
            .set_to_addresses(Some(request.to_addresses.clone()))
            .build();

        self.client
            .send_email()
            .from_email_address(&request.from_email_address)
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
        async fn get_raw_message(&self, bucket: &str, key: &str) -> Result<Vec<u8>, BoxError> {
            self.calls
                .lock()
                .unwrap()
                .push((bucket.to_string(), key.to_string()));
            if self.fail {
                return Err("simulated S3 failure".into());
            }
            Ok(self.body.clone())
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
        async fn send_raw_email(&self, request: &SendRawEmailRequest) -> Result<(), BoxError> {
            self.requests.lock().unwrap().push(request.clone());
            if self.fail {
                return Err("simulated SES failure".into());
            }
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

    /// Build a `SimpleEmailEvent` by deserializing a documented-shape SES event.
    fn event(
        recipients: &[&str],
        spam: &str,
        virus: &str,
        message_id: &str,
        action_json: &str,
    ) -> SimpleEmailEvent {
        let recipients_json = serde_json::to_string(recipients).unwrap();
        let json = format!(
            r#"{{
              "Records": [{{
                "eventSource": "aws:ses",
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
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-123",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender)
            .await
            .expect("happy path succeeds");

        // Fetched from the configured bucket, keyed by messageId.
        assert_eq!(store.call_count(), 1);
        assert_eq!(
            store.last_call(),
            ("inbound-bucket-example".to_string(), "msg-123".to_string())
        );

        // Sent exactly once with the exact expected request.
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
        let event = event(
            &["nobody@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender)
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
        let event = event(
            &["info@example.com"],
            "PASS",
            "FAIL",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender)
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
        let event = event(
            &["info@example.com"],
            "FAIL",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender)
            .await
            .expect("spam FAIL with DROP_SPAM is a drop");

        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn bucket_mismatch_errors_with_no_calls() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        let action = s3_action("someone-elses-bucket", "some-key");
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", &action);

        let error = handle_event(event, &config, &store, &sender)
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
        let action = s3_action("inbound-bucket-example", "prefix/custom-key");
        let event = event(&["info@example.com"], "PASS", "PASS", "msg-1", &action);

        handle_event(event, &config, &store, &sender)
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
    async fn oversize_object_errors_before_send() {
        let config = test_config();
        let oversize = vec![b'x'; MAX_RAW_MESSAGE_BYTES + 1];
        let store = FakeStore::returning(&oversize);
        let sender = FakeSender::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender)
            .await
            .expect_err("oversize must error");
        assert!(matches!(error, HandlerError::MessageTooLarge { .. }));
        assert_eq!(store.call_count(), 1, "fetch happens, then the size check");
        assert_eq!(sender.call_count(), 0, "no send for an oversize message");
    }

    #[tokio::test]
    async fn missing_message_id_without_s3_fields_errors() {
        let config = test_config();
        let store = FakeStore::returning(b"unused");
        let sender = FakeSender::new();
        // Empty messageId and a Lambda action with no S3 fields.
        let event = event(&["info@example.com"], "PASS", "PASS", "", &lambda_action());

        let error = handle_event(event, &config, &store, &sender)
            .await
            .expect_err("no key derivable");
        assert!(matches!(error, HandlerError::MissingField(_)));
        assert_eq!(store.call_count(), 0);
        assert_eq!(sender.call_count(), 0);
    }

    #[tokio::test]
    async fn s3_failure_propagates_as_error() {
        let config = test_config();
        let store = FakeStore::failing();
        let sender = FakeSender::new();
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender)
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
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-1",
            &lambda_action(),
        );

        let error = handle_event(event, &config, &store, &sender)
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

        // Return-Path, DKIM-Signature (with its folded continuation), and
        // Message-ID are gone; From is rewritten; Subject is prefixed; Reply-To
        // equal to the original From is appended; the multipart body is
        // preserved exactly.
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
        let event = event(
            &["info@example.com"],
            "PASS",
            "PASS",
            "msg-e2e",
            &lambda_action(),
        );

        handle_event(event, &config, &store, &sender)
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
