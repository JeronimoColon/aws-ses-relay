//! Minimal, lenient view of the SES → Lambda event.
//!
//! Only the fields this function actually uses are modeled, and every field is
//! optional with a default. That deliberate leniency means a schema change to a
//! field we never read — or a hand-authored replay event that omits fields we
//! do not need — cannot fail the whole invocation at the deserialize layer.
//! Unknown fields are ignored (serde's default), so additive SES changes are
//! safe too.

use serde::Deserialize;

/// Top-level SES event: a list of records (SES delivers exactly one).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct SesEvent {
    #[serde(rename = "Records", default)]
    pub records: Vec<SesRecord>,
}

/// One SES record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesRecord {
    /// Expected to be `"aws:ses"`.
    #[serde(default)]
    pub event_source: Option<String>,
    #[serde(default)]
    pub ses: SesPayload,
}

/// The `ses` payload: the mail metadata and the receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesPayload {
    #[serde(default)]
    pub mail: SesMail,
    #[serde(default)]
    pub receipt: SesReceipt,
}

/// Mail metadata; only the message id is used (as the S3 object key).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesMail {
    #[serde(default)]
    pub message_id: Option<String>,
}

/// The receipt: recipients, verdicts, and the triggering action.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesReceipt {
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub spam_verdict: SesVerdict,
    #[serde(default)]
    pub virus_verdict: SesVerdict,
    #[serde(default)]
    pub action: SesAction,
}

/// A single verdict, e.g. `{ "status": "PASS" }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesVerdict {
    #[serde(default)]
    pub status: Option<String>,
}

/// The receipt action. `bucket_name`/`object_key` are present only for an
/// S3-type action; a Lambda-type action carries neither.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesAction {
    #[serde(default)]
    pub bucket_name: Option<String>,
    #[serde(default)]
    pub object_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full Lambda-action event (the shape AWS delivers for a direct
    /// SES → Lambda invocation), with example.com identifiers and many fields
    /// the code never reads — none of which must interfere with parsing.
    #[test]
    fn parses_full_lambda_action_event() {
        let json = r#"{
          "Records": [{
            "eventVersion": "1.0",
            "eventSource": "aws:ses",
            "ses": {
              "mail": {
                "timestamp": "2026-01-01T00:00:00.000Z",
                "source": "sender@example.net",
                "messageId": "abc123messageid",
                "destination": ["info@example.com"],
                "headersTruncated": false,
                "headers": [{"name": "From", "value": "sender@example.net"}],
                "commonHeaders": {"from": ["sender@example.net"], "to": ["info@example.com"]}
              },
              "receipt": {
                "timestamp": "2026-01-01T00:00:00.000Z",
                "processingTimeMillis": 42,
                "recipients": ["info@example.com"],
                "spamVerdict": {"status": "PASS"},
                "virusVerdict": {"status": "PASS"},
                "spfVerdict": {"status": "PASS"},
                "dkimVerdict": {"status": "PASS"},
                "dmarcVerdict": {"status": "PASS"},
                "dmarcPolicy": "reject",
                "action": {
                  "type": "Lambda",
                  "invocationType": "Event",
                  "functionArn": "arn:aws:lambda:us-east-1:000000000000:function:relay"
                }
              }
            }
          }]
        }"#;
        let event: SesEvent = serde_json::from_str(json).expect("parse");
        assert_eq!(event.records.len(), 1);
        let record = &event.records[0];
        assert_eq!(record.event_source.as_deref(), Some("aws:ses"));
        assert_eq!(
            record.ses.mail.message_id.as_deref(),
            Some("abc123messageid")
        );
        assert_eq!(record.ses.receipt.recipients, vec!["info@example.com"]);
        assert_eq!(
            record.ses.receipt.spam_verdict.status.as_deref(),
            Some("PASS")
        );
        assert_eq!(
            record.ses.receipt.virus_verdict.status.as_deref(),
            Some("PASS")
        );
        // Lambda-type action carries no S3 fields.
        assert_eq!(record.ses.receipt.action.bucket_name, None);
        assert_eq!(record.ses.receipt.action.object_key, None);
    }

    /// An S3-action event carries `bucketName` and `objectKey`.
    #[test]
    fn parses_s3_action_event() {
        let json = r#"{
          "Records": [{
            "eventSource": "aws:ses",
            "ses": {
              "receipt": {
                "recipients": ["recipient@example.com"],
                "spamVerdict": {"status": "PASS"},
                "virusVerdict": {"status": "PASS"},
                "action": {
                  "type": "S3",
                  "topicArn": "arn:aws:sns:us-east-1:000000000000:topic",
                  "bucketName": "inbound-bucket-example",
                  "objectKey": "prefix/the-key"
                }
              },
              "mail": {"messageId": "s3msgid"}
            }
          }]
        }"#;
        let event: SesEvent = serde_json::from_str(json).expect("parse");
        let action = &event.records[0].ses.receipt.action;
        assert_eq!(
            action.bucket_name.as_deref(),
            Some("inbound-bucket-example")
        );
        assert_eq!(action.object_key.as_deref(), Some("prefix/the-key"));
    }

    /// A stripped-down event with only the fields we use must still parse —
    /// this is the leniency that keeps a schema change to an unused field, or a
    /// minimal replay event, from failing the whole invocation.
    #[test]
    fn parses_minimal_event_with_only_used_fields() {
        let json = r#"{
          "Records": [{
            "eventSource": "aws:ses",
            "ses": {
              "mail": {"messageId": "minimal"},
              "receipt": {
                "recipients": ["info@example.com"],
                "virusVerdict": {"status": "FAIL"}
              }
            }
          }]
        }"#;
        let event: SesEvent = serde_json::from_str(json).expect("parse");
        let record = &event.records[0];
        assert_eq!(record.ses.mail.message_id.as_deref(), Some("minimal"));
        assert_eq!(
            record.ses.receipt.virus_verdict.status.as_deref(),
            Some("FAIL")
        );
        // Absent verdict/action fields default cleanly rather than erroring.
        assert_eq!(record.ses.receipt.spam_verdict.status, None);
        assert_eq!(record.ses.receipt.action.bucket_name, None);
    }

    /// Unknown extra fields are ignored (additive SES changes are safe).
    #[test]
    fn ignores_unknown_fields() {
        let json = r#"{
          "Records": [{"eventSource": "aws:ses", "ses": {}, "brandNewField": {"x": 1}}],
          "somethingElse": 42
        }"#;
        let event: SesEvent = serde_json::from_str(json).expect("parse");
        assert_eq!(event.records.len(), 1);
    }
}
