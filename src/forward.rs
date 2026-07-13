//! Pure forwarding logic: no I/O, no AWS calls, fully unit-testable.
//!
//! Three concerns live here:
//! 1. [`resolve_destinations`] - map inbound recipients to forward addresses.
//! 2. [`evaluate_verdicts`] - the spam/virus gate.
//! 3. [`rewrite_message`] - rewrite the raw message headers, on **bytes**, so
//!    non-UTF-8 mail is never corrupted.
//!
//! All parsing is a linear byte scan. No backtracking regex is used anywhere,
//! so a pathological message cannot trigger catastrophic-backtracking denial of
//! service in header parsing.

use std::collections::HashMap;
use std::collections::HashSet;

use thiserror::Error;

/// SES caps `Destination.ToAddresses` at 50 recipients per send.
pub const MAX_TO_ADDRESSES: usize = 50;

/// Errors from the pure forwarding logic.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ForwardError {
    #[error(
        "resolved {count} destinations, exceeding the SES cap of {MAX_TO_ADDRESSES} \
         recipients (ToAddresses) per send"
    )]
    TooManyDestinations { count: usize },
}

// ---------------------------------------------------------------------------
// Recipient resolution
// ---------------------------------------------------------------------------

/// The result of resolving inbound recipients against the forward mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedForward {
    /// Deduplicated destination addresses, in deterministic first-seen order.
    pub destinations: Vec<String>,
    /// The inbound recipients that matched, with the mapping key each hit.
    /// Used for logging only.
    pub matched_recipients: Vec<MatchedRecipient>,
}

/// One inbound recipient that matched a mapping key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRecipient {
    /// The normalized (lowercased) inbound address that matched.
    pub incoming: String,
    /// The mapping key it matched on (`user@domain`, `@domain`, `mailbox`, or `@`).
    pub matched_key: String,
}

/// Resolve the inbound recipients to forward destinations.
///
/// For each recipient the mapping is consulted in this precedence, first match
/// wins: exact address -> `@domain` -> bare mailbox -> `@` catch-all. When
/// `allow_plus_sign` is true, a `+tag` suffix on the mailbox is stripped before
/// matching. Destinations are aggregated across all recipients and
/// deduplicated deterministically.
///
/// A no-match yields an empty destination list (the caller treats that as a
/// drop). More than [`MAX_TO_ADDRESSES`] resolved destinations is an error.
pub fn resolve_destinations(
    recipients: &[String],
    forward_mapping: &HashMap<String, Vec<String>>,
    allow_plus_sign: bool,
) -> Result<ResolvedForward, ForwardError> {
    let mut destinations: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut matched_recipients: Vec<MatchedRecipient> = Vec::new();

    for recipient in recipients {
        let incoming = recipient.trim().to_ascii_lowercase();
        if incoming.is_empty() {
            continue;
        }
        let Some(matched_key) = first_matching_key(&incoming, forward_mapping, allow_plus_sign)
        else {
            continue;
        };

        for destination in &forward_mapping[&matched_key] {
            if seen.insert(destination.clone()) {
                destinations.push(destination.clone());
            }
        }
        matched_recipients.push(MatchedRecipient {
            incoming,
            matched_key,
        });
    }

    if destinations.len() > MAX_TO_ADDRESSES {
        return Err(ForwardError::TooManyDestinations {
            count: destinations.len(),
        });
    }

    Ok(ResolvedForward {
        destinations,
        matched_recipients,
    })
}

/// Return the first mapping key that matches `incoming` by precedence, if any.
fn first_matching_key(
    incoming: &str,
    forward_mapping: &HashMap<String, Vec<String>>,
    allow_plus_sign: bool,
) -> Option<String> {
    // Split on the last '@' so a (rare) quoted local-part with an embedded '@'
    // still identifies the domain correctly.
    let (mailbox_raw, domain) = match incoming.rsplit_once('@') {
        Some((mailbox, domain)) => (mailbox, domain),
        None => (incoming, ""),
    };
    let mailbox = effective_mailbox(mailbox_raw, allow_plus_sign);

    let mut candidates: Vec<String> = Vec::new();
    if !domain.is_empty() {
        candidates.push(format!("{mailbox}@{domain}"));
        candidates.push(format!("@{domain}"));
    }
    if !mailbox.is_empty() {
        candidates.push(mailbox.to_string());
    }
    candidates.push("@".to_string());

    candidates
        .into_iter()
        .find(|candidate| forward_mapping.contains_key(candidate))
}

/// Strip a `+tag` suffix from the mailbox when plus-sign addressing is allowed.
fn effective_mailbox(mailbox: &str, allow_plus_sign: bool) -> &str {
    if allow_plus_sign {
        match mailbox.split_once('+') {
            Some((base, _tag)) => base,
            None => mailbox,
        }
    } else {
        mailbox
    }
}

// ---------------------------------------------------------------------------
// Verdict gate
// ---------------------------------------------------------------------------

/// The gate's decision for a message given its spam/virus verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    Forward,
    Drop(DropReason),
}

/// Why a message was dropped by the verdict gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    Virus,
    Spam,
    /// The virus scan could not render a verdict (`PROCESSING_FAILED`) and
    /// `drop_unscanned` is set, so we fail closed rather than forward it.
    UnscannedVirus,
}

/// Apply the spam/virus gate.
///
/// A `FAIL` virus verdict always drops. A `PROCESSING_FAILED` virus verdict
/// drops only when `drop_unscanned` is set (fail closed on an unscannable
/// message). A `FAIL` spam verdict drops only when `drop_spam` is set. Every
/// other status - `PASS`, `GRAY`, `DISABLED`, or absent - forwards.
pub fn evaluate_verdicts(
    spam_verdict: Option<&str>,
    virus_verdict: Option<&str>,
    drop_spam: bool,
    drop_unscanned: bool,
) -> GateDecision {
    if verdict_matches(virus_verdict, "FAIL") {
        return GateDecision::Drop(DropReason::Virus);
    }
    if drop_unscanned && verdict_matches(virus_verdict, "PROCESSING_FAILED") {
        return GateDecision::Drop(DropReason::UnscannedVirus);
    }
    if drop_spam && verdict_matches(spam_verdict, "FAIL") {
        return GateDecision::Drop(DropReason::Spam);
    }
    GateDecision::Forward
}

/// Whether a forwarded message carried a verdict worth surfacing: present, and
/// neither `PASS` (clean) nor `DISABLED` (scanning deliberately off). This makes
/// a fail-open forward (spam `FAIL`, virus `PROCESSING_FAILED`, `GRAY`) visible
/// and alarmable in the logs rather than silent.
pub fn verdict_is_concerning(verdict: Option<&str>) -> bool {
    match verdict {
        Some(status) => {
            !status.eq_ignore_ascii_case("PASS") && !status.eq_ignore_ascii_case("DISABLED")
        }
        None => false,
    }
}

/// True only when the verdict is present and equal to `target` (case-insensitive).
fn verdict_matches(verdict: Option<&str>, target: &str) -> bool {
    match verdict {
        Some(status) => status.eq_ignore_ascii_case(target),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Message header rewriting (operates on bytes)
// ---------------------------------------------------------------------------

/// Header field names removed entirely (all occurrences) before re-sending.
const REMOVED_FIELDS: [&str; 4] = ["return-path", "sender", "message-id", "dkim-signature"];

/// The result of [`rewrite_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteOutcome {
    /// The rewritten message bytes.
    pub message: Vec<u8>,
    /// Whether a `From` header was found and rewritten. When false, the message
    /// had no `From` to rewrite (e.g. it began with a blank line, so the entire
    /// content became body), and the caller must not forward it - SES would
    /// reject a send whose raw `From` is not the verified sender.
    pub from_rewritten: bool,
}

/// Rewrite the raw message so SES will accept it for sending.
///
/// - `From` is rewritten to `from_email`, preserving any display name.
/// - `Reply-To` equal to the original `From` is added, unless one already exists
///   or the original `From` value is blank.
/// - `Return-Path`, `Sender`, `Message-ID`, and `DKIM-Signature` are removed.
/// - When `subject_prefix` is set, it is prepended to the `Subject` value.
///
/// The body is preserved exactly. When nothing needs to change, the output is
/// byte-for-byte identical to the input.
pub fn rewrite_message(
    raw: &[u8],
    from_email: &str,
    subject_prefix: Option<&str>,
) -> RewriteOutcome {
    let (header_block, separator, body) = split_message(raw);
    let line_ending = detect_line_ending(header_block);
    let fields = parse_header_fields(header_block);

    let reply_to_already_present = fields.iter().any(|field| field.name_lower == "reply-to");

    let mut new_header: Vec<u8> = Vec::with_capacity(header_block.len() + 64);
    let mut first_from_captured: Option<Vec<u8>> = None;
    let mut subject_prefixed = false;

    for field in &fields {
        if REMOVED_FIELDS.contains(&field.name_lower.as_str()) {
            continue;
        }

        if field.name_lower == "from" {
            // Rewrite the first From; drop any additional From fields so the
            // outgoing message has exactly one (no header injection).
            if first_from_captured.is_none() {
                let from_value = value_after_colon(&field.bytes);
                let rewritten = build_rewritten_from(&from_value, from_email, line_ending);
                new_header.extend_from_slice(&rewritten);
                first_from_captured = Some(from_value);
            }
            continue;
        }

        if field.name_lower == "subject" && !subject_prefixed {
            if let Some(prefix) = subject_prefix {
                subject_prefixed = true;
                new_header.extend_from_slice(&build_prefixed_subject(&field.bytes, prefix));
                continue;
            }
        }

        new_header.extend_from_slice(&field.bytes);
    }

    let from_rewritten = first_from_captured.is_some();
    if let Some(from_value) = first_from_captured {
        // Only add Reply-To when there is a real original address to reply to;
        // a blank From value would otherwise produce an empty `Reply-To:` line.
        let original_is_blank = unfold_value(&from_value).trim_ascii().is_empty();
        if !reply_to_already_present && !original_is_blank {
            new_header.extend_from_slice(&build_reply_to(&from_value, line_ending));
        }
    }

    let mut message = Vec::with_capacity(new_header.len() + separator.len() + body.len());
    message.extend_from_slice(&new_header);
    message.extend_from_slice(separator);
    message.extend_from_slice(body);

    RewriteOutcome {
        message,
        from_rewritten,
    }
}

/// Split a raw message into `(header_block, separator, body)`.
///
/// `separator` is the blank line that divides headers from body. When there is
/// no blank line the whole message is the header block.
fn split_message(raw: &[u8]) -> (&[u8], &[u8], &[u8]) {
    match find_body_boundary(raw) {
        Some((header_end, body_start)) => (
            &raw[..header_end],
            &raw[header_end..body_start],
            &raw[body_start..],
        ),
        None => (raw, &[], &[]),
    }
}

/// Find the first blank line. Returns `(header_end, body_start)` where the
/// separator bytes are `raw[header_end..body_start]`.
fn find_body_boundary(raw: &[u8]) -> Option<(usize, usize)> {
    let mut line_start = 0;
    while line_start < raw.len() {
        if raw[line_start] == b'\n' {
            return Some((line_start, line_start + 1));
        }
        if raw[line_start] == b'\r' && raw.get(line_start + 1) == Some(&b'\n') {
            return Some((line_start, line_start + 2));
        }
        let newline_index = next_newline(raw, line_start)?;
        line_start = newline_index + 1;
    }
    None
}

/// Index of the next `\n` at or after `start`, if any.
fn next_newline(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|offset| start + offset)
}

/// A parsed header field: its lowercased name and its exact raw bytes
/// (including any folded continuation lines and the trailing terminator).
#[derive(Debug)]
struct HeaderField {
    name_lower: String,
    bytes: Vec<u8>,
}

/// Parse the header block into fields, fold-aware. A field is its first line
/// plus any following continuation lines (lines beginning with space or tab).
/// The concatenation of every field's bytes equals the input exactly.
fn parse_header_fields(header_block: &[u8]) -> Vec<HeaderField> {
    let mut fields: Vec<HeaderField> = Vec::new();
    let mut index = 0;

    while index < header_block.len() {
        let field_start = index;
        index = end_of_line(header_block, index);

        while index < header_block.len()
            && (header_block[index] == b' ' || header_block[index] == b'\t')
        {
            index = end_of_line(header_block, index);
        }

        let bytes = header_block[field_start..index].to_vec();
        let name_lower = extract_field_name(&bytes);
        fields.push(HeaderField { name_lower, bytes });
    }

    fields
}

/// Index just past the next `\n` from `start`, or the end of the slice.
fn end_of_line(bytes: &[u8], start: usize) -> usize {
    match next_newline(bytes, start) {
        Some(newline_index) => newline_index + 1,
        None => bytes.len(),
    }
}

/// The lowercased field name (bytes before the first `:` on the first line).
/// A line with no colon yields an empty name and matches no transform.
fn extract_field_name(field_bytes: &[u8]) -> String {
    match field_bytes.iter().position(|&byte| byte == b':') {
        Some(colon) => String::from_utf8_lossy(&field_bytes[..colon])
            .trim()
            .to_ascii_lowercase(),
        None => String::new(),
    }
}

/// The raw bytes after the first `:` in a field (its value, including the
/// leading space, any folded continuation, and the terminator).
fn value_after_colon(field_bytes: &[u8]) -> Vec<u8> {
    match field_bytes.iter().position(|&byte| byte == b':') {
        Some(colon) => field_bytes[colon + 1..].to_vec(),
        None => field_bytes.to_vec(),
    }
}

/// Detect the line ending to use for synthesized headers, from the first line
/// terminator in the header block. Defaults to LF.
fn detect_line_ending(header_block: &[u8]) -> &'static [u8] {
    match header_block.iter().position(|&byte| byte == b'\n') {
        Some(newline_index) if newline_index > 0 && header_block[newline_index - 1] == b'\r' => {
            b"\r\n"
        }
        _ => b"\n",
    }
}

/// Build the rewritten `From` field, preserving the display name if present.
fn build_rewritten_from(original_value: &[u8], from_email: &str, line_ending: &[u8]) -> Vec<u8> {
    let unfolded = unfold_value(original_value);
    let trimmed = unfolded.trim_ascii();
    let display_name: &[u8] = match trimmed.iter().position(|&byte| byte == b'<') {
        Some(angle) => trimmed[..angle].trim_ascii(),
        None => &[],
    };

    let mut field = Vec::new();
    field.extend_from_slice(b"From: ");
    if display_name.is_empty() {
        field.extend_from_slice(from_email.as_bytes());
    } else {
        field.extend_from_slice(display_name);
        field.extend_from_slice(b" <");
        field.extend_from_slice(from_email.as_bytes());
        field.push(b'>');
    }
    field.extend_from_slice(line_ending);
    field
}

/// Build a `Reply-To` field from the captured original `From` value.
///
/// The value is unfolded first, which strips every CR and LF byte (folds become
/// single spaces). That preserves the address while guaranteeing the reused,
/// attacker-influenced bytes cannot carry a stray CR/LF into a header a lenient
/// parser might split on.
fn build_reply_to(from_value: &[u8], line_ending: &[u8]) -> Vec<u8> {
    let unfolded = unfold_value(from_value);
    let mut field = Vec::with_capacity(unfolded.len() + 16);
    field.extend_from_slice(b"Reply-To:");
    field.extend_from_slice(&unfolded);
    field.extend_from_slice(line_ending);
    field
}

/// Build the `Subject` field with `prefix` prepended to its value, preserving
/// the original leading whitespace and any folded continuation.
fn build_prefixed_subject(field_bytes: &[u8], prefix: &str) -> Vec<u8> {
    let colon = match field_bytes.iter().position(|&byte| byte == b':') {
        Some(colon) => colon,
        None => return field_bytes.to_vec(),
    };
    let (name_and_colon, after_colon) = field_bytes.split_at(colon + 1);
    let leading_whitespace_len = after_colon
        .iter()
        .take_while(|&&byte| byte == b' ' || byte == b'\t')
        .count();
    let (leading_whitespace, subject_text) = after_colon.split_at(leading_whitespace_len);

    let mut field = Vec::with_capacity(field_bytes.len() + prefix.len());
    field.extend_from_slice(name_and_colon);
    field.extend_from_slice(leading_whitespace);
    field.extend_from_slice(prefix.as_bytes());
    field.extend_from_slice(subject_text);
    field
}

/// Unfold a header value: replace each line fold (a terminator followed by
/// leading whitespace) with a single space, and drop the trailing terminator.
/// Operates on bytes so non-UTF-8 content is not corrupted.
fn unfold_value(value: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(value.len());
    let mut index = 0;

    while index < value.len() {
        let byte = value[index];
        if byte != b'\r' && byte != b'\n' {
            out.push(byte);
            index += 1;
            continue;
        }

        // Consume the terminator (\r\n, \r, or \n).
        let mut after_terminator = index;
        if value.get(after_terminator) == Some(&b'\r') {
            after_terminator += 1;
        }
        if value.get(after_terminator) == Some(&b'\n') {
            after_terminator += 1;
        }

        let is_fold = matches!(value.get(after_terminator), Some(&b' ') | Some(&b'\t'));
        if is_fold {
            out.push(b' ');
            while matches!(value.get(after_terminator), Some(&b' ') | Some(&b'\t')) {
                after_terminator += 1;
            }
        }
        index = after_terminator;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(key, destinations)| {
                let addresses = destinations.iter().map(|d| d.to_string()).collect();
                (key.to_string(), addresses)
            })
            .collect()
    }

    fn recipients(addresses: &[&str]) -> Vec<String> {
        addresses
            .iter()
            .map(|address| address.to_string())
            .collect()
    }

    // --- resolve_destinations -------------------------------------------

    #[test]
    fn resolves_exact_address_match() {
        let map = mapping(&[("info@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["info@example.com"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn resolves_domain_match() {
        let map = mapping(&[("@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["anybody@example.com"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn resolves_bare_mailbox_match() {
        let map = mapping(&[("info", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["info@anything.example"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn resolves_catch_all_match() {
        let map = mapping(&[("@", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["whoever@example.com"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn precedence_prefers_exact_over_domain_over_mailbox_over_catch_all() {
        let map = mapping(&[
            ("info@example.com", &["exact@example.net"]),
            ("@example.com", &["domain@example.net"]),
            ("info", &["mailbox@example.net"]),
            ("@", &["catchall@example.net"]),
        ]);
        let resolved =
            resolve_destinations(&recipients(&["info@example.com"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["exact@example.net"]);

        let map_without_exact = mapping(&[
            ("@example.com", &["domain@example.net"]),
            ("info", &["mailbox@example.net"]),
            ("@", &["catchall@example.net"]),
        ]);
        let resolved =
            resolve_destinations(&recipients(&["info@example.com"]), &map_without_exact, true)
                .unwrap();
        assert_eq!(resolved.destinations, vec!["domain@example.net"]);
    }

    #[test]
    fn plus_tag_is_stripped_when_allowed() {
        let map = mapping(&[("info@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["info+sales@example.com"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn plus_tag_is_literal_when_disallowed() {
        let map = mapping(&[("info@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["info+sales@example.com"]), &map, false).unwrap();
        assert!(
            resolved.destinations.is_empty(),
            "with plus disabled, info+sales is not info"
        );
    }

    #[test]
    fn recipient_is_lowercased_before_matching() {
        let map = mapping(&[("info@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["INFO@Example.COM"]), &map, true).unwrap();
        assert_eq!(resolved.destinations, vec!["dest@example.net"]);
    }

    #[test]
    fn destinations_are_deduplicated_deterministically() {
        let map = mapping(&[
            ("a@example.com", &["shared@example.net", "one@example.net"]),
            ("b@example.com", &["shared@example.net", "two@example.net"]),
        ]);
        let resolved =
            resolve_destinations(&recipients(&["a@example.com", "b@example.com"]), &map, true)
                .unwrap();
        assert_eq!(
            resolved.destinations,
            vec!["shared@example.net", "one@example.net", "two@example.net"]
        );
    }

    #[test]
    fn no_match_yields_empty_destinations() {
        let map = mapping(&[("info@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["nobody@example.com"]), &map, true).unwrap();
        assert!(resolved.destinations.is_empty());
        assert!(resolved.matched_recipients.is_empty());
    }

    #[test]
    fn more_than_fifty_destinations_errors() {
        let many: Vec<String> = (0..51).map(|n| format!("dest{n}@example.net")).collect();
        let mut map = HashMap::new();
        map.insert("@".to_string(), many);
        let error =
            resolve_destinations(&recipients(&["whoever@example.com"]), &map, true).unwrap_err();
        assert_eq!(error, ForwardError::TooManyDestinations { count: 51 });
    }

    #[test]
    fn matched_recipient_records_incoming_and_key() {
        let map = mapping(&[("@example.com", &["dest@example.net"])]);
        let resolved =
            resolve_destinations(&recipients(&["Someone@Example.com"]), &map, true).unwrap();
        assert_eq!(resolved.matched_recipients.len(), 1);
        assert_eq!(
            resolved.matched_recipients[0].incoming,
            "someone@example.com"
        );
        assert_eq!(resolved.matched_recipients[0].matched_key, "@example.com");
    }

    // --- evaluate_verdicts ----------------------------------------------

    #[test]
    fn virus_fail_always_drops() {
        assert_eq!(
            evaluate_verdicts(Some("PASS"), Some("FAIL"), false, false),
            GateDecision::Drop(DropReason::Virus)
        );
        assert_eq!(
            evaluate_verdicts(Some("PASS"), Some("FAIL"), true, true),
            GateDecision::Drop(DropReason::Virus)
        );
    }

    #[test]
    fn spam_fail_drops_only_when_drop_spam_set() {
        assert_eq!(
            evaluate_verdicts(Some("FAIL"), Some("PASS"), false, false),
            GateDecision::Forward
        );
        assert_eq!(
            evaluate_verdicts(Some("FAIL"), Some("PASS"), true, false),
            GateDecision::Drop(DropReason::Spam)
        );
    }

    #[test]
    fn unscanned_virus_drops_only_when_drop_unscanned_set() {
        // PROCESSING_FAILED means the scanner could not render a verdict.
        assert_eq!(
            evaluate_verdicts(Some("PASS"), Some("PROCESSING_FAILED"), false, false),
            GateDecision::Forward,
            "fail open by default"
        );
        assert_eq!(
            evaluate_verdicts(Some("PASS"), Some("PROCESSING_FAILED"), false, true),
            GateDecision::Drop(DropReason::UnscannedVirus),
            "fail closed with DROP_UNSCANNED"
        );
    }

    #[test]
    fn non_fail_statuses_all_forward_by_default() {
        for status in ["PASS", "GRAY", "PROCESSING_FAILED", "DISABLED"] {
            assert_eq!(
                evaluate_verdicts(Some(status), Some(status), false, false),
                GateDecision::Forward,
                "status = {status}"
            );
        }
    }

    #[test]
    fn absent_verdicts_forward() {
        assert_eq!(
            evaluate_verdicts(None, None, true, true),
            GateDecision::Forward
        );
    }

    #[test]
    fn concerning_verdict_flags_bypasses_but_not_clean_or_disabled() {
        assert!(verdict_is_concerning(Some("FAIL")));
        assert!(verdict_is_concerning(Some("GRAY")));
        assert!(verdict_is_concerning(Some("PROCESSING_FAILED")));
        assert!(!verdict_is_concerning(Some("PASS")));
        assert!(!verdict_is_concerning(Some("DISABLED")));
        assert!(!verdict_is_concerning(None));
    }

    // --- rewrite_message ------------------------------------------------

    #[test]
    fn rewrites_from_preserving_display_name_and_adds_reply_to() {
        let raw = b"From: Alice Sender <alice@example.net>\r\n\
                    To: info@example.com\r\n\
                    Subject: Hello\r\n\
                    \r\n\
                    Body text here.\r\n";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();

        assert!(text.contains("From: Alice Sender <relay@example.com>\r\n"));
        assert!(text.contains("Reply-To: Alice Sender <alice@example.net>\r\n"));
        assert!(text.contains("To: info@example.com\r\n"));
        assert!(text.contains("Subject: Hello\r\n"));
        assert!(text.ends_with("\r\nBody text here.\r\n"));
        // The original sender address survives only in Reply-To, not in From.
        assert!(!text.contains("From: Alice Sender <alice@example.net>"));
    }

    #[test]
    fn rewrites_bare_address_from_without_display_name() {
        let raw = b"From: alice@example.net\r\nTo: info@example.com\r\n\r\nbody";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("From: relay@example.com\r\n"));
        assert!(text.contains("Reply-To: alice@example.net\r\n"));
    }

    #[test]
    fn removes_return_path_sender_message_id_and_all_dkim_signatures() {
        let raw = b"Return-Path: <bounce@example.net>\r\n\
                    Sender: agent@example.net\r\n\
                    Message-ID: <abc@example.net>\r\n\
                    DKIM-Signature: v=1; a=rsa-sha256;\r\n\
                    \tbh=abc; b=def\r\n\
                    DKIM-Signature: v=1; a=ed25519-sha256; b=xyz\r\n\
                    From: Alice <alice@example.net>\r\n\
                    Subject: Hi\r\n\
                    \r\n\
                    body";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("Return-Path"));
        assert!(!text.contains("Sender:"));
        assert!(!text.contains("Message-ID"));
        assert!(!text.contains("DKIM-Signature"));
        // The folded DKIM continuation line must be gone too.
        assert!(!text.contains("bh=abc"));
        assert!(text.contains("From: Alice <relay@example.com>\r\n"));
    }

    #[test]
    fn byte_for_byte_identical_when_nothing_changes() {
        // No From, no removable headers, no subject prefix, and a body that
        // itself contains a blank line.
        let raw = b"To: info@example.com\r\n\
                    Subject: Keep me\r\n\
                    \r\n\
                    First paragraph.\r\n\
                    \r\n\
                    Second paragraph after a blank line.\r\n";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        assert_eq!(
            output,
            raw.to_vec(),
            "unchanged message must round-trip exactly"
        );
    }

    #[test]
    fn folded_from_across_continuation_lines_is_captured_for_reply_to() {
        let raw = b"From: Alice\r\n <alice@example.net>\r\nTo: info@example.com\r\n\r\nbody";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        // Reply-To preserves the original address, unfolded onto one line.
        assert!(text.contains("Reply-To: Alice <alice@example.net>\r\n"));
        // The rewritten From is unfolded onto one line with the display name.
        assert!(text.contains("From: Alice <relay@example.com>\r\n"));
    }

    #[test]
    fn bare_cr_in_from_cannot_inject_a_header_via_reply_to() {
        // A bare CR (not part of a CRLF) inside the From value must not survive
        // into Reply-To where a lenient parser could treat it as a line break.
        let raw = b"From: Alice\rBcc: attacker@evil.example <alice@example.net>\r\nTo: info@example.com\r\n\r\nbody";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        // No CR may appear inside the synthesized Reply-To line, and there is no
        // standalone Bcc header.
        let text = String::from_utf8_lossy(&output);
        assert!(!text.contains("\rBcc:"), "bare CR must be stripped");
        assert!(!text.contains("\nBcc:"), "no injected Bcc header");
    }

    #[test]
    fn existing_reply_to_is_not_duplicated() {
        let raw = b"From: Alice <alice@example.net>\r\n\
                    Reply-To: preferred@example.net\r\n\
                    To: info@example.com\r\n\
                    \r\n\
                    body";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        let reply_to_count = text.matches("Reply-To:").count();
        assert_eq!(reply_to_count, 1, "must not add a second Reply-To");
        assert!(text.contains("Reply-To: preferred@example.net\r\n"));
    }

    #[test]
    fn multiple_from_headers_collapse_to_one_without_injection() {
        let raw = b"From: Alice <alice@example.net>\r\n\
                    From: Mallory <mallory@example.net>\r\n\
                    To: info@example.com\r\n\
                    \r\n\
                    body";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        let from_count = text.matches("From:").count();
        assert_eq!(from_count, 1, "exactly one From in the output");
        assert!(text.contains("From: Alice <relay@example.com>\r\n"));
        assert!(!text.contains("mallory@example.net"));
    }

    #[test]
    fn eight_bit_body_bytes_survive_byte_for_byte() {
        let mut raw: Vec<u8> =
            b"From: Alice <alice@example.net>\r\nTo: info@example.com\r\n\r\n".to_vec();
        let body: Vec<u8> = (0u16..=255).map(|byte| byte as u8).collect();
        raw.extend_from_slice(&body);
        let output = rewrite_message(&raw, "relay@example.com", None).message;

        // The output must end with the exact 0x00..=0xFF body bytes.
        assert!(
            output.ends_with(&body),
            "8-bit body bytes must be preserved exactly"
        );
    }

    #[test]
    fn lf_only_line_endings_are_handled() {
        let raw = b"From: Alice <alice@example.net>\nTo: info@example.com\n\nbody";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("From: Alice <relay@example.com>\n"));
        assert!(text.contains("Reply-To: Alice <alice@example.net>\n"));
        assert!(text.ends_with("\nbody"));
    }

    #[test]
    fn header_only_message_with_no_blank_line_round_trips_when_unchanged() {
        let raw = b"To: info@example.com\r\nSubject: no body\r\n";
        let output = rewrite_message(raw, "relay@example.com", None).message;
        assert_eq!(output, raw.to_vec());
    }

    #[test]
    fn subject_prefix_is_prepended_preserving_the_rest() {
        let raw = b"From: Alice <alice@example.net>\r\nSubject: Hello\r\n\r\nbody";
        let output = rewrite_message(raw, "relay@example.com", Some("[EXT] ")).message;
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Subject: [EXT] Hello\r\n"));
    }

    #[test]
    fn subject_prefix_without_existing_subject_adds_nothing() {
        let raw = b"From: Alice <alice@example.net>\r\nTo: info@example.com\r\n\r\nbody";
        let output = rewrite_message(raw, "relay@example.com", Some("[EXT] ")).message;
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("[EXT]"), "no Subject to prefix");
    }

    #[test]
    fn redos_guard_pathological_message_processes_quickly() {
        // Thousands of blank/whitespace-fold lines. A linear scan handles this
        // in well under a second; a backtracking regex would not.
        let mut raw: Vec<u8> = b"From: Alice <alice@example.net>\r\n".to_vec();
        for _ in 0..200_000 {
            raw.extend_from_slice(b" \t \t\r\n");
        }
        raw.extend_from_slice(b"To: info@example.com\r\n\r\nbody");

        let start = std::time::Instant::now();
        let output = rewrite_message(&raw, "relay@example.com", None).message;
        let elapsed = start.elapsed();

        assert!(!output.is_empty());
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "rewrite took {elapsed:?}, expected < 1s"
        );
    }

    #[test]
    fn from_rewritten_is_true_when_a_from_header_exists() {
        let raw = b"From: Bob <bob@example.net>\r\nTo: info@example.com\r\n\r\nbody";
        let outcome = rewrite_message(raw, "relay@example.com", None);
        assert!(outcome.from_rewritten);
    }

    #[test]
    fn no_from_header_reports_from_not_rewritten_and_adds_no_reply_to() {
        // A message that begins with a blank line has an empty header block, so
        // there is no From to rewrite and no Reply-To should be synthesized.
        let raw = b"\r\nFrom: attacker@evil.example\r\nTo: info@example.com\r\n\r\nbody";
        let outcome = rewrite_message(raw, "relay@example.com", None);
        assert!(!outcome.from_rewritten, "no header From existed to rewrite");
        let text = String::from_utf8(outcome.message).unwrap();
        assert!(!text.contains("Reply-To:"), "no Reply-To without a From");
    }

    #[test]
    fn empty_from_value_does_not_emit_an_empty_reply_to() {
        let raw = b"From:\r\nTo: info@example.com\r\n\r\nbody";
        let outcome = rewrite_message(raw, "relay@example.com", None);
        assert!(
            outcome.from_rewritten,
            "the From field existed and was rewritten"
        );
        let text = String::from_utf8(outcome.message).unwrap();
        assert!(text.contains("From: relay@example.com\r\n"));
        assert!(
            !text.contains("Reply-To:"),
            "blank original From -> no Reply-To"
        );
    }

    #[test]
    fn header_field_name_matching_is_case_insensitive() {
        // Unusual casing on the field names must still be matched and rewritten.
        let raw = b"FROM: Alice <alice@example.net>\r\n\
                    DKIM-signature: v=1; b=abc\r\n\
                    Message-id: <x@example.net>\r\n\
                    To: info@example.com\r\n\
                    \r\n\
                    body";
        let outcome = rewrite_message(raw, "relay@example.com", None);
        assert!(outcome.from_rewritten);
        let text = String::from_utf8(outcome.message).unwrap();
        assert!(text.contains("From: Alice <relay@example.com>\r\n"));
        assert!(!text.to_ascii_lowercase().contains("dkim-signature"));
        assert!(!text.to_ascii_lowercase().contains("message-id"));
    }
}
