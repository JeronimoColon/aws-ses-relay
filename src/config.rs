//! Configuration loaded entirely from environment variables.
//!
//! No configuration value is ever written into the source, so private data
//! cannot leak through the code. [`Config::from_env`] validates everything and
//! reports *all* problems at once rather than failing on the first, so an
//! operator fixing a misconfiguration sees the complete list in one deploy.

use std::collections::HashMap;
use std::fmt;

/// Fully validated configuration for the forwarder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Verified-domain address that all forwarded mail is sent as.
    pub from_email: String,
    /// S3 bucket SES writes inbound mail to; also an allowlist cross-check
    /// against the bucket named in the event.
    pub email_bucket: String,
    /// Lowercased match key -> non-empty list of destination addresses.
    pub forward_mapping: HashMap<String, Vec<String>>,
    /// Prepended to the Subject when present. Absent means "no prefix".
    pub subject_prefix: Option<String>,
    /// When true, a `+tag` suffix in the recipient mailbox is stripped before
    /// matching (so `info+sales@example.com` matches as `info@example.com`).
    pub allow_plus_sign: bool,
    /// When true, messages whose spam verdict is `FAIL` are dropped.
    pub drop_spam: bool,
}

/// Aggregated configuration error: carries every problem found, not just the
/// first, so the operator can fix them all in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub problems: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "invalid configuration ({} problem(s)):",
            self.problems.len()
        )?;
        for problem in &self.problems {
            writeln!(formatter, "  - {problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load and validate configuration from the process environment.
    pub fn from_process_env() -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Config::from_env(&vars)
    }

    /// Load and validate configuration from an explicit variable map.
    ///
    /// Every problem is collected and returned together; the function never
    /// stops at the first error.
    pub fn from_env(vars: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let mut problems: Vec<String> = Vec::new();

        let from_email = required(vars, "FROM_EMAIL", &mut problems)
            .and_then(|value| validate_email("FROM_EMAIL", value, &mut problems));

        let email_bucket = required(vars, "EMAIL_BUCKET", &mut problems);

        let forward_mapping = required(vars, "FORWARD_MAPPING", &mut problems)
            .and_then(|raw| parse_forward_mapping(&raw, &mut problems));

        let subject_prefix = match vars.get("SUBJECT_PREFIX") {
            Some(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        };

        let allow_plus_sign = parse_optional_bool(vars, "ALLOW_PLUS_SIGN", true, &mut problems);
        let drop_spam = parse_optional_bool(vars, "DROP_SPAM", false, &mut problems);

        if !problems.is_empty() {
            return Err(ConfigError { problems });
        }

        // Every required value is `Some` here: any missing/invalid one would
        // have pushed a problem above and returned via the guard.
        Ok(Config {
            from_email: from_email.expect("validated: FROM_EMAIL present"),
            email_bucket: email_bucket.expect("validated: EMAIL_BUCKET present"),
            forward_mapping: forward_mapping.expect("validated: FORWARD_MAPPING present"),
            subject_prefix,
            allow_plus_sign,
            drop_spam,
        })
    }
}

/// Fetch a required variable, trimming surrounding whitespace. Records a
/// problem (and returns `None`) when the variable is missing or blank.
fn required(
    vars: &HashMap<String, String>,
    name: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    match vars.get(name) {
        Some(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        Some(_) => {
            problems.push(format!("{name} is set but empty"));
            None
        }
        None => {
            problems.push(format!("{name} is required but not set"));
            None
        }
    }
}

/// Light sanity check: the address must be `local@domain` with both parts
/// non-empty. Stricter RFC validation is intentionally avoided — a malformed
/// address that slips past this is rejected by SES at send time anyway.
fn validate_email(name: &str, value: String, problems: &mut Vec<String>) -> Option<String> {
    let parts: Vec<&str> = value.split('@').collect();
    let looks_like_email = parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty();
    if looks_like_email {
        Some(value)
    } else {
        problems.push(format!(
            "{name} must be a valid email address (local@domain); got `{value}`"
        ));
        None
    }
}

/// Parse a strict boolean: only `true`/`false` (case-insensitive) are accepted.
/// When the variable is absent, the default is used. When it is present but not
/// a strict boolean, a problem is recorded and the default is returned so
/// parsing can continue and surface any further problems.
fn parse_optional_bool(
    vars: &HashMap<String, String>,
    name: &str,
    default: bool,
    problems: &mut Vec<String>,
) -> bool {
    let Some(raw) = vars.get(name) else {
        return default;
    };
    match raw.to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            problems.push(format!(
                "{name} must be `true` or `false` (case-insensitive); got `{raw}`"
            ));
            default
        }
    }
}

/// Parse and validate `FORWARD_MAPPING`: a JSON object whose values are
/// non-empty arrays of non-empty destination strings. Keys are lowercased.
fn parse_forward_mapping(
    raw: &str,
    problems: &mut Vec<String>,
) -> Option<HashMap<String, Vec<String>>> {
    let parsed_json: serde_json::Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(error) => {
            problems.push(format!("FORWARD_MAPPING is not valid JSON: {error}"));
            return None;
        }
    };

    let object = match parsed_json {
        serde_json::Value::Object(map) => map,
        _ => {
            problems.push(
                "FORWARD_MAPPING must be a JSON object mapping match keys to arrays of \
                 destination addresses"
                    .to_string(),
            );
            return None;
        }
    };

    if object.is_empty() {
        problems.push("FORWARD_MAPPING must contain at least one mapping".to_string());
        return None;
    }

    let mut mapping: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_entries_valid = true;

    for (key, value) in object {
        match parse_destinations(&key, value, problems) {
            Some(destinations) => {
                let normalized_key = key.to_ascii_lowercase();
                match mapping.entry(normalized_key) {
                    std::collections::hash_map::Entry::Occupied(existing) => {
                        problems.push(format!(
                            "FORWARD_MAPPING has duplicate key `{}` after lowercasing; \
                             keys must be unique",
                            existing.key()
                        ));
                        all_entries_valid = false;
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(destinations);
                    }
                }
            }
            None => all_entries_valid = false,
        }
    }

    if all_entries_valid {
        Some(mapping)
    } else {
        None
    }
}

/// Validate the destination list for a single mapping key. Returns the parsed,
/// trimmed addresses, or `None` (recording problems) if the value is not a
/// non-empty array of non-empty strings.
fn parse_destinations(
    key: &str,
    value: serde_json::Value,
    problems: &mut Vec<String>,
) -> Option<Vec<String>> {
    let items = match value {
        serde_json::Value::Array(items) => items,
        _ => {
            problems.push(format!(
                "FORWARD_MAPPING key `{key}` must map to a non-empty array of addresses"
            ));
            return None;
        }
    };

    if items.is_empty() {
        problems.push(format!(
            "FORWARD_MAPPING key `{key}` maps to an empty array; provide at least one destination"
        ));
        return None;
    }

    let mut destinations: Vec<String> = Vec::new();
    let mut entry_valid = true;

    for item in items {
        match item {
            serde_json::Value::String(address) if !address.trim().is_empty() => {
                destinations.push(address.trim().to_string());
            }
            serde_json::Value::String(_) => {
                problems.push(format!(
                    "FORWARD_MAPPING key `{key}` contains an empty destination address"
                ));
                entry_valid = false;
            }
            _ => {
                problems.push(format!(
                    "FORWARD_MAPPING key `{key}` contains a non-string destination"
                ));
                entry_valid = false;
            }
        }
    }

    if entry_valid {
        Some(destinations)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a variable map from `(name, value)` pairs.
    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    /// A complete, valid environment used as the baseline for most tests.
    fn valid_vars() -> HashMap<String, String> {
        vars(&[
            ("FROM_EMAIL", "relay@example.com"),
            ("EMAIL_BUCKET", "inbound-mail-example"),
            (
                "FORWARD_MAPPING",
                r#"{"info@example.com":["dest@example.net"],"@":["catchall@example.net"]}"#,
            ),
        ])
    }

    #[test]
    fn all_present_succeeds_with_defaults() {
        let config = Config::from_env(&valid_vars()).expect("config should be valid");
        assert_eq!(config.from_email, "relay@example.com");
        assert_eq!(config.email_bucket, "inbound-mail-example");
        assert_eq!(config.subject_prefix, None);
        assert!(config.allow_plus_sign, "ALLOW_PLUS_SIGN defaults to true");
        assert!(!config.drop_spam, "DROP_SPAM defaults to false");
        assert_eq!(
            config.forward_mapping.get("info@example.com"),
            Some(&vec!["dest@example.net".to_string()])
        );
    }

    #[test]
    fn missing_from_email_errors() {
        let mut environment = valid_vars();
        environment.remove("FROM_EMAIL");
        let error = Config::from_env(&environment).expect_err("missing FROM_EMAIL");
        assert!(error.problems.iter().any(|p| p.contains("FROM_EMAIL")));
    }

    #[test]
    fn missing_email_bucket_errors() {
        let mut environment = valid_vars();
        environment.remove("EMAIL_BUCKET");
        let error = Config::from_env(&environment).expect_err("missing EMAIL_BUCKET");
        assert!(error.problems.iter().any(|p| p.contains("EMAIL_BUCKET")));
    }

    #[test]
    fn missing_forward_mapping_errors() {
        let mut environment = valid_vars();
        environment.remove("FORWARD_MAPPING");
        let error = Config::from_env(&environment).expect_err("missing FORWARD_MAPPING");
        assert!(error.problems.iter().any(|p| p.contains("FORWARD_MAPPING")));
    }

    #[test]
    fn all_missing_required_surfaces_every_problem_at_once() {
        let environment = HashMap::new();
        let error = Config::from_env(&environment).expect_err("empty environment");
        assert!(error.problems.iter().any(|p| p.contains("FROM_EMAIL")));
        assert!(error.problems.iter().any(|p| p.contains("EMAIL_BUCKET")));
        assert!(error.problems.iter().any(|p| p.contains("FORWARD_MAPPING")));
        assert_eq!(
            error.problems.len(),
            3,
            "exactly three required vars missing"
        );
    }

    #[test]
    fn invalid_forward_mapping_json_errors() {
        let mut environment = valid_vars();
        environment.insert("FORWARD_MAPPING".to_string(), "{not json".to_string());
        let error = Config::from_env(&environment).expect_err("invalid JSON");
        assert!(error.problems.iter().any(|p| p.contains("not valid JSON")));
    }

    #[test]
    fn non_object_forward_mapping_errors() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"["dest@example.net"]"#.to_string(),
        );
        let error = Config::from_env(&environment).expect_err("array is not an object");
        assert!(error
            .problems
            .iter()
            .any(|p| p.contains("must be a JSON object")));
    }

    #[test]
    fn empty_array_value_errors() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"{"info@example.com":[]}"#.to_string(),
        );
        let error = Config::from_env(&environment).expect_err("empty destination array");
        assert!(error.problems.iter().any(|p| p.contains("empty array")));
    }

    #[test]
    fn non_string_value_errors() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"{"info@example.com":[42]}"#.to_string(),
        );
        let error = Config::from_env(&environment).expect_err("non-string destination");
        assert!(error
            .problems
            .iter()
            .any(|p| p.contains("non-string destination")));
    }

    #[test]
    fn empty_string_destination_errors() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"{"info@example.com":["  "]}"#.to_string(),
        );
        let error = Config::from_env(&environment).expect_err("blank destination");
        assert!(error
            .problems
            .iter()
            .any(|p| p.contains("empty destination")));
    }

    #[test]
    fn keys_are_lowercased() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"{"Info@Example.COM":["dest@example.net"]}"#.to_string(),
        );
        let config = Config::from_env(&environment).expect("config should be valid");
        assert!(config.forward_mapping.contains_key("info@example.com"));
        assert!(!config.forward_mapping.contains_key("Info@Example.COM"));
    }

    #[test]
    fn duplicate_key_after_lowercasing_errors() {
        let mut environment = valid_vars();
        environment.insert(
            "FORWARD_MAPPING".to_string(),
            r#"{"Info":["a@example.net"],"info":["b@example.net"]}"#.to_string(),
        );
        let error = Config::from_env(&environment).expect_err("case-colliding keys");
        assert!(error.problems.iter().any(|p| p.contains("duplicate key")));
    }

    #[test]
    fn allow_plus_sign_accepts_true_false_case_insensitively() {
        for (raw, expected) in [
            ("true", true),
            ("TRUE", true),
            ("False", false),
            ("FALSE", false),
        ] {
            let mut environment = valid_vars();
            environment.insert("ALLOW_PLUS_SIGN".to_string(), raw.to_string());
            let config = Config::from_env(&environment).expect("valid boolean");
            assert_eq!(config.allow_plus_sign, expected, "raw = {raw}");
        }
    }

    #[test]
    fn allow_plus_sign_rejects_non_boolean_tokens() {
        for raw in ["1", "0", "yes", "no", "on", "off"] {
            let mut environment = valid_vars();
            environment.insert("ALLOW_PLUS_SIGN".to_string(), raw.to_string());
            let error = Config::from_env(&environment).expect_err("non-boolean token");
            assert!(
                error.problems.iter().any(|p| p.contains("ALLOW_PLUS_SIGN")),
                "raw = {raw}"
            );
        }
    }

    #[test]
    fn drop_spam_rejects_non_boolean_tokens() {
        let mut environment = valid_vars();
        environment.insert("DROP_SPAM".to_string(), "yes".to_string());
        let error = Config::from_env(&environment).expect_err("non-boolean token");
        assert!(error.problems.iter().any(|p| p.contains("DROP_SPAM")));
    }

    #[test]
    fn drop_spam_true_is_parsed() {
        let mut environment = valid_vars();
        environment.insert("DROP_SPAM".to_string(), "true".to_string());
        let config = Config::from_env(&environment).expect("valid boolean");
        assert!(config.drop_spam);
    }

    #[test]
    fn subject_prefix_empty_is_none_nonempty_is_some() {
        let mut environment = valid_vars();
        environment.insert("SUBJECT_PREFIX".to_string(), String::new());
        let config = Config::from_env(&environment).expect("empty prefix is valid");
        assert_eq!(config.subject_prefix, None);

        // A trailing space in the prefix is meaningful and must be preserved.
        environment.insert("SUBJECT_PREFIX".to_string(), "[EXT] ".to_string());
        let config = Config::from_env(&environment).expect("prefix is valid");
        assert_eq!(config.subject_prefix, Some("[EXT] ".to_string()));
    }

    #[test]
    fn blank_from_email_is_reported_as_empty() {
        let mut environment = valid_vars();
        environment.insert("FROM_EMAIL".to_string(), "   ".to_string());
        let error = Config::from_env(&environment).expect_err("blank FROM_EMAIL");
        assert!(error
            .problems
            .iter()
            .any(|p| p.contains("FROM_EMAIL is set but empty")));
    }

    #[test]
    fn malformed_from_email_is_rejected() {
        let mut environment = valid_vars();
        environment.insert("FROM_EMAIL".to_string(), "not-an-email".to_string());
        let error = Config::from_env(&environment).expect_err("malformed FROM_EMAIL");
        assert!(error
            .problems
            .iter()
            .any(|p| p.contains("valid email address")));
    }
}
