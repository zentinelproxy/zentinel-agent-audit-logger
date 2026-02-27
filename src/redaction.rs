//! PII redaction and data masking.

use crate::config::RedactionConfig;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;

/// PII redactor that applies configured patterns to text.
pub struct Redactor {
    /// Compiled regex patterns
    patterns: Vec<CompiledPattern>,
    /// Default replacement text
    replacement: String,
    /// Whether to hash original values
    hash_original: bool,
    /// Headers to always redact
    redact_headers: Vec<String>,
    /// JSON fields to always redact
    redact_fields: Vec<String>,
}

struct CompiledPattern {
    name: String,
    regex: Regex,
    replacement: Option<String>,
}

impl Redactor {
    /// Create a new redactor from configuration.
    pub fn new(config: &RedactionConfig) -> Self {
        let mut patterns = Vec::new();

        // Compile built-in patterns
        for pattern in &config.patterns {
            if let Ok(regex) = Regex::new(pattern.regex()) {
                patterns.push(CompiledPattern {
                    name: pattern.name().to_string(),
                    regex,
                    replacement: None,
                });
            }
        }

        // Compile custom patterns
        for custom in &config.custom_patterns {
            if let Ok(regex) = Regex::new(&custom.pattern) {
                patterns.push(CompiledPattern {
                    name: custom.name.clone(),
                    regex,
                    replacement: custom.replacement.clone(),
                });
            }
        }

        Self {
            patterns,
            replacement: config.replacement.clone(),
            hash_original: config.hash_original,
            redact_headers: config
                .redact_headers
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
            redact_fields: config.redact_fields.clone(),
        }
    }

    /// Create a no-op redactor (passes through unchanged).
    pub fn noop() -> Self {
        Self {
            patterns: Vec::new(),
            replacement: String::new(),
            hash_original: false,
            redact_headers: Vec::new(),
            redact_fields: Vec::new(),
        }
    }

    /// Redact PII from a string.
    pub fn redact_string<'a>(&self, input: &'a str) -> Cow<'a, str> {
        if self.patterns.is_empty() {
            return Cow::Borrowed(input);
        }

        let mut result = Cow::Borrowed(input);

        for pattern in &self.patterns {
            if pattern.regex.is_match(&result) {
                let replacement = if self.hash_original {
                    // Hash the matched value for correlation
                    pattern
                        .regex
                        .replace_all(&result, |caps: &regex::Captures| {
                            let matched = caps.get(0).map_or("", |m| m.as_str());
                            let hash = self.hash_value(matched);
                            format!(
                                "[REDACTED:{}:{}]",
                                pattern.name,
                                &hash[..8] // First 8 chars of hash
                            )
                        })
                } else {
                    let repl = pattern.replacement.as_deref().unwrap_or(&self.replacement);
                    pattern.regex.replace_all(&result, repl)
                };

                result = Cow::Owned(replacement.into_owned());
            }
        }

        result
    }

    /// Redact headers based on configuration.
    pub fn redact_headers(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| {
                let key_lower = k.to_lowercase();
                if self.redact_headers.contains(&key_lower) {
                    (k.clone(), self.replacement.clone())
                } else {
                    (k.clone(), self.redact_string(v).into_owned())
                }
            })
            .collect()
    }

    /// Redact JSON body based on field paths.
    pub fn redact_json(&self, json: &str) -> String {
        // First apply pattern-based redaction to the whole string
        let redacted = self.redact_string(json);

        // Then apply field-specific redaction if configured
        if self.redact_fields.is_empty() {
            return redacted.into_owned();
        }

        // Parse and redact specific fields
        match serde_json::from_str::<serde_json::Value>(&redacted) {
            Ok(mut value) => {
                for field_path in &self.redact_fields {
                    self.redact_json_field(&mut value, field_path);
                }
                serde_json::to_string(&value).unwrap_or_else(|_| redacted.into_owned())
            }
            Err(_) => redacted.into_owned(),
        }
    }

    /// Redact a specific field in JSON by dot-notation path.
    fn redact_json_field(&self, value: &mut serde_json::Value, path: &str) {
        let parts: Vec<&str> = path.split('.').collect();
        self.redact_json_field_recursive(value, &parts);
    }

    fn redact_json_field_recursive(&self, value: &mut serde_json::Value, path: &[&str]) {
        if path.is_empty() {
            return;
        }

        match value {
            serde_json::Value::Object(map) => {
                if path.len() == 1 {
                    // Final field - redact it
                    if map.contains_key(path[0]) {
                        map.insert(
                            path[0].to_string(),
                            serde_json::Value::String(self.replacement.clone()),
                        );
                    }
                } else {
                    // Recurse into nested object
                    if let Some(nested) = map.get_mut(path[0]) {
                        self.redact_json_field_recursive(nested, &path[1..]);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                // Apply to all array elements
                for item in arr {
                    self.redact_json_field_recursive(item, path);
                }
            }
            _ => {}
        }
    }

    /// Hash a value using SHA-256.
    fn hash_value(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Check if a header should be redacted.
    pub fn should_redact_header(&self, header_name: &str) -> bool {
        self.redact_headers.contains(&header_name.to_lowercase())
    }
}

/// Truncate a string to a maximum length.
pub fn truncate_body(body: &str, max_size: usize, indicator: &str) -> String {
    if body.len() <= max_size {
        body.to_string()
    } else {
        let truncate_at = max_size.saturating_sub(indicator.len());
        format!("{}{}", &body[..truncate_at], indicator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CustomRedactionPattern, RedactionPattern};

    fn test_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            patterns: vec![
                RedactionPattern::Email,
                RedactionPattern::CreditCard,
                RedactionPattern::Ssn,
            ],
            custom_patterns: Vec::new(),
            replacement: "[REDACTED]".to_string(),
            hash_original: false,
            redact_headers: vec!["authorization".to_string(), "cookie".to_string()],
            redact_fields: vec!["password".to_string(), "user.ssn".to_string()],
        }
    }

    #[test]
    fn test_redact_email() {
        let redactor = Redactor::new(&test_config());
        let input = "Contact us at support@example.com for help";
        let output = redactor.redact_string(input);
        assert_eq!(output, "Contact us at [REDACTED] for help");
    }

    #[test]
    fn test_redact_credit_card() {
        let redactor = Redactor::new(&test_config());
        let input = "Card number: 4111-1111-1111-1111";
        let output = redactor.redact_string(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("4111"));
    }

    #[test]
    fn test_redact_ssn() {
        let redactor = Redactor::new(&test_config());
        let input = "SSN: 123-45-6789";
        let output = redactor.redact_string(input);
        assert_eq!(output, "SSN: [REDACTED]");
    }

    #[test]
    fn test_redact_multiple() {
        let redactor = Redactor::new(&test_config());
        let input = "Email: test@example.com, SSN: 123-45-6789";
        let output = redactor.redact_string(input);
        assert!(!output.contains("test@example.com"));
        assert!(!output.contains("123-45-6789"));
    }

    #[test]
    fn test_no_redaction_needed() {
        let redactor = Redactor::new(&test_config());
        let input = "Hello, world!";
        let output = redactor.redact_string(input);
        assert_eq!(output, "Hello, world!");
    }

    #[test]
    fn test_redact_headers() {
        let redactor = Redactor::new(&test_config());
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer secret-token".to_string(),
        );
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let redacted = redactor.redact_headers(&headers);
        assert_eq!(
            redacted.get("Authorization"),
            Some(&"[REDACTED]".to_string())
        );
        assert_eq!(
            redacted.get("Content-Type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_redact_json_field() {
        let redactor = Redactor::new(&test_config());
        let json = r#"{"username": "john", "password": "secret123"}"#;
        let redacted = redactor.redact_json(json);
        let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();

        assert_eq!(parsed["username"], "john");
        assert_eq!(parsed["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_nested_json_field() {
        let redactor = Redactor::new(&test_config());
        let json = r#"{"user": {"name": "john", "ssn": "123-45-6789"}}"#;
        let redacted = redactor.redact_json(json);
        let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();

        assert_eq!(parsed["user"]["name"], "john");
        assert_eq!(parsed["user"]["ssn"], "[REDACTED]");
    }

    #[test]
    fn test_hash_original() {
        let mut config = test_config();
        config.hash_original = true;
        let redactor = Redactor::new(&config);

        let input = "Email: test@example.com";
        let output = redactor.redact_string(input);

        assert!(output.contains("[REDACTED:email:"));
        assert!(!output.contains("test@example.com"));
    }

    #[test]
    fn test_custom_pattern() {
        let mut config = test_config();
        config.custom_patterns.push(CustomRedactionPattern {
            name: "account_id".to_string(),
            pattern: r"ACC-\d{8}".to_string(),
            replacement: Some("[ACCOUNT]".to_string()),
        });

        let redactor = Redactor::new(&config);
        let input = "Account: ACC-12345678";
        let output = redactor.redact_string(input);
        assert_eq!(output, "Account: [ACCOUNT]");
    }

    #[test]
    fn test_truncate_body() {
        let body = "This is a very long body that needs truncation";
        let truncated = truncate_body(body, 20, "...[truncated]");
        assert!(truncated.len() <= 20);
        assert!(truncated.ends_with("...[truncated]"));
    }

    #[test]
    fn test_truncate_body_short() {
        let body = "Short body";
        let truncated = truncate_body(body, 100, "...[truncated]");
        assert_eq!(truncated, "Short body");
    }

    #[test]
    fn test_noop_redactor() {
        let redactor = Redactor::noop();
        let input = "test@example.com 123-45-6789";
        let output = redactor.redact_string(input);
        assert_eq!(output, input);
    }
}
