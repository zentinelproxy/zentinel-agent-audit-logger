//! Configuration types for the audit logger agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main configuration for the audit logger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditLoggerConfig {
    /// Log format settings
    pub format: FormatConfig,
    /// Fields to include in logs
    pub fields: FieldsConfig,
    /// Output destinations
    pub outputs: Vec<OutputConfig>,
    /// PII redaction settings
    pub redaction: RedactionConfig,
    /// Body logging settings
    pub body: BodyConfig,
    /// Compliance template (optional, overrides other settings)
    pub compliance_template: Option<ComplianceTemplate>,
    /// Sampling rate (0.0 to 1.0, default 1.0 = log everything)
    pub sample_rate: f64,
    /// Only log requests matching these conditions
    pub filters: Vec<FilterConfig>,
}

impl Default for AuditLoggerConfig {
    fn default() -> Self {
        Self {
            format: FormatConfig::default(),
            fields: FieldsConfig::default(),
            outputs: vec![OutputConfig::Stdout],
            redaction: RedactionConfig::default(),
            body: BodyConfig::default(),
            compliance_template: None,
            sample_rate: 1.0,
            filters: Vec::new(),
        }
    }
}

/// Log format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FormatConfig {
    /// Output format type
    pub format_type: FormatType,
    /// Pretty print JSON (only for JSON format)
    pub pretty: bool,
    /// Include timestamp in logs
    pub include_timestamp: bool,
    /// Timestamp format (strftime)
    pub timestamp_format: String,
    /// CEF/LEEF device vendor
    pub device_vendor: String,
    /// CEF/LEEF device product
    pub device_product: String,
    /// CEF/LEEF device version
    pub device_version: String,
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self {
            format_type: FormatType::Json,
            pretty: false,
            include_timestamp: true,
            timestamp_format: "%Y-%m-%dT%H:%M:%S%.3fZ".to_string(),
            device_vendor: "Zentinel".to_string(),
            device_product: "AuditLogger".to_string(),
            device_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Supported log formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FormatType {
    /// JSON format
    Json,
    /// Common Event Format (ArcSight)
    Cef,
    /// Log Event Extended Format (IBM QRadar)
    Leef,
}

/// Fields to include in audit logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FieldsConfig {
    // Request metadata
    pub correlation_id: bool,
    pub timestamp: bool,
    pub client_ip: bool,
    pub method: bool,
    pub path: bool,
    pub query_string: bool,
    pub protocol: bool,
    pub host: bool,

    // Request details
    pub request_headers: HeaderFieldConfig,
    pub request_body: bool,
    pub request_body_size: bool,

    // Response details
    pub status_code: bool,
    pub response_headers: HeaderFieldConfig,
    pub response_body: bool,
    pub response_body_size: bool,

    // Timing
    pub duration_ms: bool,
    pub upstream_duration_ms: bool,

    // Routing
    pub route_id: bool,
    pub upstream: bool,

    // Security context
    pub user_id: bool,
    pub user_id_header: String,
    pub session_id: bool,
    pub session_id_header: String,

    // Agent decisions
    pub agent_decisions: bool,

    // Custom fields from headers
    pub custom_fields: HashMap<String, String>,
}

impl Default for FieldsConfig {
    fn default() -> Self {
        Self {
            correlation_id: true,
            timestamp: true,
            client_ip: true,
            method: true,
            path: true,
            query_string: true,
            protocol: true,
            host: true,
            request_headers: HeaderFieldConfig::default(),
            request_body: false,
            request_body_size: true,
            status_code: true,
            response_headers: HeaderFieldConfig::None,
            response_body: false,
            response_body_size: true,
            duration_ms: true,
            upstream_duration_ms: true,
            route_id: true,
            upstream: true,
            user_id: true,
            user_id_header: "x-user-id".to_string(),
            session_id: true,
            session_id_header: "x-session-id".to_string(),
            agent_decisions: true,
            custom_fields: HashMap::new(),
        }
    }
}

/// Header field inclusion configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HeaderFieldConfig {
    /// Don't include headers
    None,
    /// Include all headers
    All,
    /// Include only specified headers
    Include(Vec<String>),
    /// Include all except specified headers
    Exclude(Vec<String>),
}

impl Default for HeaderFieldConfig {
    fn default() -> Self {
        // Default: include common useful headers, exclude sensitive ones
        Self::Include(vec![
            "content-type".to_string(),
            "content-length".to_string(),
            "user-agent".to_string(),
            "accept".to_string(),
            "accept-language".to_string(),
            "referer".to_string(),
            "origin".to_string(),
            "x-forwarded-for".to_string(),
            "x-real-ip".to_string(),
            "x-request-id".to_string(),
        ])
    }
}

/// Output destination configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutputConfig {
    /// Write to stdout
    Stdout,
    /// Write to stderr
    Stderr,
    /// Write to file
    File {
        path: PathBuf,
        /// Rotate files by size (bytes)
        max_size: Option<u64>,
        /// Maximum number of rotated files to keep
        max_files: Option<u32>,
    },
    /// Send via syslog
    Syslog {
        /// Syslog server address (host:port)
        address: String,
        /// Protocol: udp or tcp
        protocol: SyslogProtocol,
        /// Syslog facility
        facility: SyslogFacility,
    },
    /// Send via HTTP webhook
    #[cfg(feature = "http-output")]
    Http {
        /// Webhook URL
        url: String,
        /// HTTP method (POST or PUT)
        method: HttpMethod,
        /// Additional headers
        headers: HashMap<String, String>,
        /// Batch size (number of events before sending)
        batch_size: usize,
        /// Flush interval in seconds
        flush_interval_secs: u64,
        /// Timeout in seconds
        timeout_secs: u64,
        /// Retry count
        retries: u32,
    },
    /// Send to Kafka
    #[cfg(feature = "kafka-output")]
    Kafka {
        /// Kafka brokers
        brokers: String,
        /// Topic name
        topic: String,
        /// Optional key field (use a field value as partition key)
        key_field: Option<String>,
        /// Additional Kafka config
        config: HashMap<String, String>,
    },
}

/// Syslog protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    Udp,
    Tcp,
}

/// Syslog facility.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl SyslogFacility {
    pub fn code(&self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Authpriv => 10,
            Self::Ftp => 11,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

/// HTTP method for webhook output.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Post,
    Put,
}

/// PII redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionConfig {
    /// Enable PII redaction
    pub enabled: bool,
    /// Built-in patterns to use
    pub patterns: Vec<RedactionPattern>,
    /// Custom regex patterns
    pub custom_patterns: Vec<CustomRedactionPattern>,
    /// Redaction replacement text
    pub replacement: String,
    /// Hash the original value (for correlation)
    pub hash_original: bool,
    /// Headers to always redact
    pub redact_headers: Vec<String>,
    /// JSON fields to always redact (dot notation: "user.email")
    pub redact_fields: Vec<String>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                RedactionPattern::Email,
                RedactionPattern::CreditCard,
                RedactionPattern::Ssn,
                RedactionPattern::Phone,
            ],
            custom_patterns: Vec::new(),
            replacement: "[REDACTED]".to_string(),
            hash_original: false,
            redact_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "set-cookie".to_string(),
                "x-api-key".to_string(),
                "x-auth-token".to_string(),
            ],
            redact_fields: Vec::new(),
        }
    }
}

/// Built-in redaction patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPattern {
    /// Email addresses
    Email,
    /// Credit card numbers (Luhn-valid patterns)
    CreditCard,
    /// US Social Security Numbers
    Ssn,
    /// Phone numbers (various formats)
    Phone,
    /// IP addresses (IPv4 and IPv6)
    IpAddress,
    /// JWT tokens
    Jwt,
    /// AWS access keys
    AwsKey,
    /// Generic API keys (long alphanumeric strings)
    ApiKey,
}

impl RedactionPattern {
    /// Get the regex pattern for this redaction type.
    pub fn regex(&self) -> &'static str {
        match self {
            Self::Email => r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Self::CreditCard => r"\b(?:\d[ -]*?){13,16}\b",
            Self::Ssn => r"\b\d{3}-\d{2}-\d{4}\b",
            Self::Phone => r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
            Self::IpAddress => r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
            Self::Jwt => r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b",
            Self::AwsKey => r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
            Self::ApiKey => r"\b[a-zA-Z0-9]{32,}\b",
        }
    }

    /// Get the display name for this pattern.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::CreditCard => "credit_card",
            Self::Ssn => "ssn",
            Self::Phone => "phone",
            Self::IpAddress => "ip_address",
            Self::Jwt => "jwt",
            Self::AwsKey => "aws_key",
            Self::ApiKey => "api_key",
        }
    }
}

/// Custom redaction pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRedactionPattern {
    /// Pattern name (for reporting)
    pub name: String,
    /// Regex pattern
    pub pattern: String,
    /// Custom replacement (uses global replacement if not set)
    pub replacement: Option<String>,
}

/// Body logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BodyConfig {
    /// Log request body
    pub log_request_body: bool,
    /// Log response body
    pub log_response_body: bool,
    /// Maximum body size to log (bytes)
    pub max_body_size: usize,
    /// Content types to log bodies for
    pub content_types: Vec<String>,
    /// Truncation indicator
    pub truncation_indicator: String,
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            log_request_body: false,
            log_response_body: false,
            max_body_size: 4096,
            content_types: vec![
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ],
            truncation_indicator: "...[truncated]".to_string(),
        }
    }
}

/// Pre-built compliance templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceTemplate {
    /// SOC 2 compliance
    Soc2,
    /// HIPAA compliance
    Hipaa,
    /// PCI DSS compliance
    Pci,
    /// GDPR compliance
    Gdpr,
}

impl ComplianceTemplate {
    /// Apply this compliance template to a config.
    pub fn apply(&self, config: &mut AuditLoggerConfig) {
        match self {
            Self::Soc2 => self.apply_soc2(config),
            Self::Hipaa => self.apply_hipaa(config),
            Self::Pci => self.apply_pci(config),
            Self::Gdpr => self.apply_gdpr(config),
        }
    }

    fn apply_soc2(&self, config: &mut AuditLoggerConfig) {
        // SOC 2: Focus on access control and change management
        config.fields.correlation_id = true;
        config.fields.timestamp = true;
        config.fields.client_ip = true;
        config.fields.user_id = true;
        config.fields.method = true;
        config.fields.path = true;
        config.fields.status_code = true;
        config.fields.duration_ms = true;
        config.fields.agent_decisions = true;

        // Redact sensitive data
        config.redaction.enabled = true;
        config.redaction.patterns = vec![
            RedactionPattern::Email,
            RedactionPattern::CreditCard,
            RedactionPattern::Ssn,
            RedactionPattern::ApiKey,
        ];
    }

    fn apply_hipaa(&self, config: &mut AuditLoggerConfig) {
        // HIPAA: Strict PHI protection
        config.fields.correlation_id = true;
        config.fields.timestamp = true;
        config.fields.client_ip = true;
        config.fields.user_id = true;
        config.fields.method = true;
        config.fields.path = true;
        config.fields.status_code = true;

        // No body logging for PHI
        config.body.log_request_body = false;
        config.body.log_response_body = false;

        // Aggressive redaction
        config.redaction.enabled = true;
        config.redaction.patterns = vec![
            RedactionPattern::Email,
            RedactionPattern::Ssn,
            RedactionPattern::Phone,
        ];

        // Hash for correlation without exposing data
        config.redaction.hash_original = true;
    }

    fn apply_pci(&self, config: &mut AuditLoggerConfig) {
        // PCI DSS: Card data protection
        config.fields.correlation_id = true;
        config.fields.timestamp = true;
        config.fields.client_ip = true;
        config.fields.user_id = true;
        config.fields.method = true;
        config.fields.path = true;
        config.fields.status_code = true;

        // Redact card data
        config.redaction.enabled = true;
        config.redaction.patterns = vec![
            RedactionPattern::CreditCard,
            RedactionPattern::ApiKey,
        ];

        // Don't log bodies that might contain card data
        config.body.log_request_body = false;
        config.body.log_response_body = false;
    }

    fn apply_gdpr(&self, config: &mut AuditLoggerConfig) {
        // GDPR: Personal data protection
        config.fields.correlation_id = true;
        config.fields.timestamp = true;
        config.fields.method = true;
        config.fields.path = true;
        config.fields.status_code = true;

        // Minimize personal data
        config.fields.client_ip = false; // IP is personal data under GDPR
        config.fields.user_id = false;

        // Aggressive redaction
        config.redaction.enabled = true;
        config.redaction.patterns = vec![
            RedactionPattern::Email,
            RedactionPattern::Phone,
            RedactionPattern::IpAddress,
        ];

        config.redaction.hash_original = true;
    }
}

/// Filter configuration for conditional logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Filter name
    pub name: String,
    /// Match condition
    pub condition: FilterCondition,
    /// Action when matched
    pub action: FilterAction,
}

/// Filter conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FilterCondition {
    /// Match by HTTP method
    Method { values: Vec<String> },
    /// Match by path prefix
    PathPrefix { prefix: String },
    /// Match by path regex
    PathRegex { pattern: String },
    /// Match by status code range
    StatusCode { min: u16, max: u16 },
    /// Match by header presence/value
    Header { name: String, value: Option<String> },
    /// Match all (always true)
    All,
}

/// Filter actions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    /// Include in logs
    Include,
    /// Exclude from logs
    Exclude,
    /// Include with extra detail
    Verbose,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AuditLoggerConfig::default();
        assert_eq!(config.format.format_type, FormatType::Json);
        assert!(config.redaction.enabled);
        assert_eq!(config.sample_rate, 1.0);
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
format:
  format_type: cef
  device_vendor: "MyCompany"
fields:
  client_ip: true
  user_id: true
outputs:
  - type: stdout
  - type: file
    path: /var/log/audit.log
redaction:
  enabled: true
  patterns:
    - email
    - credit_card
"#;
        let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.format.format_type, FormatType::Cef);
        assert_eq!(config.format.device_vendor, "MyCompany");
        assert_eq!(config.outputs.len(), 2);
    }

    #[test]
    fn test_compliance_template_hipaa() {
        let mut config = AuditLoggerConfig::default();
        ComplianceTemplate::Hipaa.apply(&mut config);

        assert!(!config.body.log_request_body);
        assert!(!config.body.log_response_body);
        assert!(config.redaction.hash_original);
    }

    #[test]
    fn test_redaction_pattern_regex() {
        let pattern = RedactionPattern::Email;
        let regex = regex::Regex::new(pattern.regex()).unwrap();
        assert!(regex.is_match("test@example.com"));
        assert!(!regex.is_match("not an email"));
    }

    #[test]
    fn test_syslog_facility_codes() {
        assert_eq!(SyslogFacility::Auth.code(), 4);
        assert_eq!(SyslogFacility::Local0.code(), 16);
    }
}
