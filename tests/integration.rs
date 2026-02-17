//! Integration tests for the Zentinel Audit Logger Agent.
//!
//! These tests verify the complete functionality of the audit logger,
//! including configuration parsing, event building, formatting,
//! redaction, and output handling.

use zentinel_agent_audit_logger::{
    AuditEvent, AuditEventBuilder, AuditLoggerAgent, AuditLoggerConfig, Redactor,
    create_formatter,
};
use zentinel_agent_audit_logger::config::{
    ComplianceTemplate, CustomRedactionPattern, FilterAction,
    FilterCondition, FormatConfig, FormatType, HeaderFieldConfig, OutputConfig,
    RedactionConfig, RedactionPattern,
};
use zentinel_agent_audit_logger::event::AgentDecision;
use std::collections::HashMap;

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_default_config_is_valid() {
    let config = AuditLoggerConfig::default();

    assert_eq!(config.format.format_type, FormatType::Json);
    assert!(config.redaction.enabled);
    assert_eq!(config.sample_rate, 1.0);
    assert_eq!(config.outputs.len(), 1);
    assert!(matches!(config.outputs[0], OutputConfig::Stdout));
}

#[test]
fn test_full_config_from_yaml() {
    // Note: HeaderFieldConfig with Include/Exclude variants requires special YAML syntax
    // Test configuration without those variants to verify other settings
    let yaml = r#"
format:
  format_type: json
  pretty: true
  include_timestamp: true
  device_vendor: "TestCompany"
  device_product: "AuditLogger"

fields:
  correlation_id: true
  timestamp: true
  client_ip: true
  method: true
  path: true
  query_string: true
  status_code: true
  duration_ms: true
  user_id: true
  agent_decisions: true
  response_headers: none

outputs:
  - type: stdout
  - type: file
    path: /tmp/audit.log
    max_size: 10485760
    max_files: 5

redaction:
  enabled: true
  patterns:
    - email
    - credit_card
    - ssn
    - phone
  custom_patterns:
    - name: "internal_id"
      pattern: "INT-\\d{8}"
      replacement: "[INTERNAL-ID]"
  replacement: "[REDACTED]"
  hash_original: false
  redact_headers:
    - authorization
    - cookie
    - x-api-key
  redact_fields:
    - password
    - secret

body:
  log_request_body: true
  log_response_body: false
  max_body_size: 4096
  content_types:
    - application/json
    - text/plain

sample_rate: 1.0

filters:
  - name: "exclude-health"
    condition:
      type: path_prefix
      prefix: "/health"
    action: exclude
  - name: "exclude-metrics"
    condition:
      type: path_prefix
      prefix: "/metrics"
    action: exclude
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.format.format_type, FormatType::Json);
    assert!(config.format.pretty);
    assert_eq!(config.format.device_vendor, "TestCompany");
    assert_eq!(config.outputs.len(), 2);
    assert!(config.redaction.enabled);
    assert_eq!(config.redaction.patterns.len(), 4);
    assert_eq!(config.redaction.custom_patterns.len(), 1);
    assert!(config.body.log_request_body);
    assert!(!config.body.log_response_body);
    assert_eq!(config.filters.len(), 2);
}

#[test]
fn test_cef_format_config() {
    let yaml = r#"
format:
  format_type: cef
  device_vendor: "Acme Corp"
  device_product: "SecurityGateway"
  device_version: "2.0"
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.format.format_type, FormatType::Cef);
    assert_eq!(config.format.device_vendor, "Acme Corp");
    assert_eq!(config.format.device_product, "SecurityGateway");
}

#[test]
fn test_leef_format_config() {
    let yaml = r#"
format:
  format_type: leef
  device_vendor: "Acme Corp"
  device_product: "AuditSystem"
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.format.format_type, FormatType::Leef);
}

// =============================================================================
// Compliance Template Tests
// =============================================================================

#[test]
fn test_soc2_compliance_template() {
    let mut config = AuditLoggerConfig::default();
    ComplianceTemplate::Soc2.apply(&mut config);

    assert!(config.fields.correlation_id);
    assert!(config.fields.timestamp);
    assert!(config.fields.client_ip);
    assert!(config.fields.user_id);
    assert!(config.fields.agent_decisions);
    assert!(config.redaction.enabled);
    assert!(config.redaction.patterns.contains(&RedactionPattern::Email));
    assert!(config.redaction.patterns.contains(&RedactionPattern::CreditCard));
}

#[test]
fn test_hipaa_compliance_template() {
    let mut config = AuditLoggerConfig::default();
    ComplianceTemplate::Hipaa.apply(&mut config);

    // HIPAA should disable body logging to protect PHI
    assert!(!config.body.log_request_body);
    assert!(!config.body.log_response_body);
    // Hash for correlation without exposing data
    assert!(config.redaction.hash_original);
    // Should redact SSN and phone (common PHI)
    assert!(config.redaction.patterns.contains(&RedactionPattern::Ssn));
    assert!(config.redaction.patterns.contains(&RedactionPattern::Phone));
}

#[test]
fn test_pci_compliance_template() {
    let mut config = AuditLoggerConfig::default();
    ComplianceTemplate::Pci.apply(&mut config);

    // PCI should redact credit card data
    assert!(config.redaction.patterns.contains(&RedactionPattern::CreditCard));
    // Don't log bodies that might contain card data
    assert!(!config.body.log_request_body);
    assert!(!config.body.log_response_body);
}

#[test]
fn test_gdpr_compliance_template() {
    let mut config = AuditLoggerConfig::default();
    ComplianceTemplate::Gdpr.apply(&mut config);

    // GDPR minimizes personal data collection
    assert!(!config.fields.client_ip); // IP is personal data under GDPR
    assert!(!config.fields.user_id);
    // Should redact IP addresses
    assert!(config.redaction.patterns.contains(&RedactionPattern::IpAddress));
    // Hash for pseudonymization
    assert!(config.redaction.hash_original);
}

// =============================================================================
// Event Builder Tests
// =============================================================================

#[test]
fn test_event_builder_full_request() {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("User-Agent".to_string(), "test-client/1.0".to_string());

    let event = AuditEventBuilder::new()
        .correlation_id("req-12345")
        .client_ip("192.168.1.100")
        .method("POST")
        .path("/api/v1/users")
        .query_string("page=1&limit=10")
        .host("api.example.com")
        .protocol("HTTP/1.1")
        .status_code(201)
        .duration_ms(42)
        .user_id("user-789")
        .session_id("sess-abc")
        .user_agent("test-client/1.0")
        .request_headers(headers.clone())
        .request_body(r#"{"name":"John"}"#)
        .request_body_size(15)
        .response_body_size(256)
        .route_id("route-users")
        .upstream("backend-1")
        .upstream_duration_ms(38)
        .build();

    assert_eq!(event.correlation_id, Some("req-12345".to_string()));
    assert_eq!(event.client_ip, Some("192.168.1.100".to_string()));
    assert_eq!(event.method, Some("POST".to_string()));
    assert_eq!(event.path, Some("/api/v1/users".to_string()));
    assert_eq!(event.query_string, Some("page=1&limit=10".to_string()));
    assert_eq!(event.status_code, Some(201));
    assert_eq!(event.duration_ms, Some(42));
    assert_eq!(event.user_id, Some("user-789".to_string()));
}

#[test]
fn test_event_builder_with_agent_decisions() {
    let event = AuditEventBuilder::new()
        .method("POST")
        .path("/api/login")
        .agent_decision(AgentDecision {
            agent: "waf".to_string(),
            decision: "allow".to_string(),
            reason: None,
            rule_ids: None,
            duration_us: Some(150),
        })
        .agent_decision(AgentDecision {
            agent: "rate-limiter".to_string(),
            decision: "allow".to_string(),
            reason: Some("Within limit".to_string()),
            rule_ids: Some(vec!["rl-001".to_string()]),
            duration_us: Some(50),
        })
        .build();

    let decisions = event.agent_decisions.unwrap();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].agent, "waf");
    assert_eq!(decisions[1].agent, "rate-limiter");
}

#[test]
fn test_event_builder_custom_fields() {
    let event = AuditEventBuilder::new()
        .method("GET")
        .path("/api/data")
        .custom_field("tenant_id", "tenant-123")
        .custom_field("environment", "production")
        .custom_field("region", "us-west-2")
        .build();

    let fields = event.custom_fields.unwrap();
    assert_eq!(fields.get("tenant_id"), Some(&"tenant-123".to_string()));
    assert_eq!(fields.get("environment"), Some(&"production".to_string()));
    assert_eq!(fields.get("region"), Some(&"us-west-2".to_string()));
}

#[test]
fn test_event_serialization_skips_none() {
    let event = AuditEventBuilder::new()
        .method("GET")
        .path("/api/health")
        .status_code(200)
        .build();

    let json = serde_json::to_string(&event).unwrap();

    // Fields that are set should be present
    assert!(json.contains("\"method\":\"GET\""));
    assert!(json.contains("\"status_code\":200"));

    // None fields should be skipped (not serialized as null)
    assert!(!json.contains("\"user_id\""));
    assert!(!json.contains("\"session_id\""));
    assert!(!json.contains("\"request_body\""));
}

// =============================================================================
// Formatter Tests
// =============================================================================

fn create_test_event() -> AuditEvent {
    AuditEventBuilder::new()
        .correlation_id("test-req-001")
        .client_ip("10.0.0.1")
        .method("GET")
        .path("/api/users/123")
        .host("api.example.com")
        .status_code(200)
        .duration_ms(25)
        .user_id("user-456")
        .user_agent("Mozilla/5.0")
        .request_body_size(0)
        .response_body_size(512)
        .build()
}

#[test]
fn test_json_formatter_output() {
    let config = FormatConfig::default();
    let formatter = create_formatter(&config);
    let event = create_test_event();

    let output = formatter.format(&event);

    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["correlation_id"], "test-req-001");
    assert_eq!(parsed["method"], "GET");
    assert_eq!(parsed["path"], "/api/users/123");
    assert_eq!(parsed["status_code"], 200);
}

#[test]
fn test_json_formatter_pretty_output() {
    let config = FormatConfig {
        pretty: true,
        ..Default::default()
    };
    let formatter = create_formatter(&config);
    let event = create_test_event();

    let output = formatter.format(&event);

    // Pretty format should have newlines and indentation
    assert!(output.contains('\n'));
    assert!(output.contains("  ")); // Indentation
}

#[test]
fn test_cef_formatter_output() {
    let config = FormatConfig {
        format_type: FormatType::Cef,
        device_vendor: "TestVendor".to_string(),
        device_product: "TestProduct".to_string(),
        ..Default::default()
    };
    let formatter = create_formatter(&config);
    let event = create_test_event();

    let output = formatter.format(&event);

    // CEF format validation
    assert!(output.starts_with("CEF:0|"));
    assert!(output.contains("TestVendor"));
    assert!(output.contains("TestProduct"));
    assert!(output.contains("src=10.0.0.1"));
    assert!(output.contains("request=/api/users/123"));
    assert!(output.contains("requestMethod=GET"));
    assert!(output.contains("outcome=200"));
}

#[test]
fn test_leef_formatter_output() {
    let config = FormatConfig {
        format_type: FormatType::Leef,
        device_vendor: "TestVendor".to_string(),
        ..Default::default()
    };
    let formatter = create_formatter(&config);
    let event = create_test_event();

    let output = formatter.format(&event);

    // LEEF format validation
    assert!(output.starts_with("LEEF:2.0|"));
    assert!(output.contains("TestVendor"));
    assert!(output.contains("src=10.0.0.1"));
    assert!(output.contains("url=/api/users/123"));
    assert!(output.contains("responseCode=200"));
}

#[test]
fn test_cef_severity_mapping() {
    let config = FormatConfig::default();
    let mut config_cef = config.clone();
    config_cef.format_type = FormatType::Cef;
    let formatter = create_formatter(&config_cef);

    // Test different status codes map to correct severity
    let test_cases = [
        (200, "1"), // Success = severity 1
        (301, "3"), // Redirect = severity 3
        (404, "5"), // Client error = severity 5
        (500, "7"), // Server error = severity 7
    ];

    for (status, expected_severity) in test_cases {
        let event = AuditEventBuilder::new()
            .method("GET")
            .path("/test")
            .status_code(status)
            .build();

        let output = formatter.format(&event);
        // CEF format: ...vendor|product|version|sigId|name|severity|...
        // The severity is the 7th field
        assert!(output.contains(&format!("|{}|", expected_severity)),
            "Status {} should map to severity {}", status, expected_severity);
    }
}

// =============================================================================
// Redaction Tests
// =============================================================================

fn create_test_redactor() -> Redactor {
    let config = RedactionConfig {
        enabled: true,
        patterns: vec![
            RedactionPattern::Email,
            RedactionPattern::CreditCard,
            RedactionPattern::Ssn,
            RedactionPattern::Phone,
            RedactionPattern::Jwt,
        ],
        custom_patterns: vec![],
        replacement: "[REDACTED]".to_string(),
        hash_original: false,
        redact_headers: vec![
            "authorization".to_string(),
            "cookie".to_string(),
            "x-api-key".to_string(),
        ],
        redact_fields: vec![
            "password".to_string(),
            "secret".to_string(),
            "user.ssn".to_string(),
        ],
    };
    Redactor::new(&config)
}

#[test]
fn test_redact_email_addresses() {
    let redactor = create_test_redactor();

    let test_cases = [
        ("Contact: john@example.com", "Contact: [REDACTED]"),
        ("Email: test.user+tag@company.co.uk", "Email: [REDACTED]"),
        ("Multiple: a@b.com and c@d.org", "Multiple: [REDACTED] and [REDACTED]"),
    ];

    for (input, expected) in test_cases {
        let result = redactor.redact_string(input);
        assert_eq!(result, expected, "Failed for input: {}", input);
    }
}

#[test]
fn test_redact_credit_cards() {
    let redactor = create_test_redactor();

    let inputs = [
        "Card: 4111-1111-1111-1111",
        "Card: 4111 1111 1111 1111",
        "Card: 5500000000000004",
    ];

    for input in inputs {
        let result = redactor.redact_string(input);
        assert!(result.contains("[REDACTED]"), "Card not redacted in: {}", input);
        assert!(!result.contains("4111"), "Card digits remain in: {}", input);
    }
}

#[test]
fn test_redact_ssn() {
    let redactor = create_test_redactor();

    let input = "SSN: 123-45-6789";
    let result = redactor.redact_string(input);

    assert_eq!(result, "SSN: [REDACTED]");
}

#[test]
fn test_redact_phone_numbers() {
    let redactor = create_test_redactor();

    let inputs = [
        "Phone: (555) 123-4567",
        "Phone: 555-123-4567",
        "Phone: +1 555 123 4567",
    ];

    for input in inputs {
        let result = redactor.redact_string(input);
        assert!(result.contains("[REDACTED]"), "Phone not redacted in: {}", input);
    }
}

#[test]
fn test_redact_jwt_tokens() {
    let redactor = create_test_redactor();

    // A sample JWT-like token structure
    let input = "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature";
    let result = redactor.redact_string(input);

    assert!(result.contains("[REDACTED]"));
    assert!(!result.contains("eyJhbGciOiJIUzI1NiJ9"));
}

#[test]
fn test_redact_headers() {
    let redactor = create_test_redactor();

    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer secret-token-12345".to_string());
    headers.insert("Cookie".to_string(), "session=abc123".to_string());
    headers.insert("X-API-Key".to_string(), "api-key-secret".to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("User-Agent".to_string(), "test-client".to_string());

    let redacted = redactor.redact_headers(&headers);

    // Sensitive headers should be fully redacted
    assert_eq!(redacted.get("Authorization"), Some(&"[REDACTED]".to_string()));
    assert_eq!(redacted.get("Cookie"), Some(&"[REDACTED]".to_string()));
    assert_eq!(redacted.get("X-API-Key"), Some(&"[REDACTED]".to_string()));

    // Non-sensitive headers should pass through
    assert_eq!(redacted.get("Content-Type"), Some(&"application/json".to_string()));
    assert_eq!(redacted.get("User-Agent"), Some(&"test-client".to_string()));
}

#[test]
fn test_redact_json_simple_field() {
    let redactor = create_test_redactor();

    let json = r#"{"username": "john", "password": "secret123", "role": "admin"}"#;
    let redacted = redactor.redact_json(json);
    let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();

    assert_eq!(parsed["username"], "john");
    assert_eq!(parsed["password"], "[REDACTED]");
    assert_eq!(parsed["role"], "admin");
}

#[test]
fn test_redact_json_nested_field() {
    let redactor = create_test_redactor();

    let json = r#"{"user": {"name": "John", "ssn": "123-45-6789"}, "action": "login"}"#;
    let redacted = redactor.redact_json(json);
    let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();

    assert_eq!(parsed["user"]["name"], "John");
    assert_eq!(parsed["user"]["ssn"], "[REDACTED]");
    assert_eq!(parsed["action"], "login");
}

#[test]
fn test_redact_json_with_email_in_content() {
    let redactor = create_test_redactor();

    let json = r#"{"message": "Contact support@example.com for help"}"#;
    let redacted = redactor.redact_json(json);

    // Email should be pattern-redacted even in nested content
    assert!(redacted.contains("[REDACTED]"));
    assert!(!redacted.contains("support@example.com"));
}

#[test]
fn test_redact_with_hash_original() {
    let config = RedactionConfig {
        enabled: true,
        patterns: vec![RedactionPattern::Email],
        custom_patterns: vec![],
        replacement: "[REDACTED]".to_string(),
        hash_original: true, // Enable hashing
        redact_headers: vec![],
        redact_fields: vec![],
    };
    let redactor = Redactor::new(&config);

    let input = "Email: test@example.com";
    let result = redactor.redact_string(input);

    // Should contain hash prefix for correlation
    assert!(result.contains("[REDACTED:email:"));
    assert!(!result.contains("test@example.com"));
}

#[test]
fn test_custom_redaction_pattern() {
    let config = RedactionConfig {
        enabled: true,
        patterns: vec![],
        custom_patterns: vec![
            CustomRedactionPattern {
                name: "employee_id".to_string(),
                pattern: r"EMP-\d{6}".to_string(),
                replacement: Some("[EMPLOYEE-ID]".to_string()),
            },
            CustomRedactionPattern {
                name: "project_code".to_string(),
                pattern: r"PRJ-[A-Z]{3}-\d{4}".to_string(),
                replacement: None, // Uses default replacement
            },
        ],
        replacement: "[REDACTED]".to_string(),
        hash_original: false,
        redact_headers: vec![],
        redact_fields: vec![],
    };
    let redactor = Redactor::new(&config);

    let input = "Employee EMP-123456 on project PRJ-ABC-2024";
    let result = redactor.redact_string(input);

    assert_eq!(result, "Employee [EMPLOYEE-ID] on project [REDACTED]");
}

#[test]
fn test_noop_redactor() {
    let redactor = Redactor::noop();

    let input = "Email: test@example.com, SSN: 123-45-6789";
    let result = redactor.redact_string(input);

    // No-op redactor should pass through unchanged
    assert_eq!(result, input);
}

// =============================================================================
// Filter Tests
// =============================================================================

#[test]
fn test_filter_config_path_prefix() {
    let yaml = r#"
filters:
  - name: "exclude-health"
    condition:
      type: path_prefix
      prefix: "/health"
    action: exclude
  - name: "exclude-metrics"
    condition:
      type: path_prefix
      prefix: "/metrics"
    action: exclude
  - name: "verbose-errors"
    condition:
      type: status_code
      min: 500
      max: 599
    action: verbose
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.filters.len(), 3);
    assert_eq!(config.filters[0].name, "exclude-health");
    assert!(matches!(config.filters[0].action, FilterAction::Exclude));
    assert!(matches!(config.filters[2].action, FilterAction::Verbose));
}

#[test]
fn test_filter_config_method() {
    let yaml = r#"
filters:
  - name: "only-mutations"
    condition:
      type: method
      values: ["POST", "PUT", "DELETE", "PATCH"]
    action: include
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(config.filters.len(), 1);
    if let FilterCondition::Method { values } = &config.filters[0].condition {
        assert_eq!(values.len(), 4);
        assert!(values.contains(&"POST".to_string()));
    } else {
        panic!("Expected Method condition");
    }
}

#[test]
fn test_filter_config_header() {
    let yaml = r#"
filters:
  - name: "debug-requests"
    condition:
      type: header
      name: "X-Debug"
      value: "true"
    action: verbose
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    if let FilterCondition::Header { name, value } = &config.filters[0].condition {
        assert_eq!(name, "X-Debug");
        assert_eq!(value, &Some("true".to_string()));
    } else {
        panic!("Expected Header condition");
    }
}

// =============================================================================
// Header Field Config Tests
// =============================================================================

#[test]
fn test_header_field_config_include() {
    // Test Include variant using JSON - enum uses lowercase due to rename_all
    let json = r#"{
        "fields": {
            "request_headers": {
                "include": ["content-type", "user-agent", "x-request-id"]
            }
        }
    }"#;

    let config: AuditLoggerConfig = serde_json::from_str(json).unwrap();

    if let HeaderFieldConfig::Include(headers) = &config.fields.request_headers {
        assert_eq!(headers.len(), 3);
        assert!(headers.contains(&"content-type".to_string()));
    } else {
        panic!("Expected Include config");
    }
}

#[test]
fn test_header_field_config_exclude() {
    // Test Exclude variant using JSON - enum uses lowercase due to rename_all
    let json = r#"{
        "fields": {
            "request_headers": {
                "exclude": ["authorization", "cookie"]
            }
        }
    }"#;

    let config: AuditLoggerConfig = serde_json::from_str(json).unwrap();

    if let HeaderFieldConfig::Exclude(headers) = &config.fields.request_headers {
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&"authorization".to_string()));
    } else {
        panic!("Expected Exclude config");
    }
}

#[test]
fn test_header_field_config_all() {
    let yaml = r#"
fields:
  request_headers: all
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(matches!(config.fields.request_headers, HeaderFieldConfig::All));
}

#[test]
fn test_header_field_config_none() {
    let yaml = r#"
fields:
  response_headers: none
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(matches!(config.fields.response_headers, HeaderFieldConfig::None));
}

// =============================================================================
// Body Config Tests
// =============================================================================

#[test]
fn test_body_config() {
    let yaml = r#"
body:
  log_request_body: true
  log_response_body: true
  max_body_size: 8192
  content_types:
    - application/json
    - application/xml
    - text/plain
  truncation_indicator: "...[TRUNCATED]"
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    assert!(config.body.log_request_body);
    assert!(config.body.log_response_body);
    assert_eq!(config.body.max_body_size, 8192);
    assert_eq!(config.body.content_types.len(), 3);
    assert_eq!(config.body.truncation_indicator, "...[TRUNCATED]");
}

// =============================================================================
// Output Config Tests
// =============================================================================

#[test]
fn test_output_config_stdout() {
    let yaml = r#"
outputs:
  - type: stdout
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(matches!(config.outputs[0], OutputConfig::Stdout));
}

#[test]
fn test_output_config_file() {
    let yaml = r#"
outputs:
  - type: file
    path: /var/log/zentinel/audit.log
    max_size: 104857600
    max_files: 10
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    if let OutputConfig::File { path, max_size, max_files } = &config.outputs[0] {
        assert_eq!(path.to_str().unwrap(), "/var/log/zentinel/audit.log");
        assert_eq!(*max_size, Some(104857600));
        assert_eq!(*max_files, Some(10));
    } else {
        panic!("Expected File output config");
    }
}

#[test]
fn test_output_config_syslog() {
    let yaml = r#"
outputs:
  - type: syslog
    address: "syslog.example.com:514"
    protocol: udp
    facility: local0
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    if let OutputConfig::Syslog { address, protocol, facility } = &config.outputs[0] {
        assert_eq!(address, "syslog.example.com:514");
        assert!(matches!(protocol, zentinel_agent_audit_logger::config::SyslogProtocol::Udp));
        assert!(matches!(facility, zentinel_agent_audit_logger::config::SyslogFacility::Local0));
    } else {
        panic!("Expected Syslog output config");
    }
}

// =============================================================================
// Agent Integration Tests
// =============================================================================

#[tokio::test]
async fn test_agent_creation_with_default_config() {
    let config = AuditLoggerConfig::default();
    // Verify config defaults before passing to agent
    assert!(config.redaction.enabled);

    // Agent should be created successfully
    let _agent = AuditLoggerAgent::new(config).await;
}

#[tokio::test]
async fn test_agent_from_yaml() {
    let yaml = r#"
format:
  format_type: json
  pretty: false
redaction:
  enabled: true
  patterns:
    - email
outputs:
  - type: stdout
"#;

    let result = AuditLoggerAgent::from_yaml(yaml).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_agent_request_duration_tracking() {
    let config = AuditLoggerConfig::default();
    let agent = AuditLoggerAgent::new(config).await;

    // Record start time
    agent.record_request_start("test-correlation-id").await;

    // Small delay
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Get duration
    let duration = agent.get_request_duration("test-correlation-id").await;

    assert!(duration.is_some());
    assert!(duration.unwrap() >= 10);
}

#[tokio::test]
async fn test_agent_compliance_template_applied() {
    let mut config = AuditLoggerConfig {
        compliance_template: Some(ComplianceTemplate::Hipaa),
        ..Default::default()
    };

    // Apply the template manually to verify its effects
    ComplianceTemplate::Hipaa.apply(&mut config);

    // HIPAA template should modify config
    assert!(!config.body.log_request_body);
    assert!(!config.body.log_response_body);
    assert!(config.redaction.hash_original);

    // Agent should be created successfully with the template
    let _agent = AuditLoggerAgent::new(config).await;
}

// =============================================================================
// Sampling Tests
// =============================================================================

#[test]
fn test_sample_rate_config() {
    let yaml = r#"
sample_rate: 0.1
"#;

    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
    assert!((config.sample_rate - 0.1).abs() < f64::EPSILON);
}

#[test]
fn test_sample_rate_bounds() {
    // Test that sample_rate accepts valid values
    let configs = [
        ("sample_rate: 0.0", 0.0),
        ("sample_rate: 0.5", 0.5),
        ("sample_rate: 1.0", 1.0),
    ];

    for (yaml, expected) in configs {
        let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!((config.sample_rate - expected).abs() < f64::EPSILON);
    }
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

#[test]
fn test_empty_config_uses_defaults() {
    let yaml = "";
    let config: AuditLoggerConfig = serde_yaml::from_str(yaml).unwrap();

    // Should use all defaults
    assert_eq!(config.format.format_type, FormatType::Json);
    assert!(config.redaction.enabled);
    assert_eq!(config.sample_rate, 1.0);
}

#[test]
fn test_redaction_with_empty_string() {
    let redactor = create_test_redactor();
    let result = redactor.redact_string("");
    assert_eq!(result, "");
}

#[test]
fn test_redaction_no_matches() {
    let redactor = create_test_redactor();
    let input = "This is a normal string with no PII";
    let result = redactor.redact_string(input);
    assert_eq!(result, input);
}

#[test]
fn test_event_with_minimal_data() {
    let event = AuditEventBuilder::new().build();

    // Should have timestamp by default
    assert!(event.timestamp.is_some());

    // All other fields should be None
    assert!(event.correlation_id.is_none());
    assert!(event.method.is_none());
    assert!(event.path.is_none());
}

#[test]
fn test_json_formatter_with_empty_event() {
    let config = FormatConfig::default();
    let formatter = create_formatter(&config);
    let event = AuditEventBuilder::new().build();

    let output = formatter.format(&event);

    // Should still produce valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&output);
    assert!(parsed.is_ok());
}

#[test]
fn test_cef_formatter_escapes_special_chars() {
    let config = FormatConfig {
        format_type: FormatType::Cef,
        ..FormatConfig::default()
    };
    let formatter = create_formatter(&config);

    let event = AuditEventBuilder::new()
        .method("GET")
        .path("/api/test|special\\chars")
        .client_ip("10.0.0.1")
        .build();

    let output = formatter.format(&event);

    // Special characters should be escaped
    assert!(output.contains("\\|") || output.contains("\\\\"));
}

// =============================================================================
// Redaction Pattern Tests
// =============================================================================

#[test]
fn test_redaction_pattern_regex_validity() {
    // Ensure all built-in patterns compile to valid regex
    let patterns = [
        RedactionPattern::Email,
        RedactionPattern::CreditCard,
        RedactionPattern::Ssn,
        RedactionPattern::Phone,
        RedactionPattern::IpAddress,
        RedactionPattern::Jwt,
        RedactionPattern::AwsKey,
        RedactionPattern::ApiKey,
    ];

    for pattern in patterns {
        let regex = regex::Regex::new(pattern.regex());
        assert!(regex.is_ok(), "Pattern {:?} has invalid regex", pattern);
    }
}

#[test]
fn test_redaction_pattern_names() {
    assert_eq!(RedactionPattern::Email.name(), "email");
    assert_eq!(RedactionPattern::CreditCard.name(), "credit_card");
    assert_eq!(RedactionPattern::Ssn.name(), "ssn");
    assert_eq!(RedactionPattern::Phone.name(), "phone");
    assert_eq!(RedactionPattern::IpAddress.name(), "ip_address");
    assert_eq!(RedactionPattern::Jwt.name(), "jwt");
    assert_eq!(RedactionPattern::AwsKey.name(), "aws_key");
    assert_eq!(RedactionPattern::ApiKey.name(), "api_key");
}
