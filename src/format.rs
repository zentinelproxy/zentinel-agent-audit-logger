//! Log format implementations (JSON, CEF, LEEF).

use crate::config::{FormatConfig, FormatType};
use crate::event::AuditEvent;
use serde_json::Value;

/// Trait for log formatters.
pub trait Formatter: Send + Sync {
    /// Format an audit event as a string.
    fn format(&self, event: &AuditEvent) -> String;
}

/// Create a formatter based on configuration.
pub fn create_formatter(config: &FormatConfig) -> Box<dyn Formatter> {
    match config.format_type {
        FormatType::Json => Box::new(JsonFormatter::new(config)),
        FormatType::Cef => Box::new(CefFormatter::new(config)),
        FormatType::Leef => Box::new(LeefFormatter::new(config)),
    }
}

/// JSON log formatter.
pub struct JsonFormatter {
    pretty: bool,
    include_timestamp: bool,
    timestamp_format: String,
}

impl JsonFormatter {
    pub fn new(config: &FormatConfig) -> Self {
        Self {
            pretty: config.pretty,
            include_timestamp: config.include_timestamp,
            timestamp_format: config.timestamp_format.clone(),
        }
    }
}

impl Formatter for JsonFormatter {
    fn format(&self, event: &AuditEvent) -> String {
        let mut obj = serde_json::to_value(event).unwrap_or(Value::Null);

        // Format timestamp if needed
        if self.include_timestamp {
            if let Value::Object(ref mut map) = obj {
                if let Some(ts) = event.timestamp {
                    let formatted = ts.format(&self.timestamp_format).to_string();
                    map.insert("@timestamp".to_string(), Value::String(formatted));
                }
            }
        }

        if self.pretty {
            serde_json::to_string_pretty(&obj).unwrap_or_default()
        } else {
            serde_json::to_string(&obj).unwrap_or_default()
        }
    }
}

/// CEF (Common Event Format) formatter.
///
/// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
pub struct CefFormatter {
    device_vendor: String,
    device_product: String,
    device_version: String,
    include_timestamp: bool,
    timestamp_format: String,
}

impl CefFormatter {
    pub fn new(config: &FormatConfig) -> Self {
        Self {
            device_vendor: config.device_vendor.clone(),
            device_product: config.device_product.clone(),
            device_version: config.device_version.clone(),
            include_timestamp: config.include_timestamp,
            timestamp_format: config.timestamp_format.clone(),
        }
    }

    /// Escape special characters in CEF header fields.
    fn escape_header(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Escape special characters in CEF extension values.
    fn escape_extension(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Map HTTP status code to CEF severity (0-10).
    fn status_to_severity(status: Option<u16>) -> u8 {
        match status {
            Some(s) if s >= 500 => 7,  // Server error
            Some(s) if s >= 400 => 5,  // Client error
            Some(s) if s >= 300 => 3,  // Redirect
            Some(s) if s >= 200 => 1,  // Success
            _ => 0,                     // Unknown
        }
    }

    /// Generate signature ID from request.
    fn signature_id(event: &AuditEvent) -> String {
        format!(
            "{}-{}",
            event.method.as_deref().unwrap_or("UNKNOWN"),
            event.status_code.unwrap_or(0)
        )
    }
}

impl Formatter for CefFormatter {
    fn format(&self, event: &AuditEvent) -> String {
        let severity = Self::status_to_severity(event.status_code);
        let sig_id = Self::signature_id(event);
        let name = format!(
            "{} {}",
            event.method.as_deref().unwrap_or("REQUEST"),
            event.path.as_deref().unwrap_or("/")
        );

        // Build CEF header
        let header = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|",
            Self::escape_header(&self.device_vendor),
            Self::escape_header(&self.device_product),
            Self::escape_header(&self.device_version),
            Self::escape_header(&sig_id),
            Self::escape_header(&name),
            severity
        );

        // Build extensions
        let mut extensions = Vec::new();

        if self.include_timestamp {
            if let Some(ts) = event.timestamp {
                let formatted = ts.format(&self.timestamp_format).to_string();
                extensions.push(format!("rt={}", Self::escape_extension(&formatted)));
            }
        }

        if let Some(ref id) = event.correlation_id {
            extensions.push(format!("externalId={}", Self::escape_extension(id)));
        }

        if let Some(ref ip) = event.client_ip {
            extensions.push(format!("src={}", Self::escape_extension(ip)));
        }

        if let Some(ref host) = event.host {
            extensions.push(format!("dhost={}", Self::escape_extension(host)));
        }

        if let Some(ref path) = event.path {
            extensions.push(format!("request={}", Self::escape_extension(path)));
        }

        if let Some(ref method) = event.method {
            extensions.push(format!("requestMethod={}", Self::escape_extension(method)));
        }

        if let Some(status) = event.status_code {
            extensions.push(format!("outcome={}", status));
        }

        if let Some(duration) = event.duration_ms {
            extensions.push(format!("cn1={}", duration));
            extensions.push("cn1Label=duration_ms".to_string());
        }

        if let Some(ref user_id) = event.user_id {
            extensions.push(format!("suser={}", Self::escape_extension(user_id)));
        }

        if let Some(ref ua) = event.user_agent {
            extensions.push(format!("requestClientApplication={}", Self::escape_extension(ua)));
        }

        format!("{}{}", header, extensions.join(" "))
    }
}

/// LEEF (Log Event Extended Format) formatter.
///
/// Format: LEEF:Version|Vendor|Product|Version|EventID|<attributes>
pub struct LeefFormatter {
    device_vendor: String,
    device_product: String,
    device_version: String,
    include_timestamp: bool,
    timestamp_format: String,
}

impl LeefFormatter {
    pub fn new(config: &FormatConfig) -> Self {
        Self {
            device_vendor: config.device_vendor.clone(),
            device_product: config.device_product.clone(),
            device_version: config.device_version.clone(),
            include_timestamp: config.include_timestamp,
            timestamp_format: config.timestamp_format.clone(),
        }
    }

    /// Escape special characters in LEEF fields.
    fn escape(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('|', "\\|")
    }

    /// Generate event ID.
    fn event_id(event: &AuditEvent) -> String {
        format!(
            "{}:{}",
            event.method.as_deref().unwrap_or("UNKNOWN"),
            event.status_code.unwrap_or(0)
        )
    }
}

impl Formatter for LeefFormatter {
    fn format(&self, event: &AuditEvent) -> String {
        let event_id = Self::event_id(event);

        // Build LEEF header (using tab as attribute delimiter)
        let header = format!(
            "LEEF:2.0|{}|{}|{}|{}|",
            Self::escape(&self.device_vendor),
            Self::escape(&self.device_product),
            Self::escape(&self.device_version),
            Self::escape(&event_id),
        );

        // Build attributes (tab-separated key=value pairs)
        let mut attrs = Vec::new();

        if self.include_timestamp {
            if let Some(ts) = event.timestamp {
                let formatted = ts.format(&self.timestamp_format).to_string();
                attrs.push(format!("devTime={}", Self::escape(&formatted)));
            }
        }

        if let Some(ref id) = event.correlation_id {
            attrs.push(format!("devTimeFormat={}", Self::escape(&self.timestamp_format)));
            attrs.push(format!("externalId={}", Self::escape(id)));
        }

        if let Some(ref ip) = event.client_ip {
            attrs.push(format!("src={}", Self::escape(ip)));
        }

        if let Some(ref host) = event.host {
            attrs.push(format!("dstHost={}", Self::escape(host)));
        }

        if let Some(ref path) = event.path {
            attrs.push(format!("url={}", Self::escape(path)));
        }

        if let Some(ref method) = event.method {
            attrs.push(format!("proto={}", Self::escape(method)));
        }

        if let Some(status) = event.status_code {
            attrs.push(format!("responseCode={}", status));
        }

        if let Some(duration) = event.duration_ms {
            attrs.push(format!("responseTime={}", duration));
        }

        if let Some(ref user_id) = event.user_id {
            attrs.push(format!("usrName={}", Self::escape(user_id)));
        }

        if let Some(ref session_id) = event.session_id {
            attrs.push(format!("sessId={}", Self::escape(session_id)));
        }

        if let Some(ref ua) = event.user_agent {
            attrs.push(format!("userAgent={}", Self::escape(ua)));
        }

        if let Some(req_size) = event.request_body_size {
            attrs.push(format!("srcBytes={}", req_size));
        }

        if let Some(resp_size) = event.response_body_size {
            attrs.push(format!("dstBytes={}", resp_size));
        }

        // Join with tabs
        format!("{}{}", header, attrs.join("\t"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_event() -> AuditEvent {
        AuditEvent {
            timestamp: Some(Utc::now()),
            correlation_id: Some("req-123".to_string()),
            client_ip: Some("192.168.1.1".to_string()),
            method: Some("GET".to_string()),
            path: Some("/api/users".to_string()),
            query_string: Some("page=1".to_string()),
            host: Some("api.example.com".to_string()),
            protocol: Some("HTTP/1.1".to_string()),
            status_code: Some(200),
            duration_ms: Some(42),
            user_id: Some("user-456".to_string()),
            session_id: Some("sess-789".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            request_headers: None,
            response_headers: None,
            request_body: None,
            response_body: None,
            request_body_size: Some(0),
            response_body_size: Some(1024),
            route_id: Some("route-1".to_string()),
            upstream: Some("backend-1".to_string()),
            upstream_duration_ms: Some(38),
            agent_decisions: None,
            custom_fields: None,
        }
    }

    #[test]
    fn test_json_formatter() {
        let config = FormatConfig::default();
        let formatter = JsonFormatter::new(&config);
        let event = test_event();

        let output = formatter.format(&event);
        assert!(output.contains("\"correlation_id\":\"req-123\""));
        assert!(output.contains("\"status_code\":200"));
    }

    #[test]
    fn test_json_formatter_pretty() {
        let config = FormatConfig {
            pretty: true,
            ..Default::default()
        };
        let formatter = JsonFormatter::new(&config);
        let event = test_event();

        let output = formatter.format(&event);
        assert!(output.contains('\n')); // Pretty format has newlines
    }

    #[test]
    fn test_cef_formatter() {
        let config = FormatConfig::default();
        let formatter = CefFormatter::new(&config);
        let event = test_event();

        let output = formatter.format(&event);
        assert!(output.starts_with("CEF:0|"));
        assert!(output.contains("Zentinel"));
        assert!(output.contains("src=192.168.1.1"));
        assert!(output.contains("request=/api/users"));
    }

    #[test]
    fn test_cef_escape_header() {
        assert_eq!(CefFormatter::escape_header("test|value"), "test\\|value");
        assert_eq!(CefFormatter::escape_header("test\\value"), "test\\\\value");
    }

    #[test]
    fn test_leef_formatter() {
        let config = FormatConfig::default();
        let formatter = LeefFormatter::new(&config);
        let event = test_event();

        let output = formatter.format(&event);
        assert!(output.starts_with("LEEF:2.0|"));
        assert!(output.contains("src=192.168.1.1"));
        assert!(output.contains("url=/api/users"));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(CefFormatter::status_to_severity(Some(200)), 1);
        assert_eq!(CefFormatter::status_to_severity(Some(404)), 5);
        assert_eq!(CefFormatter::status_to_severity(Some(500)), 7);
        assert_eq!(CefFormatter::status_to_severity(None), 0);
    }
}
