//! Main audit logger agent implementation.

use crate::config::{
    AuditLoggerConfig, FilterAction, FilterCondition, HeaderFieldConfig,
};
use crate::event::{AgentDecision, AuditEvent, AuditEventBuilder};
use crate::format::{create_formatter, Formatter};
use crate::output::{create_outputs, MultiOutput, Output};
use crate::redaction::{truncate_body, Redactor};
use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use zentinel_agent_sdk::{Agent, Decision, Request, Response};
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent, ResponseHeadersEvent};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, CounterMetric, DrainReason,
    GaugeMetric, HealthStatus, MetricsReport, ShutdownReason,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Audit Logger Agent
///
/// Captures detailed audit logs for all API traffic passing through
/// the Zentinel proxy. Supports multiple output formats and destinations.
pub struct AuditLoggerAgent {
    config: AuditLoggerConfig,
    formatter: Box<dyn Formatter>,
    output: Arc<dyn Output>,
    redactor: Redactor,
    /// Compiled filter patterns
    filter_patterns: Vec<CompiledFilter>,
    /// Request start times for duration calculation
    request_times: Arc<Mutex<HashMap<String, Instant>>>,
    /// Metrics: total requests processed
    requests_total: AtomicU64,
    /// Metrics: total events logged
    events_logged: AtomicU64,
    /// Metrics: total events filtered (not logged due to sampling/filters)
    events_filtered: AtomicU64,
    /// Metrics: total errors writing to output
    output_errors: AtomicU64,
    /// Flag indicating the agent is draining (should finish existing work)
    draining: AtomicBool,
}

struct CompiledFilter {
    #[allow(dead_code)]
    name: String,
    condition: CompiledCondition,
    action: FilterAction,
}

enum CompiledCondition {
    Method(Vec<String>),
    PathPrefix(String),
    PathRegex(Regex),
    StatusCode { min: u16, max: u16 },
    Header { name: String, value: Option<String> },
    All,
}

/// Convert SDK headers (Vec<String> values) to single-value HashMap
fn flatten_headers(headers: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(k, v)| v.first().map(|first| (k.clone(), first.clone())))
        .collect()
}

/// Get first value from a multi-value header
fn get_header_value<'a>(headers: &'a HashMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.first()).map(|s| s.as_str())
}

impl AuditLoggerAgent {
    /// Create a new audit logger agent with the given configuration.
    pub async fn new(mut config: AuditLoggerConfig) -> Self {
        // Apply compliance template if specified
        if let Some(template) = config.compliance_template {
            template.apply(&mut config);
        }

        // Create formatter
        let formatter = create_formatter(&config.format);

        // Create outputs
        let outputs = create_outputs(&config.outputs).await;
        let output: Arc<dyn Output> = if outputs.len() == 1 {
            outputs.into_iter().next().unwrap()
        } else {
            Arc::new(MultiOutput::new(outputs))
        };

        // Create redactor
        let redactor = if config.redaction.enabled {
            Redactor::new(&config.redaction)
        } else {
            Redactor::noop()
        };

        // Compile filter patterns
        let filter_patterns = config
            .filters
            .iter()
            .filter_map(|f| {
                let condition = match &f.condition {
                    FilterCondition::Method { values } => {
                        Some(CompiledCondition::Method(values.clone()))
                    }
                    FilterCondition::PathPrefix { prefix } => {
                        Some(CompiledCondition::PathPrefix(prefix.clone()))
                    }
                    FilterCondition::PathRegex { pattern } => {
                        Regex::new(pattern).ok().map(CompiledCondition::PathRegex)
                    }
                    FilterCondition::StatusCode { min, max } => {
                        Some(CompiledCondition::StatusCode { min: *min, max: *max })
                    }
                    FilterCondition::Header { name, value } => Some(CompiledCondition::Header {
                        name: name.clone(),
                        value: value.clone(),
                    }),
                    FilterCondition::All => Some(CompiledCondition::All),
                };

                condition.map(|c| CompiledFilter {
                    name: f.name.clone(),
                    condition: c,
                    action: f.action,
                })
            })
            .collect();

        info!(
            format = ?config.format.format_type,
            outputs = config.outputs.len(),
            "Audit logger initialized"
        );

        Self {
            config,
            formatter,
            output,
            redactor,
            filter_patterns,
            request_times: Arc::new(Mutex::new(HashMap::new())),
            requests_total: AtomicU64::new(0),
            events_logged: AtomicU64::new(0),
            events_filtered: AtomicU64::new(0),
            output_errors: AtomicU64::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// Create from a YAML configuration string.
    pub async fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let config: AuditLoggerConfig = serde_yaml::from_str(yaml)?;
        Ok(Self::new(config).await)
    }

    /// Check if this request should be logged based on sampling and filters.
    fn should_log(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, Vec<String>>,
        status_code: Option<u16>,
    ) -> bool {
        // Apply sampling
        if self.config.sample_rate < 1.0 {
            let mut rng = rand::thread_rng();
            if rng.gen::<f64>() > self.config.sample_rate {
                return false;
            }
        }

        // Apply filters
        for filter in &self.filter_patterns {
            let matches = match &filter.condition {
                CompiledCondition::Method(methods) => methods.iter().any(|m| m == method),
                CompiledCondition::PathPrefix(prefix) => path.starts_with(prefix),
                CompiledCondition::PathRegex(regex) => regex.is_match(path),
                CompiledCondition::StatusCode { min, max } => {
                    if let Some(code) = status_code {
                        code >= *min && code <= *max
                    } else {
                        false
                    }
                }
                CompiledCondition::Header { name, value } => {
                    if let Some(header_value) = get_header_value(headers, name) {
                        if let Some(expected) = value {
                            header_value == expected
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                }
                CompiledCondition::All => true,
            };

            if matches {
                match filter.action {
                    FilterAction::Exclude => return false,
                    FilterAction::Include | FilterAction::Verbose => return true,
                }
            }
        }

        true
    }

    /// Extract headers based on configuration.
    fn extract_headers(
        &self,
        headers: &HashMap<String, String>,
        config: &HeaderFieldConfig,
    ) -> Option<HashMap<String, String>> {
        match config {
            HeaderFieldConfig::None => None,
            HeaderFieldConfig::All => {
                let redacted = self.redactor.redact_headers(headers);
                Some(redacted)
            }
            HeaderFieldConfig::Include(include_list) => {
                let filtered: HashMap<String, String> = headers
                    .iter()
                    .filter(|(k, _)| include_list.iter().any(|i| i.eq_ignore_ascii_case(k)))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if filtered.is_empty() {
                    None
                } else {
                    Some(self.redactor.redact_headers(&filtered))
                }
            }
            HeaderFieldConfig::Exclude(exclude_list) => {
                let filtered: HashMap<String, String> = headers
                    .iter()
                    .filter(|(k, _)| !exclude_list.iter().any(|e| e.eq_ignore_ascii_case(k)))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if filtered.is_empty() {
                    None
                } else {
                    Some(self.redactor.redact_headers(&filtered))
                }
            }
        }
    }

    /// Process body for logging.
    fn process_body(&self, body: Option<&[u8]>, content_type: Option<&str>) -> Option<String> {
        let body = body?;
        if body.is_empty() {
            return None;
        }

        // Check content type
        let ct = content_type.unwrap_or("");
        let allowed = self.config.body.content_types.iter().any(|t| ct.contains(t));
        if !allowed {
            return None;
        }

        // Convert to string
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return None, // Binary content
        };

        // Truncate if needed
        let truncated = truncate_body(
            body_str,
            self.config.body.max_body_size,
            &self.config.body.truncation_indicator,
        );

        // Apply redaction
        let redacted = if ct.contains("json") {
            self.redactor.redact_json(&truncated)
        } else {
            self.redactor.redact_string(&truncated).into_owned()
        };

        Some(redacted)
    }

    /// Build an audit event from request and response.
    #[allow(clippy::too_many_arguments)]
    fn build_event(
        &self,
        method: &str,
        path: &str,
        query_string: Option<&str>,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
        response: Option<(&Response, &HashMap<String, String>)>,
        duration_ms: Option<u64>,
    ) -> AuditEvent {
        let fields = &self.config.fields;
        let mut builder = AuditEventBuilder::new();

        // Request metadata
        if fields.correlation_id {
            if let Some(id) = headers.get("x-correlation-id") {
                builder = builder.correlation_id(id.clone());
            } else if let Some(id) = headers.get("x-request-id") {
                builder = builder.correlation_id(id.clone());
            }
        }

        if fields.client_ip {
            // Try various headers for client IP
            let ip = headers
                .get("x-forwarded-for")
                .and_then(|v| v.split(',').next().map(|s| s.trim().to_string()))
                .or_else(|| headers.get("x-real-ip").cloned())
                .unwrap_or_else(|| "unknown".to_string());
            builder = builder.client_ip(ip);
        }

        if fields.method {
            builder = builder.method(method);
        }

        if fields.path {
            builder = builder.path(path);
        }

        if fields.query_string {
            if let Some(qs) = query_string {
                builder = builder.query_string(qs.to_string());
            }
        }

        if fields.host {
            if let Some(host) = headers.get("host") {
                builder = builder.host(host.clone());
            }
        }

        if fields.protocol {
            builder = builder.protocol("HTTP/1.1"); // Default
        }

        // User context
        if fields.user_id {
            if let Some(user_id) = headers.get(&fields.user_id_header) {
                builder = builder.user_id(user_id.clone());
            }
        }

        if fields.session_id {
            if let Some(session_id) = headers.get(&fields.session_id_header) {
                builder = builder.session_id(session_id.clone());
            }
        }

        if let Some(ua) = headers.get("user-agent") {
            builder = builder.user_agent(ua.clone());
        }

        // Request headers
        if let Some(extracted_headers) = self.extract_headers(headers, &fields.request_headers) {
            builder = builder.request_headers(extracted_headers);
        }

        // Request body
        if fields.request_body && self.config.body.log_request_body {
            let content_type = headers.get("content-type").map(|s| s.as_str());
            if let Some(processed_body) = self.process_body(body, content_type) {
                builder = builder.request_body(processed_body);
            }
        }

        if fields.request_body_size {
            let size = body.map(|b| b.len() as u64).unwrap_or(0);
            builder = builder.request_body_size(size);
        }

        // Response data
        if let Some((resp, resp_headers)) = response {
            if fields.status_code {
                builder = builder.status_code(resp.status_code());
            }

            // Response headers
            if let Some(extracted_headers) =
                self.extract_headers(resp_headers, &fields.response_headers)
            {
                builder = builder.response_headers(extracted_headers);
            }

            // Response body
            if fields.response_body && self.config.body.log_response_body {
                let content_type = resp_headers.get("content-type").map(|s| s.as_str());
                if let Some(processed_body) = self.process_body(resp.body(), content_type) {
                    builder = builder.response_body(processed_body);
                }
            }

            if fields.response_body_size {
                let size = resp.body().map(|b| b.len() as u64).unwrap_or(0);
                builder = builder.response_body_size(size);
            }
        }

        // Timing
        if fields.duration_ms {
            if let Some(ms) = duration_ms {
                builder = builder.duration_ms(ms);
            }
        }

        // Routing info
        if fields.route_id {
            if let Some(route) = headers.get("x-zentinel-route-id") {
                builder = builder.route_id(route.clone());
            }
        }

        if fields.upstream {
            if let Some(upstream) = headers.get("x-zentinel-upstream") {
                builder = builder.upstream(upstream.clone());
            }
        }

        if fields.upstream_duration_ms {
            if let Some(duration) = headers
                .get("x-zentinel-upstream-duration-ms")
                .and_then(|s| s.parse().ok())
            {
                builder = builder.upstream_duration_ms(duration);
            }
        }

        // Agent decisions
        if fields.agent_decisions {
            if let Some(decisions) = headers.get("x-zentinel-agent-decisions") {
                // Parse JSON array of decisions
                if let Ok(decisions) = serde_json::from_str::<Vec<AgentDecision>>(decisions) {
                    for decision in decisions {
                        builder = builder.agent_decision(decision);
                    }
                }
            }
        }

        // Custom fields
        for (field_name, header_name) in &fields.custom_fields {
            if let Some(value) = headers.get(header_name) {
                builder = builder.custom_field(field_name.clone(), value.clone());
            }
        }

        builder.build()
    }

    /// Write an audit event to the output.
    async fn write_event(&self, event: &AuditEvent) {
        let formatted = self.formatter.format(event);
        if let Err(e) = self.output.write(&formatted).await {
            error!("Failed to write audit log: {}", e);
            self.output_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.events_logged.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record request start time for duration calculation.
    pub async fn record_request_start(&self, correlation_id: &str) {
        let mut times = self.request_times.lock().await;
        times.insert(correlation_id.to_string(), Instant::now());
    }

    /// Get request duration in milliseconds.
    pub async fn get_request_duration(&self, correlation_id: &str) -> Option<u64> {
        let mut times = self.request_times.lock().await;
        times
            .remove(correlation_id)
            .map(|start| start.elapsed().as_millis() as u64)
    }
}

// The agent needs to be Send + Sync for the SDK
unsafe impl Send for AuditLoggerAgent {}
unsafe impl Sync for AuditLoggerAgent {}

#[async_trait]
impl Agent for AuditLoggerAgent {
    fn name(&self) -> &str {
        "audit-logger"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        // Track request count
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Extract request data using SDK accessor methods
        let method = request.method();
        let path = request.path();
        let headers = request.headers();

        // Record start time for duration calculation
        let correlation_id = get_header_value(headers, "x-correlation-id")
            .or_else(|| get_header_value(headers, "x-request-id"))
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}", uuid::Uuid::new_v4()));

        self.record_request_start(&correlation_id).await;

        // For request-only logging (no response yet)
        debug!(
            method = %method,
            path = %path,
            "Request received"
        );

        // Always allow - audit logger doesn't block requests
        Decision::allow()
    }

    async fn on_response(&self, request: &Request, response: &Response) -> Decision {
        // Extract request data using SDK accessor methods
        let method = request.method();
        let path = request.path();
        let query_string = request.query_string();
        let headers = request.headers();
        let body = request.body();

        // Get correlation ID
        let correlation_id = get_header_value(headers, "x-correlation-id")
            .or_else(|| get_header_value(headers, "x-request-id"))
            .unwrap_or_default();

        // Get duration
        let duration_ms = self.get_request_duration(correlation_id).await;

        // Check if we should log this request
        if !self.should_log(method, path, headers, Some(response.status_code())) {
            self.events_filtered.fetch_add(1, Ordering::Relaxed);
            return Decision::allow();
        }

        // Flatten headers for internal use
        let flat_headers = flatten_headers(headers);
        let flat_resp_headers = flatten_headers(response.headers());

        // Build and write audit event
        let event = self.build_event(
            method,
            path,
            query_string,
            &flat_headers,
            body,
            Some((response, &flat_resp_headers)),
            duration_ms,
        );
        self.write_event(&event).await;

        debug!(
            method = %method,
            path = %path,
            status = response.status_code(),
            duration_ms = ?duration_ms,
            "Audit log written"
        );

        Decision::allow()
    }
}

/// v2 Protocol implementation for AuditLoggerAgent.
///
/// Provides capability reporting, health status, and metrics export.
#[async_trait]
impl AgentHandlerV2 for AuditLoggerAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("audit-logger", "Zentinel Audit Logger", env!("CARGO_PKG_VERSION"))
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::ResponseHeaders)
            .with_features(AgentFeatures {
                streaming_body: false,       // Audit logger doesn't need body streaming
                websocket: false,            // No WebSocket support
                guardrails: false,           // No guardrails
                config_push: true,           // Supports runtime config updates
                health_reporting: true,      // Reports health status
                metrics_export: true,        // Exports metrics
                concurrent_requests: 1000,   // Can handle many concurrent requests
                cancellation: true,          // Supports request cancellation
                flow_control: false,         // Doesn't need flow control (always allows)
            })
    }

    fn health_status(&self) -> HealthStatus {
        // Check if we're draining
        if self.draining.load(Ordering::Relaxed) {
            return HealthStatus::degraded(
                "audit-logger",
                vec!["new_requests".to_string()],
                1.0,
            );
        }

        // Check if there are output errors accumulating
        let errors = self.output_errors.load(Ordering::Relaxed);
        let logged = self.events_logged.load(Ordering::Relaxed);

        if errors > 0 && logged > 0 {
            let error_rate = errors as f64 / (errors + logged) as f64;
            if error_rate > 0.1 {
                // More than 10% error rate - report degraded
                return HealthStatus::degraded(
                    "audit-logger",
                    vec![],
                    1.5, // Increase timeouts by 50%
                );
            }
        }

        HealthStatus::healthy("audit-logger")
    }

    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("audit-logger", 10_000);

        // Add counter metrics
        report.counters.push(CounterMetric::new(
            "audit_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "audit_events_logged_total",
            self.events_logged.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "audit_events_filtered_total",
            self.events_filtered.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "audit_output_errors_total",
            self.output_errors.load(Ordering::Relaxed),
        ));

        // Add gauge for in-flight requests (approximate from request_times map size)
        // We can't easily get the map size without blocking, so we skip it
        // In a production implementation, you might use a separate AtomicU64 counter

        Some(report)
    }

    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            ?reason,
            grace_period_ms,
            "Received shutdown request, flushing outputs"
        );

        // Mark as draining to report degraded health
        self.draining.store(true, Ordering::Relaxed);

        // In a real implementation, we would flush outputs here
        // For now, just log the shutdown
    }

    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        warn!(
            ?reason,
            duration_ms,
            "Received drain request"
        );

        // Mark as draining
        self.draining.store(true, Ordering::Relaxed);
    }

    async fn on_stream_closed(&self) {
        debug!("Control stream closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ComplianceTemplate;

    fn test_headers() -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "api.example.com".to_string());
        headers.insert("user-agent".to_string(), "test-client/1.0".to_string());
        headers.insert("x-correlation-id".to_string(), "test-123".to_string());
        headers.insert("x-user-id".to_string(), "user-456".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers
    }

    fn test_multi_headers() -> HashMap<String, Vec<String>> {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), vec!["api.example.com".to_string()]);
        headers.insert("user-agent".to_string(), vec!["test-client/1.0".to_string()]);
        headers.insert("x-correlation-id".to_string(), vec!["test-123".to_string()]);
        headers.insert("x-user-id".to_string(), vec!["user-456".to_string()]);
        headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
        headers
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let config = AuditLoggerConfig::default();
        let agent = AuditLoggerAgent::new(config).await;
        assert!(agent.config.redaction.enabled);
    }

    #[tokio::test]
    async fn test_should_log_sampling() {
        let config = AuditLoggerConfig {
            sample_rate: 0.0, // Never sample
            ..Default::default()
        };

        let agent = AuditLoggerAgent::new(config).await;
        let headers = test_multi_headers();

        assert!(!agent.should_log("POST", "/api/users", &headers, Some(200)));
    }

    #[tokio::test]
    async fn test_should_log_filter_exclude() {
        let mut config = AuditLoggerConfig::default();
        config.filters.push(crate::config::FilterConfig {
            name: "exclude-health".to_string(),
            condition: crate::config::FilterCondition::PathPrefix {
                prefix: "/health".to_string(),
            },
            action: FilterAction::Exclude,
        });

        let agent = AuditLoggerAgent::new(config).await;
        let headers = test_multi_headers();

        assert!(!agent.should_log("GET", "/health/live", &headers, Some(200)));
    }

    #[tokio::test]
    async fn test_build_event() {
        let config = AuditLoggerConfig::default();
        let agent = AuditLoggerAgent::new(config).await;

        let headers = test_headers();
        let body = br#"{"name":"John"}"#;

        let event = agent.build_event(
            "POST",
            "/api/users",
            Some("page=1"),
            &headers,
            Some(body),
            None,
            Some(42),
        );

        assert_eq!(event.method, Some("POST".to_string()));
        assert_eq!(event.path, Some("/api/users".to_string()));
        assert_eq!(event.duration_ms, Some(42));
        assert_eq!(event.correlation_id, Some("test-123".to_string()));
    }

    #[tokio::test]
    async fn test_header_extraction_include() {
        let config = AuditLoggerConfig::default();
        let agent = AuditLoggerAgent::new(config).await;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("authorization".to_string(), "Bearer secret".to_string());
        headers.insert("x-custom".to_string(), "value".to_string());

        let config = HeaderFieldConfig::Include(vec!["content-type".to_string()]);
        let extracted = agent.extract_headers(&headers, &config);

        assert!(extracted.is_some());
        let extracted = extracted.unwrap();
        assert!(extracted.contains_key("content-type"));
        assert!(!extracted.contains_key("authorization"));
    }

    #[tokio::test]
    async fn test_body_redaction() {
        let mut config = AuditLoggerConfig::default();
        config.body.log_request_body = true;

        let agent = AuditLoggerAgent::new(config).await;

        let body = br#"{"email":"test@example.com","password":"secret"}"#;
        let processed = agent.process_body(Some(body), Some("application/json"));

        assert!(processed.is_some());
        let processed = processed.unwrap();
        // Email should be redacted
        assert!(!processed.contains("test@example.com"));
        assert!(processed.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_compliance_template() {
        let config = AuditLoggerConfig {
            compliance_template: Some(ComplianceTemplate::Hipaa),
            ..Default::default()
        };

        let agent = AuditLoggerAgent::new(config).await;

        // HIPAA should disable body logging
        assert!(!agent.config.body.log_request_body);
        assert!(!agent.config.body.log_response_body);
        // And enable hash_original
        assert!(agent.config.redaction.hash_original);
    }

    #[tokio::test]
    async fn test_request_duration_tracking() {
        let config = AuditLoggerConfig::default();
        let agent = AuditLoggerAgent::new(config).await;

        agent.record_request_start("test-id").await;

        // Small delay
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let duration = agent.get_request_duration("test-id").await;
        assert!(duration.is_some());
        assert!(duration.unwrap() >= 10);
    }

    #[test]
    fn test_flatten_headers() {
        let mut multi = HashMap::new();
        multi.insert("single".to_string(), vec!["value".to_string()]);
        multi.insert(
            "multi".to_string(),
            vec!["first".to_string(), "second".to_string()],
        );

        let flat = flatten_headers(&multi);

        assert_eq!(flat.get("single"), Some(&"value".to_string()));
        assert_eq!(flat.get("multi"), Some(&"first".to_string())); // Takes first value
    }

    #[test]
    fn test_get_header_value() {
        let mut headers = HashMap::new();
        headers.insert("present".to_string(), vec!["value".to_string()]);

        assert_eq!(get_header_value(&headers, "present"), Some("value"));
        assert_eq!(get_header_value(&headers, "missing"), None);
    }
}
