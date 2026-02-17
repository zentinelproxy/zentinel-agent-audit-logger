# Zentinel Audit Logger Agent

A comprehensive audit logging agent for the Zentinel API Gateway. Provides structured, compliance-focused logging with PII redaction, multiple output formats (JSON, CEF, LEEF), and various output destinations.

## Features

- **Multiple Log Formats**: JSON, CEF (ArcSight), LEEF (IBM QRadar)
- **PII Redaction**: Automatic detection and masking of sensitive data
  - Email addresses, credit cards, SSNs, phone numbers
  - JWT tokens, API keys, AWS access keys
  - Custom regex patterns
- **Compliance Templates**: Pre-configured for SOC2, HIPAA, PCI DSS, GDPR
- **Flexible Output**: Stdout, file (with rotation), syslog (UDP/TCP), HTTP webhooks
- **Conditional Logging**: Filter by path, method, status code, or headers
- **Request Sampling**: Configurable sample rate for high-traffic environments

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zentinel-agent-audit-logger = { git = "https://github.com/zentinelproxy/zentinel-agent-audit-logger" }
```

## Quick Start

```rust
use zentinel_agent_audit_logger::{AuditLoggerAgent, AuditLoggerConfig};
use zentinel_agent_sdk::AgentRunner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AuditLoggerConfig::default();
    let agent = AuditLoggerAgent::new(config).await;

    AgentRunner::new(agent)
        .with_name("audit-logger")
        .run()
        .await?;

    Ok(())
}
```

## Configuration

Create an `audit-logger.yaml` file:

```yaml
# Log format settings
format:
  format_type: json  # json, cef, or leef
  pretty: false
  include_timestamp: true
  timestamp_format: "%Y-%m-%dT%H:%M:%S%.3fZ"

# Fields to include in logs
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
  user_id_header: "x-user-id"
  request_headers:
    include:
      - content-type
      - user-agent
      - x-forwarded-for
  request_body: false
  response_body: false

# Output destinations
outputs:
  - type: stdout
  - type: file
    path: /var/log/zentinel/audit.log
    max_size: 104857600  # 100MB
    max_files: 10

# PII redaction
redaction:
  enabled: true
  patterns:
    - email
    - credit_card
    - ssn
    - phone
  replacement: "[REDACTED]"
  hash_original: false
  redact_headers:
    - authorization
    - cookie
    - x-api-key

# Request/response body logging
body:
  log_request_body: false
  log_response_body: false
  max_body_size: 4096
  content_types:
    - application/json
    - text/plain

# Compliance template (overrides other settings)
# compliance_template: hipaa

# Sampling rate (1.0 = log everything, 0.1 = 10%)
sample_rate: 1.0

# Conditional logging filters
filters:
  - name: exclude-health
    condition:
      type: path_prefix
      prefix: /health
    action: exclude
  - name: verbose-errors
    condition:
      type: status_code
      min: 500
      max: 599
    action: verbose
```

### Compliance Templates

Use pre-configured settings for common compliance standards:

```yaml
compliance_template: hipaa  # or soc2, pci, gdpr
```

- **SOC2**: Focus on access control and change management
- **HIPAA**: Strict PHI protection with hashed identifiers
- **PCI**: Card data protection, no body logging
- **GDPR**: Minimal personal data, IP addresses anonymized

## Log Formats

### JSON (default)

```json
{
  "@timestamp": "2024-01-15T10:30:45.123Z",
  "correlation_id": "req-abc123",
  "client_ip": "192.168.1.1",
  "method": "POST",
  "path": "/api/users",
  "status_code": 201,
  "duration_ms": 45,
  "user_id": "user-456"
}
```

### CEF (Common Event Format)

```
CEF:0|Zentinel|AuditLogger|1.0|POST-201|POST /api/users|1|rt=2024-01-15T10:30:45.123Z src=192.168.1.1 request=/api/users outcome=201
```

### LEEF (Log Event Extended Format)

```
LEEF:2.0|Zentinel|AuditLogger|1.0|POST:201|devTime=2024-01-15T10:30:45.123Z	src=192.168.1.1	url=/api/users	responseCode=201
```

## Custom Redaction Patterns

Add custom patterns for domain-specific data:

```yaml
redaction:
  custom_patterns:
    - name: account_id
      pattern: "ACC-\\d{8}"
      replacement: "[ACCOUNT]"
    - name: internal_id
      pattern: "INT-[A-Z0-9]{12}"
      replacement: "[INTERNAL_ID]"
```

## Running

```bash
# With default configuration
zentinel-agent-audit-logger

# With custom configuration
zentinel-agent-audit-logger --config /etc/zentinel/audit-logger.yaml

# Print default configuration
zentinel-agent-audit-logger --print-config

# Validate configuration
zentinel-agent-audit-logger --validate --config audit-logger.yaml
```

## CLI Options

- `-c, --config <PATH>`: Configuration file path (default: `audit-logger.yaml`)
- `-s, --socket <PATH>`: Unix socket path (default: `/tmp/zentinel-audit-logger.sock`)
- `-L, --log-level <LEVEL>`: Log level (trace, debug, info, warn, error)
- `--print-config`: Print default configuration and exit
- `--validate`: Validate configuration and exit

## Zentinel Integration

Add to your Zentinel configuration:

```kdl
agents {
    audit-logger socket="/tmp/zentinel-audit-logger.sock" {
        // Agent-specific configuration can be added here
    }
}
```

## License

Apache-2.0
