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

### Using Bundle (Recommended)

```bash
# Install just this agent
zentinel bundle install audit-logger

# Or install all bundled agents
zentinel bundle install
```

The bundle command downloads the correct binary for your platform and places it in the standard location. See the [bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/) for details.

### Using Cargo

Not supported. `zentinel-agent-audit-logger` is not published on crates.io, and it depends on
`zentinel-agent-protocol` through a path dependency, so neither
`cargo install zentinel-agent-audit-logger` nor `cargo install --git` works. Use a prebuilt
binary or build from source (below).

### Prebuilt Binaries

Each [release](https://github.com/zentinelproxy/zentinel-agent-audit-logger/releases) ships binaries
for `linux-x86_64`, `linux-aarch64`, and `darwin-aarch64`:

```bash
VERSION=0.4.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-audit-logger-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-audit-logger/releases/download/v${VERSION}/zentinel-audit-logger-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-audit-logger-agent.tar.gz
sudo install -m 0755 zentinel-audit-logger-agent /usr/local/bin/
```

### From Source

Building from source requires the [zentinel](https://github.com/zentinelproxy/zentinel) repository checked out
**next to** this one, because `zentinel-agent-protocol` is a path dependency:

```bash
git clone https://github.com/zentinelproxy/zentinel
git clone https://github.com/zentinelproxy/zentinel-agent-audit-logger
cd zentinel-agent-audit-logger
cargo build --release
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
zentinel-audit-logger-agent

# With custom configuration
zentinel-audit-logger-agent --config /etc/zentinel/audit-logger.yaml

# Print default configuration
zentinel-audit-logger-agent --print-config

# Validate configuration
zentinel-audit-logger-agent --validate --config audit-logger.yaml
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
