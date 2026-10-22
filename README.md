<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Audit logger agent</h3>

<p align="center">Writes one structured audit record per request, in JSON, CEF or LEEF, with PII redacted, from the request and response headers Zentinel sends it.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-audit-logger/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-audit-logger/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/audit-logger/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For teams that need an access trail a SIEM can ingest: the agent builds an audit
event when the response headers arrive, redacts sensitive values (named headers
and regex patterns such as emails, card numbers, SSNs, JWTs), and writes it to
stdout, stderr, a rotating file, syslog or an HTTP webhook. It never blocks or
changes a request; every decision it returns is "allow". Because of that, run it
with `failure-mode "open"`, so an unavailable logger does not take traffic down.

## Quick start

```bash
zentinel bundle install audit-logger
zentinel-audit-logger-agent --socket /tmp/zentinel-audit-logger.sock
```

Without `--config`, the agent looks for `audit-logger.yaml` in the working
directory and falls back to the defaults (JSON to stdout, redaction on).

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "audit-logger" type="custom" {
        unix-socket "/tmp/zentinel-audit-logger.sock"
        events "request_headers" "response_headers"
        timeout-ms 100
    }
}

filters {
    filter "audit-logger" {
        type "agent"
        agent "audit-logger"
        failure-mode "open"
    }
}

routes {
    route "default" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "audit-logger"
    }
}
```

The agent needs both `request_headers` and `response_headers`: the record is
written on the response event, from the request cached on the first.

## Install

### Bundle (recommended)

```bash
zentinel bundle install audit-logger
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-audit-logger-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-audit-logger/releases).

### From source

`cargo install --git` does not work for this crate: it depends on a sibling
checkout of `zentinel-agent-rust-sdk` by path. Clone both side by side:

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-rust-sdk
git clone https://github.com/zentinelproxy/zentinel-agent-audit-logger
cd zentinel-agent-audit-logger
cargo build --release   # target/release/zentinel-audit-logger-agent
```

Building needs `protoc` (CI installs `protobuf-compiler`).

## Configuration

Zentinel 0.6.50 does not forward an `agent { config { ... } }` block to agents;
configure the agent with the flags and the YAML file below.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config <PATH>` | `audit-logger.yaml` | YAML configuration file. If it does not exist, the defaults are used. |
| `-s`, `--socket <PATH>` | `/tmp/zentinel-audit-logger.sock` | Unix socket the agent listens on. |
| `--grpc-address <ADDR>` | unset | Also serve gRPC on this address (for example `0.0.0.0:50051`), in addition to the socket. |
| `-L`, `--log-level <LEVEL>` | `info` | `trace`, `debug`, `info`, `warn` or `error`. |
| `--print-config` | | Print the default configuration as YAML and exit. |
| `--validate` | | Parse the configuration file, print a summary and exit (fails if the file is missing). |

A minimal configuration file:

```yaml
format:
  format_type: json        # json, cef or leef
outputs:
  - type: stdout
  - type: file
    path: /var/log/zentinel/audit.log
    max_size: 104857600    # rotate at 100 MiB
    max_files: 10
redaction:
  patterns: [email, credit_card, ssn, phone, jwt]
  redact_fields: [password, user.ssn]
filters:
  - name: skip-health
    condition: { type: path_prefix, prefix: /health }
    action: exclude
```

Every key is optional; run `zentinel-audit-logger-agent --print-config` for the
full default file.

| Option | Default | Meaning |
|---|---|---|
| `format.format_type` | `json` | `json`, `cef` (ArcSight) or `leef` (QRadar). |
| `format.pretty` | `false` | Pretty-print JSON. |
| `format.timestamp_format` | `%Y-%m-%dT%H:%M:%S%.3fZ` | strftime format for the timestamp. |
| `format.device_vendor`, `device_product`, `device_version` | `Zentinel`, `AuditLogger`, crate version | CEF/LEEF header fields. |
| `fields.*` | most on | Booleans per field: `correlation_id`, `timestamp`, `client_ip`, `method`, `path`, `query_string`, `protocol`, `host`, `status_code`, `duration_ms`, `upstream_duration_ms`, `route_id`, `upstream`, `user_id`, `session_id`, `agent_decisions`, `request_body_size`, `response_body_size` (on); `request_body`, `response_body` (off). |
| `fields.request_headers` | a list of ten common headers | `none`, `all`, `!include [..]` or `!exclude [..]`. |
| `fields.response_headers` | `none` | Same forms as `request_headers`. |
| `fields.user_id_header`, `session_id_header` | `x-user-id`, `x-session-id` | Headers the user and session IDs are read from. |
| `fields.custom_fields` | `{}` | Map of record field name to request header name. |
| `outputs` | `[{type: stdout}]` | List of destinations, see below. |
| `redaction.enabled` | `true` | Turn redaction on or off. |
| `redaction.patterns` | `email`, `credit_card`, `ssn`, `phone` | Built-in patterns: also `ip_address`, `jwt`, `aws_key`, `api_key`. |
| `redaction.custom_patterns` | `[]` | Entries of `name`, `pattern` (regex), optional `replacement`. |
| `redaction.replacement` | `[REDACTED]` | Text that replaces a match. |
| `redaction.hash_original` | `false` | Replace a match with its SHA-256 hex instead, so values stay correlatable. |
| `redaction.redact_headers` | `authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token` | Headers whose value is always replaced. |
| `redaction.redact_fields` | `[]` | JSON body fields to redact, dot notation (`user.email`). |
| `body.*` | bodies off, `max_body_size` 4096 | `log_request_body`, `log_response_body`, `max_body_size`, `content_types`, `truncation_indicator`. See the limitation below. |
| `compliance_template` | unset | `soc2`, `hipaa`, `pci` or `gdpr`: presets applied over the file at startup. |
| `sample_rate` | `1.0` | Fraction of requests to log, `0.0` to `1.0`. |
| `filters` | `[]` | Ordered rules of `name`, `condition` and `action`; the first match decides. |

Outputs (`type` selects the variant):

| Option | Default | Meaning |
|---|---|---|
| `type: stdout` / `type: stderr` | | One line per record. |
| `type: file` with `path`, `max_size`, `max_files` | no rotation; `max_files` 5 when rotating | Appends to `path`; with `max_size` (bytes) set, rotates to `path.1` ... `path.N`. |
| `type: syslog` with `address`, `protocol`, `facility` | all required | `host:port`, `udp` or `tcp`, and a facility such as `local0` or `auth`. Severity is informational. |
| `type: http` with `url`, `method`, `headers`, `batch_size`, `flush_interval_secs`, `timeout_secs`, `retries` | all required | Webhook (`POST` or `PUT`) with retries and exponential backoff. Records are sent when `batch_size` is reached; `flush_interval_secs` is not used yet. |

Filter conditions: `method` (`values`), `path_prefix` (`prefix`), `path_regex`
(`pattern`), `status_code` (`min`, `max`), `header` (`name`, optional `value`)
and `all`. Actions: `include`, `exclude`, `verbose` (currently the same as
`include`).

Full reference: <https://registry.zentinelproxy.io/audit-logger/>

## How it works

- On `request_headers` the agent notes the start time, keyed by the request's
  `x-correlation-id` or `x-request-id` header; on `response_headers` it applies
  sampling and filters, builds the record and writes it to every output. An
  output that fails is logged and skipped; the others still receive the record.
- `duration_ms` is only filled when the request carries one of those two
  headers. Client IP comes from `X-Forwarded-For` or `X-Real-IP`; route,
  upstream, upstream duration and agent decisions come from the
  `x-zentinel-route-id`, `x-zentinel-upstream`,
  `x-zentinel-upstream-duration-ms` and `x-zentinel-agent-decisions` headers
  when they are present.
- Pattern redaction applies to header values and logged bodies; the path and
  query string are logged as received.
- Body logging (partial): the `body` settings and the `request_body` /
  `response_body` fields exist, but the record is built from header events
  only, so no body content reaches the log today.
- Kafka output (not implemented): the `kafka-output` cargo feature adds a
  `type: kafka` variant, which falls back to stdout with a warning.

## Development

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-rust-sdk ../zentinel-agent-rust-sdk
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Stable Rust (CI uses `dtolnay/rust-toolchain@stable`) and `protoc`. The HTTP
output is the default `http-output` feature; build with
`--no-default-features` to drop it.

## Related

- [Registry page](https://registry.zentinelproxy.io/audit-logger/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)
- [Rust agent SDK](https://github.com/zentinelproxy/zentinel-agent-rust-sdk)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
