//! Zentinel Audit Logger Agent
//!
//! A comprehensive audit logging agent for the Zentinel API Gateway.
//! Supports multiple log formats (JSON, CEF, LEEF), PII redaction,
//! and various output destinations.

pub mod agent;
pub mod config;
pub mod event;
pub mod format;
pub mod output;
pub mod redaction;

pub use agent::AuditLoggerAgent;
pub use config::AuditLoggerConfig;
pub use event::{AgentDecision, AuditEvent, AuditEventBuilder};
pub use format::{create_formatter, Formatter};
pub use output::{create_outputs, Output, OutputError};
pub use redaction::Redactor;
