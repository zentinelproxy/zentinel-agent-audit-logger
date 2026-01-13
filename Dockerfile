# syntax=docker/dockerfile:1.4

# Sentinel Audit Logger Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-audit-logger /sentinel-agent-audit-logger

LABEL org.opencontainers.image.title="Sentinel Audit Logger Agent" \
      org.opencontainers.image.description="Sentinel Audit Logger Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-audit-logger"

ENV RUST_LOG=info,sentinel_agent_audit_logger=debug \
    SOCKET_PATH=/var/run/sentinel/audit-logger.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-audit-logger"]
