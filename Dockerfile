# syntax=docker/dockerfile:1.4

# Zentinel Audit Logger Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-agent-audit-logger /zentinel-agent-audit-logger

LABEL org.opencontainers.image.title="Zentinel Audit Logger Agent" \
      org.opencontainers.image.description="Zentinel Audit Logger Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-audit-logger"

ENV RUST_LOG=info,zentinel_agent_audit_logger=debug \
    SOCKET_PATH=/var/run/zentinel/audit-logger.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-agent-audit-logger"]
