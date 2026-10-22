#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
#   1. no config file: the agent starts with its defaults (JSON to stdout)
#      and allows;
#   2. with a config writing JSON lines to a file (over the Unix socket and
#      over gRPC, subscribed to request and response headers): requests are
#      forwarded (200), the audit logger never blocks; with the agent stopped
#      the request is refused. Afterwards the file must hold one audit event
#      per request with method, path, query string and status, and the
#      Authorization header the client sent must not appear in it unredacted.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

# The first run changes directory, so make the paths absolute.
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
AGENT_BIN=$(abs "$AGENT_BIN"); ZENTINEL_BIN=$(abs "$ZENTINEL_BIN"); AGENT_SMOKE=$(abs "$AGENT_SMOKE")

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
SECRET="Bearer smoke-secret-$$-$RANDOM"

smoke() {
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name audit-logger \
        --events request_headers,response_headers "$@"
}

echo "=== audit-logger agent, no config file: defaults allow"
(cd "$dir" && mkdir -p empty && cd empty && smoke --clean '{"name": "ordinary request", "path": "/smoke"}')

for transport in uds grpc; do
    log="$dir/audit-$transport.log"
    cat > "$dir/audit-$transport.yaml" <<YAML
outputs:
  - type: file
    path: $log
YAML
    echo "=== audit-logger agent over $transport: requests allowed and audited"
    smoke --transport "$transport" --agent-arg=--config="$dir/audit-$transport.yaml" \
        --clean "{\"name\": \"ordinary request\", \"path\": \"/smoke-audit?q=1\", \"headers\": {\"Authorization\": \"$SECRET\"}}" \
        --case '{"name": "POST is allowed too", "method": "POST", "path": "/orders", "body": "{}", "expect": 200}' \
        --case '{"name": "upstream 200 on another path", "path": "/other", "expect": 200}'

    echo "=== audit-logger agent over $transport: audit file"
    python3 - "$log" "$SECRET" <<'PY'
import json, sys
path, secret = sys.argv[1], sys.argv[2]
try:
    text = open(path).read()
except OSError as e:
    sys.exit(f"FAIL: no audit log written: {e}")
if secret.split()[1] in text:
    sys.exit("FAIL: the Authorization header was written to the audit log unredacted")
events = [json.loads(line) for line in text.splitlines() if line.strip()]
def has(method, path, query=None):
    for e in events:
        # "path" carries the query string too; it is also in "query_string".
        if e.get("method") == method and (e.get("path") or "").split("?")[0] == path and e.get("status_code") == 200:
            if query is None or e.get("query_string") == query:
                return True
    return False
for method, p, q in (("GET", "/smoke-audit", "q=1"), ("POST", "/orders", None), ("GET", "/other", None)):
    if not has(method, p, q):
        print(text, file=sys.stderr)
        sys.exit(f"FAIL: no audit event for {method} {p} with status 200")
print(f"ok   {len(events)} audit events written; request lines, status codes and query string present; Authorization redacted")
PY
done
