#!/usr/bin/env bash
# Run this example end to end: build Kiji Privacy Proxy from the latest GitHub release, bring it
# up in Docker, run canarywire against it, print a summary, and tear everything down. See
# README.md.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

CANARYWIRE="${CANARYWIRE:-canarywire}"

if ! $CANARYWIRE --version >/dev/null 2>&1; then
    echo "error: \$CANARYWIRE ('$CANARYWIRE') does not run; set CANARYWIRE to a working" \
        "canarywire command (e.g. CANARYWIRE=\"uv run canarywire\")" >&2
    exit 2
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "error: 'docker compose' does not work; install Docker with the Compose plugin" >&2
    exit 2
fi

CAPTURE_PORT="${CAPTURE_PORT:-8765}"
export CAPTURE_URL="http://host.docker.internal:${CAPTURE_PORT}"

cleanup() {
    $CANARYWIRE stop >/dev/null 2>&1 || true
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Resolve the latest release tag ourselves rather than letting the Dockerfile do it: this makes
# the build arg a cache key, so `docker compose build --pull` only re-downloads the Kiji tarball
# when a new release actually exists (the ubuntu:24.04 base layer still refreshes every time).
echo "Resolving latest Kiji Privacy Proxy release..."
KIJI_TAG="$(curl -fsSL https://api.github.com/repos/dataiku/kiji-proxy/releases/latest \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')"
export KIJI_VERSION="${KIJI_TAG#v}"
echo "  resolved: ${KIJI_TAG} (KIJI_VERSION=${KIJI_VERSION})"

$CANARYWIRE serve --detach --listen "0.0.0.0:${CAPTURE_PORT}"
docker compose build --pull
docker compose up -d --wait

echo "Images under test:"
kiji_version="$(docker compose exec -T kiji /opt/kiji-proxy/bin/kiji-proxy --version \
    2>&1 || echo unknown)"
echo "  Kiji version: ${kiji_version}"

overall_exit=0

run_scenario() {
    local name="$1" config="$2"
    local out_dir="out/${name}"
    rm -rf "$out_dir"
    set +e
    $CANARYWIRE run --config "${config}" --capture "http://127.0.0.1:${CAPTURE_PORT}" \
        --out "$out_dir"
    local rc=$?
    set -e

    local report="${out_dir}/report.json"
    if [[ ! -f "$report" ]]; then
        echo "${name}: no report.json written (exit ${rc})"
        overall_exit=2
        return
    fi

    local outcome findings
    outcome="$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(data["outcome"])
' "$report")"
    findings="$(python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(len(data["findings"]))
' "$report")"
    echo "${name}: outcome=${outcome} exit=${rc} findings=${findings} report=${out_dir}/report.md"
}

run_scenario default default.yaml
run_scenario streaming streaming.yaml

exit "$overall_exit"
