#!/usr/bin/env bash
# Run this example end to end: bring up LiteLLM + Presidio in Docker, run canarywire against
# both services, print a summary, and tear everything down. See README.md.
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
export CAPTURE_URL="http://host.docker.internal:${CAPTURE_PORT}/v1"

cleanup() {
    $CANARYWIRE stop >/dev/null 2>&1 || true
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

$CANARYWIRE serve --detach --listen "0.0.0.0:${CAPTURE_PORT}"
docker compose pull
docker compose up -d --wait

echo "Images under test:"
litellm_version="$(docker compose exec -T litellm python -c \
    'import importlib.metadata; print(importlib.metadata.version("litellm"))' \
    2>/dev/null || echo unknown)"
echo "  LiteLLM version: ${litellm_version}"
for service in litellm litellm-scoped presidio-analyzer presidio-anonymizer; do
    container_id="$(docker compose ps -q "$service")"
    image_id="$(docker inspect --format '{{.Image}}' "$container_id" 2>/dev/null || true)"
    digest="$(docker inspect --format '{{index .RepoDigests 0}}' "$image_id" \
        2>/dev/null || echo "unknown")"
    echo "  ${service}: ${digest}"
done

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
run_scenario scoped scoped.yaml

exit "$overall_exit"
