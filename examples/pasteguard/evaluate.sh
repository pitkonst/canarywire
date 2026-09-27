#!/usr/bin/env bash
# Run this example end to end: bring up PasteGuard in Docker, run canarywire against it, print a
# summary, and tear everything down. See README.md.
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

$CANARYWIRE serve --detach --listen "0.0.0.0:${CAPTURE_PORT}"
docker compose pull
docker compose up -d --wait

print_image_digest() {
    # RepoDigests is empty for a platform-specific pull under emulation (no digest recorded
    # locally), so fall back to asking the registry for the release's manifest digest, and
    # finally to the local image ID, labelled as such, if even that fails (e.g. offline).
    local container_id image_id image_ref digest
    container_id="$(docker compose ps -q pasteguard)"
    image_id="$(docker inspect --format '{{.Image}}' "$container_id" 2>/dev/null || true)"

    digest="$(docker inspect \
        --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' \
        "$image_id" 2>/dev/null || true)"

    if [[ -z "$digest" ]]; then
        image_ref="$(docker compose config --images 2>/dev/null | head -n1)"
        digest="$(docker buildx imagetools inspect "$image_ref" \
            --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
    fi

    if [[ -z "$digest" ]]; then
        digest="local image id ${image_id:-unknown}"
    fi

    echo "  pasteguard: ${digest}"
}

echo "Images under test:"
print_image_digest

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

exit "$overall_exit"
