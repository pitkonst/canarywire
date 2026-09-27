# PasteGuard

A second worked sidecar setup: canarywire's capture runs on your machine, and a real PII gateway
runs in Docker. The gateway is [PasteGuard](https://github.com/sgasser/pasteguard), a proxy with a
built-in [GLiNER](https://github.com/urchade/GLiNER) detector, in contrast to
`examples/litellm-presidio/`'s LiteLLM + Presidio (regex/NER-based). Both proxy and detector run
in one container under supervisord.

| File | What it is |
|---|---|
| `compose.yaml` | Service `pasteguard` on 127.0.0.1:3000. `platform: linux/amd64` (see below). Healthcheck so `docker compose up --wait` returns only when the proxy and detector both report healthy. |
| `config.yaml` | PasteGuard config: mask mode, GLiNER entities, providers pointed at the capture, sqlite logging to `/tmp` inside the container (not the example directory), dashboard off. Mounted read-only. |
| `kill_detector.py` | Fault helper: kills the detector process inside the container (see `kill_detector.py` for how and why). Mounted read-only. |
| `default.yaml` | canarywire config: both routes (OpenAI Chat Completions and Anthropic Messages), the built-in templates and generators, and one fault, `detector-down`. |
| `evaluate.sh` | Runs the whole thing: brings the stack up, runs the scenario, prints a summary, tears the stack down. |

## What it evaluates

One service, both protocol routes PasteGuard exposes:
- `POST /openai/v1/chat/completions`
- `POST /anthropic/v1/messages`

Plus one fault: `detector-down` kills the GLiNER detector process inside the container (supervisord
restarts it a few seconds later) and checks that the proxy fails closed while it's down.

## Run it

Prerequisites: Docker with the Compose plugin, and canarywire either on `PATH` or run through
`uv` (`CANARYWIRE="uv run canarywire"`). Ports 3000 and 8765 must be free before you start.

```bash
./evaluate.sh
```

That's the whole thing: it starts the capture, brings up the stack, runs the scenario, prints a
summary, and tears everything down — even if the run fails or the script is interrupted.

To point at a different capture port: `CAPTURE_PORT=<port> ./evaluate.sh`. The capture listens on
`0.0.0.0` for the run's duration, which is what lets the container reach it — don't run this on
an untrusted network.

**Apple Silicon note:** PasteGuard's native arm64 image ships a GLiNER detector whose onnxruntime
CPU-feature detection segfaults under Docker Desktop on Apple Silicon. `compose.yaml` pins
`platform: linux/amd64` so the image runs under emulation instead, which works but is slower to
start (allow it the full healthcheck window) and slower per request than a native image would be.

## Read the results

The scenario writes `out/default/`; read `report.md` for the details, `report.json` for
machine-readable output. `evaluate.sh` also prints one summary line (outcome, exit code, finding
count, report path).

canarywire's own exit code (0 pass, 1 fail, 2 untrusted) is canarywire's verdict on that run, not
a verdict on the gateway; `evaluate.sh` itself exits 0 as long as a `report.json` was written —
see the script for exact rules.

## What we saw on 2026-09-27 (`ghcr.io/sgasser/pasteguard@sha256:dc7db60711af0d54df9e1591e0867384585fd03a4d951a9e8d3bdb2798999385`)

This table is orientation, not an expectation the script checks — canarywire doesn't pin anything
to image digests. The image floats on `latest`, so a newer PasteGuard release may behave
differently; re-run `evaluate.sh` to see for yourself, and treat any difference from this table as
news, not a bug in the example.

| # | Finding | canarywire verdict |
|---|---|---|
| 1 | The default template's national-id-shaped value (SSN) leaks: it isn't in PasteGuard's GLiNER entity list. | `leak`; exit 1 |
| 2 | The tool-calls template's IBAN, placed in a tool *description* rather than message content, leaks. | `leak` |
| 3 | The multi-turn template's assistant turn is forwarded unmasked: PasteGuard only masks the latest user turn. | `leak` + `inconsistent` |
| 4 | With a template built around just an email and an IBAN, fragmentation restores correctly on both routes (16/16 cases). | `restored`; exit 0 for this template |
| 5 | Killing the detector process makes the proxy fail closed with HTTP 503 on both routes while it's down, until supervisord restarts it. | `refused`, 2/2 |

Placeholders look like `[[EMAIL_ADDRESS_1]]`.

canarywire ranks a leak above trust problems, so the exit code on `default` is carried by the
leaks above (findings 1-3); a run that avoided those would still need to clear the fault before
reaching exit 0.

## Known limits

- **Fixed port:** `pasteguard` publishes 127.0.0.1:3000. `evaluate.sh` can't run while something
  else holds that port, or port 8765.
- **Config interpolation, not verified upstream:** PasteGuard's config loader accepts
  `${VAR:-default}` interpolation (used here for the capture URL); this isn't documented behavior
  we've verified against PasteGuard's own test suite, just what the spike observed working. If a
  future PasteGuard release drops it, `config.yaml`'s `providers.*.base_url` can be hardcoded to
  `http://host.docker.internal:8765` (and `CAPTURE_PORT` dropped from this example) as the
  simplest fallback.
- **Emulation slows detection, not just startup:** every request round-trips through the amd64
  emulation layer; expect this run to be noticeably slower than a native-image example.
