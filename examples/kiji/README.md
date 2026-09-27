# Kiji Privacy Proxy

A third worked sidecar setup: canarywire's capture runs on your machine, and a real PII gateway
runs in Docker. The gateway is
[Kiji Privacy Proxy](https://github.com/dataiku/kiji-proxy) (Dataiku), a forward proxy with a
bundled PII detector that runs in-process (no separate detector service). What makes it worth a
separate example from `examples/litellm-presidio/` and `examples/pasteguard/`: Kiji replaces PII
with **realistic fake values** (e.g. an email became `amara.wang@example.org`, a card number
became an IE-formatted IBAN-looking string) instead of `[[PLACEHOLDER]]`-style tokens — canarywire
handles that unchanged, since it tracks values, not their shape.

| File | What it is |
|---|---|
| `Dockerfile` | Builds Kiji locally on `ubuntu:24.04` from the latest (or `KIJI_VERSION`-pinned) GitHub release tarball, checksum-verified — there is no published image. `--platform=linux/amd64`: upstream only ships amd64 binaries. Healthcheck on `/health`. |
| `compose.yaml` | Service `kiji` on 127.0.0.1:8080, built from the `Dockerfile`. `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` point at the capture; healthcheck so `docker compose up --wait` returns only once Kiji is ready. |
| `default.yaml` | canarywire config: both routes (OpenAI Chat Completions and Anthropic Messages), the built-in templates, fragmentation disabled (streaming is covered separately, see below). |
| `streaming.yaml` | A minimal template (one email, one IBAN) run under both `baseline` and `fragmentation`, so streaming behavior isn't drowned out by the rest of the default template set. |
| `evaluate.sh` | Runs the whole thing: resolves the latest Kiji release, builds the image, brings the stack up, runs both scenarios, prints a summary, tears the stack down. |

## What it evaluates

One service, both protocol routes Kiji exposes in forward-proxy mode:
- `POST /v1/chat/completions`
- `POST /v1/messages`

`default.yaml` runs the built-in template set (non-streaming only); `streaming.yaml` isolates
streaming and fragmentation behavior with a small email+IBAN template. There's no fault scenario
here: Kiji's detector runs in-process, not as a separate service that can be killed independently.

## Run it

Prerequisites: Docker with the Compose plugin, and canarywire either on `PATH` or run through
`uv` (`CANARYWIRE="uv run canarywire"`). Ports 8080 and 8765 must be free before you start.

```bash
./evaluate.sh
```

That's the whole thing: it resolves the latest Kiji release, builds the image, starts the
capture, brings up the stack, runs both scenarios, prints a summary, and tears everything down —
even if the run fails or the script is interrupted.

To point at a different capture port: `CAPTURE_PORT=<port> ./evaluate.sh`. The capture listens on
`0.0.0.0` for the run's duration, which is what lets the container reach it — don't run this on
an untrusted network.

**Apple Silicon note:** Kiji only ships amd64 release binaries; `Dockerfile` and `compose.yaml`
pin `platform: linux/amd64` so the image runs under emulation. Expect a slower build (the image is
~900 MB with the bundled detector model) and slower per-request latency than a native image, and
allow several minutes for the full `default.yaml` run.

**No pinned image:** unlike the other two examples, there's no tag or digest to float on — Kiji
ships no Docker image at all. `evaluate.sh` resolves the latest GitHub release tag itself and
passes it as a build arg (`KIJI_VERSION`), both so the Docker layer cache only re-downloads the
tarball when a new release actually exists, and so it can print the resolved version as the
source of truth for what a given run tested.

## Read the results

Each scenario writes `out/<scenario>/`; read `report.md` for the details, `report.json` for
machine-readable output. `evaluate.sh` also prints one summary line per scenario (outcome, exit
code, finding count, report path).

canarywire's own exit code (0 pass, 1 fail, 2 untrusted) is canarywire's verdict on that run, not
a verdict on the gateway; `evaluate.sh` itself exits 0 as long as both `report.json` files were
written — see the script for exact rules.

## What we saw on 2026-09-27 (Kiji 1.6.4)

This table is orientation, not an expectation the script checks — canarywire doesn't pin anything
to a release. `evaluate.sh` always builds the *latest* release, so a newer Kiji version may behave
differently; re-run it to see for yourself, and treat any difference from this table as news, not
a bug in the example.

| # | Finding | canarywire verdict |
|---|---|---|
| 1 | The default template is restored correctly on both routes. | `restored` |
| 2 | The tool-calls template leaks: a card number in earlier tool-call arguments, an IBAN in a tool description, and (Anthropic route) an email in a tool result. The answering tool call's own arguments are never restored either — the client receives Kiji's fake values, not the canary's. | `leak` + `inconsistent`; exit 1 |
| 3 | The multi-turn template doesn't leak, but the same email gets a different fake value in each turn, so the run is untrustworthy even without a leak. | `inconsistent` |
| 4 | Streaming never restores, on either route, whether fragmented or not — including the unfragmented stream, where the client receives a plausible but wrong (fake) value from Kiji. 64 unrestored occurrences (32 per route: 16 fragmentation cases × email + IBAN). | `unrestored` |

Placeholders look like realistic values in Kiji's own format, e.g. `amara.wang@example.org` or an
`IE60 8741 …`-shaped IBAN — never a `[[TYPE_N]]` token.

canarywire ranks a leak above trust problems, so the exit code on `default` is carried by finding
2's leaks; `streaming.yaml` never leaks a canary's raw value but fails on restoration, so its exit
code is carried by finding 4.

## Known limits

- **No fault scenario:** Kiji's PII detector runs in-process; there's no separate service to kill
  independently the way `examples/pasteguard/` kills GLiNER or `examples/litellm-presidio/` stops
  Presidio.
- **No pinned image, longer build:** every run resolves and builds the latest release from
  scratch (subject to Docker's layer cache); expect the first run, or any run after a new Kiji
  release, to take several minutes.
- **Emulation slows everything, not just startup:** every request round-trips through the amd64
  emulation layer; expect this run to be noticeably slower than a native-image example.
