# LiteLLM + Presidio

A worked sidecar setup: canarywire's capture runs on your machine, and a real PII gateway runs
in Docker Compose in front of it. The gateway is [LiteLLM](https://github.com/BerriAI/litellm)
with its Presidio guardrail, backed by Microsoft
[Presidio](https://github.com/microsoft/presidio) analyzer and anonymizer containers.

| File | What it is |
|---|---|
| `compose.yaml` | `presidio-analyzer`, `presidio-anonymizer`, `litellm` on 127.0.0.1:4000 and `litellm-scoped` on 127.0.0.1:4001. Images float on tag; healthchecks so `docker compose up --wait` returns only when every service is ready. |
| `litellm.yaml` | Model `canarywire-test` → `openai/canarywire-test` at `CAPTURE_URL`; the Presidio guardrail as LiteLLM documents it (`mode: pre_call`, `default_on: true`, `output_parse_pii: true`). Used by `litellm`. |
| `litellm-scoped.yaml` | The same, with entities limited to `EMAIL_ADDRESS` and `IBAN_CODE` (`pii_entities_config`). Used by `litellm-scoped`. |
| `default.yaml` | canarywire config for `litellm` (the guardrail as documented): the built-in templates and generators, plus one fault, `analyzer-down`. |
| `scoped.yaml` | canarywire config for `litellm-scoped`: a neutral template (`statement`) whose only PII is an email and an IBAN, so it doesn't collide with the overlapping-recogniser problem below. |
| `evaluate.sh` | Runs the whole thing: brings the stack up, runs both scenarios, prints a summary, tears the stack down. |

## What it evaluates

Two services, same guardrail code, different scope:
- **`litellm` / `default.yaml`** — the Presidio guardrail exactly as LiteLLM's docs show it.
- **`litellm-scoped` / `scoped.yaml`** — the guardrail scoped to just `EMAIL_ADDRESS` and
  `IBAN_CODE`, evaluated with a template built for that scope.

## Run it

Prerequisites: Docker with the Compose plugin, and canarywire either on `PATH` or run through
`uv` (`CANARYWIRE="uv run canarywire"`). Ports 4000, 4001 and 8765 must be free before you start.

```bash
./evaluate.sh
```

That's the whole thing: it starts the capture, brings up the stack, runs both scenarios, prints a
summary, and tears everything down — even if a run fails or the script is interrupted. A full
run takes about three minutes (LiteLLM retries every upstream 5xx three times, and most attacks
here fail closed).

To point at a different capture port: `CAPTURE_PORT=<port> ./evaluate.sh`. The capture listens on
`0.0.0.0` for the run's duration, which is what lets the containers reach it — don't run this on
an untrusted network.

## Read the results

Each scenario writes `out/default/` and `out/scoped/`; read `report.md` in each for the details,
`report.json` for machine-readable output. `evaluate.sh` also prints one summary line per
scenario (outcome, exit code, finding count, report path).

- **`default`** exercises the guardrail as documented, plus the `analyzer-down` fault. Expect
  failures: this is where the interesting findings are (see below).
- **`scoped`** exercises the guardrail limited to email + IBAN, with a template built for that
  scope, and no fault. This is where the guardrail's masking can actually be judged on its own
  terms, without the overlapping-recogniser problem in the way.

canarywire's own exit code (0 pass, 1 fail, 2 untrusted) is canarywire's verdict on that one
scenario's run, not a verdict on the gateway; `evaluate.sh` itself exits 0 as long as both
scenarios produced a `report.json` — see the script for exact rules.

## What we saw on 2026-09-26 (LiteLLM 1.102.1)

This table is orientation, not an expectation the script checks — canarywire doesn't pin
anything to image digests any more. Images float on tag, so a newer LiteLLM or Presidio release
may behave differently; re-run `evaluate.sh` to see for yourself, and treat any difference from
this table as news, not a bug in the example.

Images tested that day (`evaluate.sh` prints the actual digests for whatever run you did):

- `ghcr.io/berriai/litellm@sha256:87f34979b9f8cb274fac90ca8a4fdda07d8480de22755562a26adeb95ce20d02`
- `mcr.microsoft.com/presidio-analyzer@sha256:286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9`
- `mcr.microsoft.com/presidio-anonymizer@sha256:a10a12a2a613d13cf29d3ad3641e3258444dd8c90403dd644a0a114c472c2483`

| # | Finding | canarywire verdict |
|---|---|---|
| 1 | Tool-call arguments and tool descriptions are never masked: the guardrail walks only `messages[].content`. | `leak` at `body.messages[1].tool_calls[0].function.arguments` and `body.tools[0].function.description`; exit 1 |
| 2 | Overlapping Presidio entities garble the prompt. An email's domain also matches `URL`, other values match more than one recogniser, and the replacements are applied with the original offsets, so text next to a value is overwritten (`mail <EMAIL_ADDRESS_1>one <PHONE_NUMBER_3>MBER_5>LICENSE_5>, …`). Any prompt with an email is affected under the default config. | `mangled` at `body.messages[0].content`; exit 1 |
| 3 | Streams are never restored: streaming requests get placeholders, and the streamed answer is not unmasked. | `unrestored` at `stream.choices[0].delta.content` for every fragmentation case (on `litellm-scoped`); exit 1 |
| 4 | Analyzer down: the gateway fails closed with HTTP 500, but the first request after the analyzer stops can take up to about 31 s. LiteLLM's Presidio client opens a new connection to the stopped container's address with no connect timeout, and it fails only once the host is found unreachable (6–31 s in our measurements); later requests fail within about 50 ms. A *paused* analyzer (`docker compose pause`) makes LiteLLM hang for over 90 s. `default.yaml` raises `timeouts.client_request` to 90 s for this reason — the default 30 s would otherwise turn the slow first failure into an `untrusted` (timeout) verdict instead of a clean `refused`. | `refused` on `litellm-scoped` in 10 of 10 runs (the faulted request took about 15 s in 9 of 10 runs); would be `untrusted` (timeout) if the first request exceeded `timeouts.client_request` |
| 5 | With entities limited so they do not overlap (`litellm-scoped`), non-streaming restore works. | `restored`; exit 0 |
| 6 | `/v1/messages` sent to an OpenAI-provider model is forwarded upstream as `/v1/responses`. | not tested here (see limits) |
| 7 | Every upstream 5xx is retried: canarywire sees three upstream requests per attack when its capture answers an error (for example after a mangled request), which also lists each `mangled` and `leak` entry three times in the report. | informational |

canarywire ranks a leak above trust problems, and trust problems above `mangled`, so in this run
the exit code 1 on `default` was carried by the tool-call **leak** alone: a gateway that only
mangled prompts would, with the fault configured, exit 2 (its fault attacks untrusted); without
the fault it would exit 1.

## Limits

- **Anthropic route:** only the OpenAI Chat Completions route is tested. Testing `/v1/messages`
  needs an `anthropic/` provider model in LiteLLM (finding 6).
- **Retries:** LiteLLM retries upstream errors (finding 7), so failing attacks take several
  seconds each; a full run takes about three minutes.
- **Fixed ports:** `litellm` and `litellm-scoped` publish 127.0.0.1:4000 and 127.0.0.1:4001.
  `evaluate.sh` can't run while something else holds those ports, or port 8765.
- **Pausing the analyzer hangs LiteLLM:** `docker compose pause presidio-analyzer` (rather than
  `stop`) makes LiteLLM hang for over 90 s (observed) instead of failing closed, because the
  paused container accepts the TCP connection but never answers. Use `stop`/`up -d --wait`
  (as the `analyzer-down` fault does) for fault tests, not `pause`.
