# canarywire

**A regression test for your PII gateway's trust boundary.**
Black-box, self-hosted, and it runs in CI. It works with any gateway that speaks the OpenAI or Anthropic API: public, commercial, or one your team wrote.

## Quick start

```bash
pip install canarywire
canarywire serve --detach --listen 127.0.0.1:8765                       # 1. fake upstream that records everything
your-gateway --upstream http://127.0.0.1:8765 --listen 127.0.0.1:4000  # 2. your gateway, pointed at it
canarywire run --target http://127.0.0.1:4000                           # 3. attack the gateway, check the boundary
canarywire stop
```

You start your gateway the way you always do, only with a different upstream. Exit code `0` means the boundary held. The report is in `out/report.json` and `out/report.md`.

A gateway that also serves Anthropic Messages, or uses other paths, needs a config file:

```yaml
# canarywire.yaml  →  canarywire run --config canarywire.yaml
target:
  base_url: http://127.0.0.1:4000
  routes:
    - {protocol: openai-chat, path: /v1/chat/completions}
    - {protocol: anthropic-messages, path: /v1/messages}
```

See [docs/guide/canarywire.yaml](https://github.com/pitkonst/canarywire/blob/main/docs/guide/canarywire.yaml) for every option with its default.

## Why

Most teams test PII masking with unit tests on the masking function. The function can be correct while the system as a whole leaks. Bugs like these pass function-level tests, and have been reported against widely used open-source gateways:

- a placeholder split across two SSE events is never restored;
- the detector goes down, and the gateway forwards the request **unmasked** instead of refusing it;
- placeholders are restored in message text, but not in tool-call arguments;
- two people get the same placeholder in one conversation, and the wrong name comes back.

canarywire checks what actually crossed the boundary.

## The invariant

1. **Absolute.** No canary value ever reaches the upstream, in any attack, whatever the outcome.
2. **Conditional.** If the request succeeded, every canary that the template echoes back reaches the client restored, in the right place.

A refused request is an acceptable outcome once the gateway has shown it works: under a fault, or
in a fragmentation case after the unsplit stream came back restored. A silent pass-through never
is. In `baseline` a refusal verifies nothing, so the run is `untrusted`: gateways that block
requests containing PII instead of masking them aren't supported yet.

## How it works

- `canarywire serve` runs a **capture server**, and you point your gateway's upstream at it.
- `canarywire run` generates **canaries**: synthetic values in the formats you declare sensitive. It sends them through the gateway, inside requests built from **templates**.
- The capture hands every upstream request to the runner, which:
  - checks it for canaries;
  - answers with a scripted response that echoes the gateway's placeholders;
  - then checks that the original values reached the client, in the right positions.

| Generator | What it tries |
| --- | --- |
| `baseline` | each template once: masked upstream, restored to the client, consistent placeholders |
| `fragmentation` | placeholders split across SSE events at every character offset |
| `fault` | your commands break the environment (e.g. stop the analyzer); the gateway must refuse |

The built-in templates cover plain messages (`default`), tool calls (`tool-calls`) and multi-turn conversations (`multi-turn`). You can add your own canary types, such as customer IDs or contract numbers, and your own templates. For gateways that only anonymize on the way in, set `target.duty: mask-only`.

| Exit code | Meaning |
| --- | --- |
| `0` | the invariant held |
| `1` | a leak, a value not restored (or altered under `mask-only`), inconsistent placeholders, or a request mangled around a canary |
| `2` | the run can't be trusted (capture unreachable, negative control not caught, config error, …) |

## Documentation

- [Configuration](https://github.com/pitkonst/canarywire/blob/main/docs/guide/configuration.md): target, routes, duty, generators, seed, timeouts.
- [Canaries and templates](https://github.com/pitkonst/canarywire/blob/main/docs/guide/canaries-and-templates.md): built-in and custom types, the template format, protocols.
- [Faults](https://github.com/pitkonst/canarywire/blob/main/docs/guide/faults.md): breaking the environment and the fail-closed verdicts.
- [Report](https://github.com/pitkonst/canarywire/blob/main/docs/guide/report.md): `report.json`, findings, templated outputs (Markdown, JUnit, your own), exit codes.
- [CI](https://github.com/pitkonst/canarywire/blob/main/docs/guide/ci.md): GitHub Actions and GitLab CI examples.

## What this is not

- **Not a gateway.** canarywire masks nothing and ships no proxy.
- **Not a detection-recall benchmark.** It proves the gateway handles the formats you declared, not how well a detector finds names in arbitrary text.
- **Not a quality benchmark.** How masking affects answer quality is a separate study.
- **Not proof of absence.** A format you didn't declare is a format that wasn't tested.
- **Not a fuzzy matcher.** A leak is the exact canary value in the upstream request (URL, headers,
  body, JSON inside strings). A gateway that forwards a value transformed, e.g. re-cased,
  re-spaced or base64-encoded, isn't caught.
- **Not a view of other channels.** Only what reaches the capture is checked. Values the gateway
  sends elsewhere (an external detection API, logs, telemetry) aren't seen.

## License

Apache-2.0
