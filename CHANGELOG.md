# Changelog

All notable changes to canarywire. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Before 1.0, a minor version may break
the config file, the `report.json` format or exit-code rules; each such change is listed here.

## [0.1.0a1] - 2026-09-27

First public release, an alpha.

### Added

- `canarywire serve [--detach]`, `run` and `stop`; exit codes `0` (the invariant held), `1`
  (fail) and `2` (untrusted).
- Capture server: a fake upstream that records every request to `.canarywire/capture.jsonl` and
  relays it to the runner. Credential headers (`authorization`, `x-api-key`, …) are redacted
  in the record.
- Generators: `baseline`, `fragmentation` (placeholders split across SSE events) and `fault`
  (your `before`/`after` commands break the environment; the gateway must refuse).
- Protocols: OpenAI Chat Completions and Anthropic Messages, streaming and non-streaming;
  `target.routes` for several paths; `target.duty: mask-only` for gateways that never restore.
- Canaries: built-in types (email, phone, IBAN, card, national ID, …), custom types, seeded and
  replayable with `--seed`.
- Templates: built-in `default`, `tool-calls` and `multi-turn`, plus your own.
- Verdicts: leak (URL, headers, body, JSON keys, JSON inside strings), unrestored/altered,
  inconsistent placeholders, mangled request text; a negative control and a no-traffic rule
  guard against passes that tested nothing.
- Reports: `report.json` (version 4) with grouped findings, `report.md`, JUnit (`--junit`), and
  custom Mustache outputs.
- Worked examples against real gateways: `examples/litellm-presidio`, `examples/pasteguard`,
  `examples/kiji`.

### Known limitations

- Gateways that refuse requests containing PII (block mode) can't pass: a refusal outside a
  fault is `untrusted`.
- Leaks are exact matches; a value forwarded transformed (re-cased, re-spaced, encoded) is not
  detected.
- POSIX only.

[0.1.0a1]: https://github.com/pitkonst/canarywire/releases/tag/v0.1.0a1
