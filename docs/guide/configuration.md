# Configuration

`canarywire run --config canarywire.yaml`. Every key is optional; CLI flags override the file.

Start from [canarywire.yaml](canarywire.yaml): every key the parser accepts, set to its actual
default, with a short comment on each — copy it and delete what you don't change. A test
(`tests/test_config_reference.py`) keeps it in sync with the parser, so it's always current.

Canary types and templates have their own page: [canaries-and-templates.md](canaries-and-templates.md).
Faults: [faults.md](faults.md).

## How the pieces interact

- **Routes.** `target.routes` is a non-empty list; each route has a `protocol` (`openai-chat` or
  `anthropic-messages`), a `path`, and an optional `name` (defaulting to the protocol). Names are
  unique; two routes may share a protocol if their paths differ, but then need different names.
  Every generator sends its traffic once per route, for each template that route serves — attack
  names carry the route, e.g. `baseline/<template>@<route>`.
- **`duty: mask-only`** is for gateways that anonymize on the way in and never restore on the way
  out. The client must receive **exactly** the answer canarywire sent upstream, placeholders
  included. A matching answer is `delivered` (replacing `restored`); a mismatch is `altered`
  (fail), listed with `note: "altered under duty mask-only"`. Fault `expect` uses `deliver` in
  place of `restore`. Leaks, consistency and the refusal rules don't change.
- **Generators** consume `templates`: each generator's `templates` list names which ones it
  sends, and `generators.fragmentation`'s templates need a slot in the streamed text
  (`response.content`). Each generator also accepts `enabled: false`; `canarywire run
  --generators fragmentation,fault` runs only the generators you name. The default fragmentation
  cases send 16 streamed requests per template and route; cuts are seeded by template and case
  only, so every route gets the same cuts for the same template.
- **Seed.** Templates decide where canaries go; the seed decides which values they get, and how
  fragmentation splits answers. Without a seed, each run picks a fresh one and writes it to the
  report, so any failure can be replayed exactly with `canarywire run --seed <seed>`.
- **Timeouts** are in seconds. Each has a CLI flag of the form `--timeout-<name>`, for example
  `--timeout-client-request 60`, except `fault_command`.
- **Capture.** `canarywire serve --listen HOST:PORT [--detach]` starts the capture server that
  `capture.url`/`--capture` points at, and `canarywire stop` stops a detached one.
- **Report.** `--out DIR` overrides `report.dir` (itself unset by default; falls back to `out/`
  when neither is given); `--junit PATH` adds a `builtin:junit` output at `PATH`. `report.dir`,
  `--out` and `--junit` are relative to the working directory; a custom `template` path is
  relative to the config file's directory; an output `path` is relative to the report directory.
  Configure JUnit either in `outputs` or with `--junit`, not both at the same path — they'd
  collide (a config error). Details, including the template tags and JUnit mapping:
  [report.md](report.md).

## Config file paths

`--config PATH` is resolved relative to the working directory, like any other path argument. Once
loaded, a relative custom `report.outputs[].template` path is resolved relative to the config
file's directory, not the working directory — so a config file works the same wherever you
invoke `canarywire` from. `report.dir`, `--out` and `--junit` are relative to the working
directory instead (see above); an output's own `path` is relative to `report.dir`.

## Errors

Config and template errors exit `2` with the offending key path, before any traffic, and no report is written.
