# Report

Every run writes `out/report.json`, plus whatever `report.outputs` configures — by default `out/report.md`, a templated Markdown summary of the same data. `run --out DIR` changes the directory; `--config` picks a different set of outputs.

| Exit code | Meaning |
| --- | --- |
| `0` | the invariant held for every generator |
| `1` | a canary leaked upstream, a successful answer was not restored (or was altered under `mask-only`), a value got inconsistent placeholders, or a request was mangled around a canary |
| `2` | the run can't be trusted: the capture is unreachable, the negative control wasn't caught, nothing reached the upstream, a config error, an output failed to write, … |

## report.json (version 4)

Top-level fields:

- **Run information:** `version` (`4`), `outcome` (`pass`, `fail` or `untrusted`), `reason`, `duty`, `seed`, `started_at`, `finished_at`, `target`.
- **`run`:** the effective configuration that was tested (below).
- **`capture`:** the URL, the upstream request count, and the count of unexpected upstream requests.
- **`negative_control`:** whether the canaries sent straight to the capture were caught, per template and route.
- **`canaries`:** every tested value, with its template, instance and type.
- **`verified`:** how many values came back as the duty requires.
- **`leaks`:** canaries found upstream. Each entry has the attack, the instance (`canary`), the value, the location, the template, the type, and an `excerpt`. A location never contains the canary value itself: a JSON key holding it is reported as the containing object's location plus `{key}` (e.g. `body.metadata{key}`, or `body.messages[1].content$.meta{key}` inside a decoded JSON string), and any ancestor path segment that itself holds the value (a key one level up, say) is shown as `{key}` too, so a canary can never leak through the `location` string.
- **`unrestored`:** values that came back wrong, with the expected and actual text, an optional `note`, and an `excerpt`. Under `mask-only` these are the `altered` values.
- **`inconsistent`:** instances masked to more than one placeholder, with each placeholder and where it was seen.
- **`mangled`:** request strings the gateway changed around a canary, with the location, the template text (`expected`, slots shown as `{{instance}}`), the string as received (`actual`), the template name and an `excerpt`. Keep a template's literal text from looking like PII itself: a gateway that masks it, or appends text after it, is reported as `mangled`.
- **`attacks`:** one entry per attack, with its name, `status`, client HTTP status, upstream request count and reason.
- **`faults`:** each configured fault, with its `before` and `after` exit codes, durations and log paths (`null` if the hook didn't run). The commands themselves are never recorded, in the report or in `run.faults`.
- **`findings`:** `leaks`, `mangled`, `unrestored` and `inconsistent` grouped for reading (below).
- **`problems`:** every trust problem, grouped (below).

### `run`

The **effective** configuration that was tested: defaults, then the config file, then CLI flags.

- `canarywire_version`: the installed version.
- `config`: `{path, sha256}` — `path` as given on the command line, `sha256` the hex digest of the file's bytes; `null` when `run` had no `--config`.
- `routes`: `[{name, protocol, path}]`.
- `generators`: every generator (including disabled ones) with its full settings — the fields of its settings dataclass, `enabled` reflecting `--generators`.
- `faults`: `[{name, expect, settle_ms}]`. **`before`/`after` shell commands are never recorded** — they are the one config field likely to carry tokens or internal hostnames, and reports get uploaded as CI artifacts. The config file's `sha256` ties the report to them instead.
- `timeouts`: the effective timeout settings.

Custom canary type definitions are not recorded in `run`; the values they produced are in `canaries`.

### `excerpt`

**On a leak:** `{before, match, after}` — taken from the text the value was found in (the decoded body string, the URL, the raw header value, or the raw body, depending on where the hit was). `match` is the value as found; `before`/`after` are up to 40 characters on each side of the first occurrence, prefixed/suffixed with `…` when cut. This covers every leak, including the `unexpected` pseudo-attack's.

**On an unrestored, altered or mangled value:** `{expected, actual}` — the first differing character of `expected` and `actual` with up to 40 characters on each side (same `…` rule), both windows starting at the same offset. `null` when `expected` or `actual` itself is `null` (a missing field); the full, uncut `expected`/`actual` fields are unaffected.

In both forms, newlines, tabs and other control characters (Unicode category `Cc`) are replaced with `⏎`, `⇥` and `�`, so an excerpt is always one line. Invisible format characters such as a zero-width space (category `Cf`) are kept.

### `findings`

Every `leaks`, `mangled`, `unrestored` and `inconsistent` item belongs to exactly one finding:

```json
{
  "kind": "leak",
  "template": "tool-calls",
  "route": "openai-chat",
  "location": "body.messages[1].tool_calls[0].function.arguments",
  "instances": ["card"],
  "types": ["card"],
  "attacks": ["baseline/tool-calls@openai-chat"],
  "occurrences": 3,
  "leak_excerpt": {"before": "…", "match": "…", "after": "…"},
  "diff_excerpt": null,
  "placeholders": []
}
```

- `kind`: `leak`, `mangled`, `unrestored` (`altered` under `mask-only`) or `inconsistent`. For `mangled`, `instances` and `types` are empty: the value never reached its slot.
- **Grouping key:** `(kind, template, route, location)`. `template` comes from the grouped item, not the attack name. `route` is parsed out of the attack name: the first `/`-separated segment containing `@`, taken from after the `@` to the end of that segment (`baseline/default@openai-chat` → `openai-chat`; `fragmentation/default@openai-chat/chunks:2@1` → `openai-chat`); `null` for the `unexpected` pseudo-attack and for names with no such segment. For `inconsistent`, `location` is the first occurrence's path.
- `instances`, `types`, `attacks`: distinct values, first-seen order. `occurrences`: how many items were grouped.
- `leak_excerpt`, `diff_excerpt`, `placeholders`: evidence from the first grouped item — every finding has all three keys, but only the one matching its `kind` is non-empty.
- **Order:** leaks, then mangled, then unrestored/altered, then inconsistent; within a kind, findings with more `attacks` come first, ties broken by first-seen order.

### `problems`

Every trust problem `Report.problems()` produces, grouped by `(reason, run_level)`:

```json
[
  {"reason": "masked value not found at body.messages[0].content", "run_level": false, "attacks": ["…"], "count": 32},
  {"reason": "negative control did not run", "run_level": true, "attacks": [], "count": 1}
]
```

- Attack problems (`run_level: false`): `reason` is the attack's own reason (without the `<attack>: ` prefix); `attacks` lists them; `count` = `len(attacks)`.
- Run-level problems (`run_level: true`): `attacks` is `[]`; `count` is the number of identical occurrences.
- Order: first-seen. The top-level `reason` field is unchanged.

### Attack statuses

| Status | Meaning |
| --- | --- |
| `restored` / `delivered` | as the duty requires (`delivered` under `mask-only`) |
| `refused` | an acceptable refusal: a fault in effect, or a fragmentation case after a restored stream baseline |
| `unrestored` / `altered` | a value didn't come back as required: fail |
| `inconsistent` | one instance was masked to different placeholders: fail |
| `mangled` | the gateway changed the request text around a canary: fail |
| `untrusted` | nothing could be verified (timeout, no traffic, refusal where none is acceptable, …) |

**Precedence:** a leak outranks a trust problem, which outranks `unrestored`/`altered`, `inconsistent` and `mangled` (all three rank together). So a run with only mangled requests plus one untrusted attack exits `2`, not `1`: the trust problem wins.

The report is meant to be kept as evidence that the control was verified, not just chosen.

## Outputs

`report.json` is always written first, and is never itself a configured output. Everything else comes from `report.outputs`, rendered by canarywire's own strict Mustache subset:

```yaml
report:
  dir: out                                          # the default; --out overrides
  outputs:                                          # the default: [builtin:markdown → report.md]
    - {template: builtin:markdown, path: report.md}
    - {template: builtin:junit, path: junit.xml}
    - {template: ci/summary.md.mustache, path: summary.md, escape: none}
```

- `template`: `builtin:markdown`, `builtin:junit`, or a file path relative to the **config file's directory**. An unknown `builtin:` name is a config error.
- `report.dir` (like `--out` and `--junit`) is relative to the **working directory**, not to the config file.
- `path`: relative to the report directory; must name a file (not `""` or `.`), must not be absolute, must not contain `..`, and must not be `report.json`. Two outputs may not resolve to the same path.
- `escape`: `xml` or `none`. Default: `xml` when `path` ends in `.xml` or `.html` (any case), else `none`.
- Setting `outputs` replaces the default list entirely — to keep `report.md`, list it explicitly.
- `--out DIR` overrides `report.dir`. `--junit PATH` appends `{template: builtin:junit, path: PATH}`, with `PATH` taken relative to the working directory (like `--out`) and allowed to lie outside the report directory. It always uses `escape: xml`, whatever the suffix of `PATH`.
- Every output path is resolved to an absolute path (config paths against the report directory, `--junit` against the working directory) before writing. No resolved path may equal `<report dir>/report.json`, and no two may be equal; a collision is a config error naming both sources, e.g. `--junit: same path as report.outputs[1].path`.
- Config errors name the key path (`report.outputs[1].path: …`), exit `2`, and no report is written — same as any other config error.
- `serve`, `run` and `stop` all check the keys, path rules, duplicate rule and `builtin:` names when they load the config. Only `run` reads template files and runs the strictness check below, before any traffic; a missing or unreadable template file is a config error there.
- **Write failures:** `report.json` is written first, then each output in list order. An output that fails at write time (I/O error, or a render error the strictness check should have prevented) is printed to stderr as `canarywire: cannot write <path>: <error>`; the remaining outputs are still attempted, and `run` exits `2` whatever the outcome. Parent directories of output paths are created as needed.

## Template engine

A strict, dependency-free subset of Mustache (spec v1.4):

| Tag | Meaning |
| --- | --- |
| `{{name}}`, `{{a.b}}` | The value, escaped per the output's `escape`. |
| `{{{name}}}`, `{{& name}}` | The value, never escaped. |
| `{{#name}}…{{/name}}` | A non-empty list: render once per item, item pushed on the context stack. `true`/a non-empty string/a number/an object: render once, value pushed. `false`/`null`/`""`/`[]`: skip. |
| `{{^name}}…{{/name}}` | Render once when the value would skip a `{{#name}}` section; otherwise skip. |
| `{{.}}` | The top of the context stack. |
| `{{! … }}` | Comment. |

- **Strict:** a name whose first part is found nowhere on the stack, or whose later part is missing from an object, is a render/check error — never rendered as empty. A key present with value `null` is not an error, and when rendering, a later dotted part on a `null` value is `null`, not an error: `{{leak_excerpt.match}}` renders empty on a finding without a leak excerpt, and `{{#run.config.path}}…{{/run.config.path}}` is skipped when no config file was given. A later part on a string or number is still an error.
- **Escaping:** `xml` replaces `&`, `<`, `>`, `"`, `'` with entities, and characters XML 1.0 does not allow (control characters other than tab/newline/carriage return, U+FFFE, U+FFFF, lone surrogates) with U+FFFD, so the output always parses. `none` changes nothing.
- Standalone lines (only whitespace plus one section/comment tag) are removed whole, including the newline, per the Mustache spec.
- **Not supported**, each a parse error: partials (`{{>`), set delimiters (`{{=`), lambdas, blocks and parents (`{{$`, `{{<`). Unclosed/mismatched sections and unclosed tags are also parse errors.
- Errors carry the template name and 1-based line: `ci/summary.md.mustache:12: unknown name "leak"`.

### Strictness check

Rendering once against a sample can't see both branches of a section — with every list non-empty, `{{^findings}}`'s body never runs. So before any traffic, `run` parses every output's template and **statically walks** the parse tree against the merged *shape* of the view (every key present, with `null` for values that don't apply to that particular kind of item):

- a name is resolved exactly as at render time, but against shapes;
- `{{#name}}` on a list pushes the shape of its first item; on an object, pushes the object; on a scalar, pushes the scalar;
- `{{^name}}` walks its body with the stack unchanged;
- both kinds of section are always walked, whatever the sample value would do at render time.

A parse error or unknown name found this way is a config error naming the output (`report.outputs[2].template`) and the template's own error with its line. A template that passes the walk cannot hit an unknown name at render time for any real report.

## View model

Templates are logic-less; a Python view model layers derived, display-ready fields over `report.json`'s data (never mutating it). Every object keeps a fixed key set — a value that doesn't apply is `null`, never a missing key. Fields a template author is likely to need:

| Field | Meaning |
| --- | --- |
| `passed`, `failed`, `untrusted` | Booleans from `outcome`. |
| `outcome_upper` | `PASS`, `FAIL`, `UNTRUSTED`. |
| `finished` | `finished_at` formatted `YYYY-MM-DD HH:MM UTC`, or `null`. |
| `has_findings`, `has_problems`, `has_faults`, `has_run_problems` | Booleans, for `{{#…}}`/`{{^…}}` gating. |
| `counts` | `{attacks, findings, leaks, unrestored, inconsistent, mangled, problems, verified, failures, errors}`. A leaking attack counts as a failure even if also `untrusted`. |
| `findings[].number` | 1-based position. |
| `findings[].title` | `Leak`, `Mangled request`, `Not restored`, `Altered` or `Inconsistent placeholders`. |
| `findings[].instances_text`, `types_text`, `attacks_text` | The corresponding lists joined with `, `. |
| `findings[].attack_count` | `len(attacks)`. |
| `findings[].is_leak`, `is_mangled`, `is_unrestored`, `is_inconsistent` | Booleans from `kind`. |
| `findings[].leak_caret` | For leaks: a line of spaces the width of `leak_excerpt.before`, then `^` per character of `match`, to print under the excerpt. `null` otherwise. |
| `findings[].has_evidence` | Whether `leak_excerpt`, `diff_excerpt` or `placeholders` has something to show (an unrestored/altered value with a `null` `expected`/`actual` has none). |
| `generators[]` | Per generator that ran, run order: `{name, total, failures, errors, summary, attacks[]}`; `summary` is status counts as text, e.g. `16 restored, 2 refused`. |
| `run_problems[]`, `run_problem_count` | `problems[]` entries with `run_level: true`, as `{reason, count}`, plus the number of distinct entries. |
| `run_failures[]` | One entry per finding attributed to an unexpected upstream request (no attacking attack), as `{name, failure, failure_detail}`; `name` is `unexpected upstream request: <location>`. |
| `has_run_suite` | Whether `run_problems` or `run_failures` has anything (the JUnit `run` testsuite is present). |
| `run_suite_tests`, `run_suite_failures`, `run_suite_errors` | The JUnit `run` testsuite's own `tests`/`failures`/`errors` attributes: `run_suite_tests` is `run_problems` entries plus `run_failures` entries, `run_suite_failures` is `run_failures` entries, `run_suite_errors` is `run_problems` entries. |
| `attacks[].generator` | The name's first `/`-separated segment. |
| `attacks[].ok` | An acceptable status (`restored`/`delivered`/`refused`) with no leak. |
| `attacks[].failure` | For attacks in `counts.failures`: the titles/locations of every finding listing this attack, joined with `; `. `null` otherwise. |
| `attacks[].failure_detail` | Same attacks as `failure`: the failure text plus each finding's evidence lines, for the JUnit `<failure>` body. `null` otherwise. |
| `attacks[].error` | For `untrusted` attacks with no leak: the reason. `null` otherwise. |
| `problems[].attacks_text` | Joined attack names. |
| `faults[].summary` | Hooks (`before exit 0, after timed out`) plus the statuses of the fault's attacks. |
| `run.config_text` | `path (sha256 first 12)`, or `none`. |
| `run.routes_text`, `run.templates_text` | Joined route/template names (templates: the union over enabled generators). |
| `junit_tests`, `junit_failures`, `junit_errors` | Totals for the `builtin:junit` output: `junit_failures` includes `run_failures`, `junit_tests` includes both `run_problems` and `run_failures`. |
| `replay` | `canarywire run --seed <seed>`, plus `--config <path>` when there was one. |

## Built-in outputs

### `builtin:markdown` (default → `report.md`)

In order: outcome heading and one-line summary (plus the reason, when `untrusted`); `## Findings` (per finding, its heading, location, attacking attacks, and an evidence code block, indented four spaces so a backtick in an excerpt cannot break it — `before match after` and a caret line for leaks, `expected:`/`actual:` for unrestored and mangled, one line per placeholder for inconsistent; per-item lists like every leak or every mangled request live only in `report.json`, not here); `## Trust problems`, when any; `## Attacks`, one line per generator with its summary; `## Faults`, when any were configured; `## Run` — target, duty, routes, templates, config, capture URL and request count, negative control, verified values, and the replay command.

### `builtin:junit`

One `<testsuite>` per generator that ran (`classname` = generator, `name` = attack name, one `<testcase>` per attack): `ok` attacks pass, a counted failure gets `<failure message="…">` with the finding evidence as its text, an `untrusted` attack with no leak gets `<error message="…"/>`. Run-level problems and unexpected-upstream-request leaks become a `run` suite (present only when there are any), one `<error>` `<testcase>` per distinct run problem and one `<failure>` `<testcase>` per unexpected leak. Totals: `tests` = attacks + `run_problems` entries + `run_failures` entries, `failures` = `counts.failures` + `run_failures` entries, `errors` = `counts.errors` + `run_problems` entries.
