# Canaries and templates

A **canary** is a synthetic value in a real format: an email address, a card number, your
customer ID. Every canary has a **type**. **Templates** decide which canaries a request carries and
where. Each run assigns one value per (template, instance), derived from the run's seed.

## Built-in types

All values are synthetic in real formats; types with a check digit always pass it.

| Type | Parameters (default first) | Values |
|---|---|---|
| `email` | `domain`: `example.org` \| any valid hostname | `<word>.<word><4 digits>@<domain>` |
| `phone` | `region`: `us` \| `uk` \| `de` \| `fr`; `format`: `e164` \| `national` | see below |
| `iban` | `country`: `de` \| `fr` \| `gb` \| `nl` \| `es`; `format`: `compact` \| `grouped` | mod-97 check digits; `grouped` = spaces every 4 |
| `card` | `brand`: `visa` \| `mastercard` \| `amex`; `format`: `compact` \| `grouped` | published test ranges; Luhn; `grouped` = 4-4-4-4 (Visa, Mastercard), 4-6-5 (Amex) |
| `national_id` | `country`: `us` \| `uk` \| `de`; `format`: `standard` \| `compact` | US SSN, UK NINO, DE tax ID (mod-11) |

- **Phone numbers:** US `555-01xx` and UK `07700 900xxx` are documented fiction ranges. DE and FR numbers are only synthetic and may match real ones, so prefer `region: us` or `uk` where that matters.
- **US SSNs** avoid never-issued ranges but are otherwise synthetic, so one may match a real issued number. Reports store the values.
- **DE tax IDs** follow the real structural rule and check digit.

Unknown parameters or parameter values are config errors naming the key path.

## Your own types

The types that matter most are usually yours. Define them under `canary_types`, each with exactly one of `values`, `schema` or `generator`, and an optional `checksum`. You can't reuse a built-in name.

```yaml
canary_types:
  customer_id:                      # a list of values: full control, nothing generated
    values: ["CUST-00412871", "CUST-99120034", "CUST-00000417"]
  contract_no:                      # a JSON Schema pattern (ECMA-262 subset)
    schema: { type: string, pattern: "^K-20[0-9]{2}-[0-9]{5}/[A-Z]{2}$" }
  work_email:                       # a JSON Schema format
    schema: { type: string, format: email }
  corporate_card:
    schema: { type: string, pattern: "^4[0-9]{15}$" }
    checksum: luhn                  # luhn | mod97 | mod11 | "package.module:function"
  loyalty_no:                       # your own Python code (the module must be importable
    generator: "acme_canaries.loyalty:generate"  # when `canarywire run` starts)
```

### `values`

- A non-empty list of distinct, non-empty strings.
- Instances draw from it without replacement, and a value already used elsewhere in the run is skipped, so several templates can share one list.
- No entry of a list used in the run may contain another entry, from the same list or another. That is a config error, whatever the seed.

### `schema`

Either `{type: string, pattern: …}` or `{type: string, format: …}`.

- **`pattern` supports:** literals, classes and ranges, `\d \w \s`, `.`, groups, alternation, and `^`/`$` at the ends.
- **Quantifiers:** `*`, `+` and `{n,}` generate at most 8 repetitions beyond the minimum. Lazy forms such as `*?` are accepted and generate the same values.
- **Config errors:** lookarounds, backreferences, named groups, flags and word boundaries.
- Every generated value is re-checked with `re.fullmatch`.
- **`format`** is one of `email`, `uuid`, `date`, `date-time`, `ipv4`, `ipv6`.

### `generator`

A `"package.module:function"` importable from the run's environment, with signature `(rng: random.Random, params: Mapping[str, Any]) -> str`.

- It must take all its randomness from `rng`: canarywire calls it twice with the same seed and rejects it if the results differ.
- Extra keys where a template declares the instance are passed as `params`.
- Loading it runs your code, so it needs the same trust as the config file itself.
- Only `canarywire run` imports it, before any traffic. An import error is a config error that names the key path. `serve` and `stop` only check the syntax.

### `checksum`

`luhn`, `mod97`, `mod11`, or `"package.module:function"` with signature `(value: str) -> bool`.

A regex can't express a check digit, and many detectors reject values that fail one: a test card that fails Luhn isn't a card, and a gateway that ignores it is right to. So:
- generated candidates that fail the checksum are discarded, and after 1000 failures the type is a config error;
- `values` entries that fail it are a config error that names them.

### Choosing values

- Prefer distinctive values of about 6 characters or more. A short value such as `DE` or `42` can turn up by chance in headers, model names or other traffic, and be reported as a leak.
- Generated values are never empty. A pattern that can only produce an empty string is a config error.
- Define canaries from **your data formats, not from your detector's rules**. A canary generated from the same regex the gateway uses to detect will always be caught, and proves nothing.
- Values from `values` are stored in reports as-is. Never put real personal data there; use synthetic values in real formats.

## Templates

A template is a request/response pair.
- It declares its canary **instances**: `name → type`, or `name → {type, <params>}`.
- It places them with slots:
  - `{{ <instance>.raw }}` puts the value in the request;
  - in the response, `{{ <instance>.masked }}` echoes back whatever the gateway sent upstream in its place, and `{{ <instance>.raw }}` gives the original value.

The runner checks that every slotted string of the response reaches the client with the original values restored. Under `mask-only`, the answer must instead arrive exactly as it was sent. A canary with no response slot is checked for masking only; `verified` does not count it.

| Built-in | What it covers |
| --- | --- |
| `default` | One message with one instance of each built-in type (instance names equal type names) |
| `tool-calls` | Canaries in a tool definition, in an earlier tool call's arguments and in a tool result, expected back restored in the answer's tool-call arguments |
| `multi-turn` | The same email in three turns and a second email in a later turn; each value must come back to its own position |

Add your own, or override a built-in by reusing its name:

```yaml
templates:
  invoice:
    canaries:
      customer: email
      card: { type: card, brand: amex, format: grouped }
      contract: contract_no
    request:
      messages:
        - role: user
          content: "Bill contract {{ contract.raw }} to card {{ card.raw }}, receipt to {{ customer.raw }}."
    response:
      content: "Billed {{ contract.masked }} to {{ card.masked }}; receipt sent to {{ customer.masked }}."

generators:
  baseline:      { templates: [default, invoice] }
  fragmentation: { templates: [default, invoice] }
```

These rules are checked before any traffic. A violation exits `2` with the key path and writes no report.
- `.masked` is only allowed in the response.
- Two request slots need literal text between them.
- Response slots may only name instances used in the request. Instances that are declared but unused are neither tested nor reported.
- A template listed under `fragmentation` needs a slot in the streamed text: `response.content`. The `tool-calls` template has none, because canarywire doesn't stream tool-call arguments.
- Within a template all values are distinct, and across the run no value may contain another.

Every scan looks for every value of the run, so a late leak of one template's value during another template's attack is still caught.

Keep the literal text around slots from looking like PII itself: a gateway that masks that text, or appends text after it, is reported as `mangled` rather than restored.

### Neutral format

A template without a `protocol` key is neutral and runs on every configured route:

```yaml
canaries: {card: card, email: email}
request:
  model: canarywire-test                       # optional, default canarywire-test
  system: "You are a billing assistant."       # optional
  tools:                                       # optional
    - {name: refund, description: "…", parameters: {type: object, properties: {…}}}
  messages:
    - {role: user, content: "Refund card {{ card.raw }}"}
    - {role: assistant, content: null, tool_calls: [{id: c1, name: lookup, arguments: {card: "{{ card.raw }}"}}]}
    - {role: tool, tool_call_id: c1, content: {status: found, to: "{{ email.raw }}"}}
response:
  content: "Done: {{ card.masked }}"           # string or null
  tool_calls: [{id: c2, name: refund, arguments: {card: "{{ card.masked }}"}}]   # optional
```

Rules:
- `messages` is required and non-empty.
- An `assistant` message needs a non-empty `content` string or a non-empty `tool_calls`, and so does the response.
- Any other role, or an unknown key anywhere, is a template error.
- Values inside `arguments`, `parameters` and tool `content` must be JSON values, and their keys must be strings.

An adapter translates the template into each protocol's shape when the config is checked:

| Neutral | openai-chat | anthropic-messages |
|---|---|---|
| `model` | `model` | `model`, plus `max_tokens: 1024` |
| `system` | first message `{role: system, content}` | top-level `system` |
| `tools[]` | `{type: function, function: {name, description, parameters}}` | `{name, description, input_schema: parameters}` |
| `user` message | `{role: user, content}` | `{role: user, content}` |
| `assistant` message | `{role: assistant, content, tool_calls?}` | `{role: assistant, content: [text block?, tool_use blocks…]}` |
| `tool` message | `{role: tool, tool_call_id, content}` | `{role: user, content: [tool_result blocks…]}` (consecutive tool messages merge) |
| response | OpenAI's `chat.completion` shape | Anthropic's `message` shape |

### Raw templates

Add `protocol: openai-chat` or `protocol: anthropic-messages` and write the request and response yourself, in that protocol's own shape. A raw template runs only on routes of its protocol; if no such route is configured, that's a config error.

In raw templates, JSON encoded inside a string (OpenAI tool-call arguments and tool results) is written as `{$json: …}`:

```yaml
arguments: {$json: {card: "{{ card.masked }}", note: "refund"}}
```

- canarywire renders it as a compact JSON string.
- Upstream, it decodes the gateway's string and requires the same shape (same keys, same list lengths). Otherwise the attack is untrusted.
- In the answer it compares after parsing, so key order and whitespace don't matter.
- A difference outside the slots fails every slot of that value, with a note saying where.
- Paths inside such strings are written with `$`, e.g. `…function.arguments$.card`.

In neutral templates `$json` is a template error: the adapters add it themselves where a protocol needs it.

### Consistency

An instance that appears several times must get the same placeholder every time.
- If the gateway masks it differently, the attack is `inconsistent` and the run fails. The report's `inconsistent` list shows each placeholder and where it was seen.
- A template can opt out with `consistency: ignore`.
- Two instances masked to the same placeholder show up as `unrestored`, with a `note` naming both.
