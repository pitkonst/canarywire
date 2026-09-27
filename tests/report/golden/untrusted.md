# canarywire: UNTRUSTED

0 findings · 1 attacks · seed 2 · canarywire 0.0.0 · 2026-09-26 09:01 UTC

**Untrusted:** upstream did not respond within budget

## Findings

No findings.

## Trust problems

- upstream did not respond within budget
- 1 attack(s): timeout: no client response
- negative control did not run

## Attacks

- baseline: 1 case(s): 1 untrusted

## Run

- Target: http://gw.example.org
- Duty: restore
- Routes: openai-chat
- Templates: default, tool-calls, multi-turn
- Config: canarywire.yaml (000000000000)
- Capture: http://127.0.0.1:8765, 0 upstream request(s)
- Negative control: NOT caught
- Verified values: 0
- Replay: `canarywire run --seed 2 --config canarywire.yaml`
