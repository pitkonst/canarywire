# canarywire: PASS

0 findings · 1 attacks · seed 0 · canarywire 0.0.0 · 2026-09-26 09:01 UTC

## Findings

No findings. All 1 values verified.

## Attacks

- baseline: 1 case(s): 1 restored

## Run

- Target: http://gw.example.org
- Duty: restore
- Routes: openai-chat
- Templates: default, tool-calls, multi-turn
- Config: canarywire.yaml (000000000000)
- Capture: http://127.0.0.1:8765, 1 upstream request(s)
- Negative control: caught
- Verified values: 1
- Replay: `canarywire run --seed 0 --config canarywire.yaml`
