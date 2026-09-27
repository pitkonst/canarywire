# canarywire: FAIL

5 findings · 5 attacks · seed 1 · canarywire 0.0.0 · 2026-09-26 09:01 UTC

## Findings

### 1. Leak: email in greeting @ main

At `body.messages[0].content` in 1 attack(s): baseline/greeting@main.

    Contact a@example.org for details
            ^^^^^^^^^^^^^

### 2. Leak: email in greeting

At `url` in 1 attack(s): unexpected.

No excerpt: the value is missing on one side.

### 3. Mangled request in farewell @ main

At `body.x` in 1 attack(s): baseline/farewell@main.

    expected: Send {{email}} the invoice.
    actual:   Send <EMAIL_1>ice.

### 4. Not restored: card in greeting @ main

At `body.x` in 1 attack(s): fragmentation/greeting@main.

    expected: Card ending 0002 approved
    actual:   Card ending REDACTED approved

### 5. Inconsistent placeholders: email in greeting @ main

At `body.a` in 1 attack(s): fault/down/greeting@main.

    <E1> at body.a
    <E2> at body.b

## Attacks

- baseline: 2 case(s): 1 mangled, 1 restored
- fragmentation: 1 case(s): 1 unrestored
- fault: 2 case(s): 1 inconsistent, 1 refused

## Faults

- `down`: before exit 0, after timed out — fault/down/greeting@main inconsistent, fault/down/farewell@main refused
- `slow`: before exit 0, after exit 0

## Run

- Target: http://gw.example.org
- Duty: restore
- Routes: openai-chat
- Templates: default, tool-calls, multi-turn
- Config: canarywire.yaml (000000000000)
- Capture: http://127.0.0.1:8765, 5 upstream request(s)
- Negative control: caught
- Verified values: 1
- Replay: `canarywire run --seed 1 --config canarywire.yaml`
