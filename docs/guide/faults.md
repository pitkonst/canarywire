# Faults

The `fault` generator breaks the environment instead of the request: it runs your commands around
templated requests, and the gateway must fail closed.

```yaml
faults:
  - name: analyzer-down
    before: docker stop presidio-analyzer
    after: docker start presidio-analyzer
    expect: refuse                  # the default
  - name: analyzer-slow
    before: tc qdisc add dev eth0 root netem delay 5s
    after: tc qdisc del dev eth0 root
    expect: [refuse, restore]       # [refuse, deliver] under duty mask-only
    settle_ms: 500                  # wait after `before`, for faults that take effect late
generators:
  fault: { templates: [default] }   # the default
timeouts:
  fault_command: 60                 # seconds, per before/after command
```

- **Names:** `[A-Za-z0-9_-]+`, unique, and not `control`.
- **`expect`:** `refuse`, `[refuse]` or `[refuse, restore]`. Under `mask-only`, use `deliver` in place of `restore`. `restore` alone isn't valid, because a fault that never has to refuse tests nothing.

## Order

Faults run after `baseline` and `fragmentation`.

1. **Controls first.** Before the first fault, canarywire sends one unfaulted control request per fault template and route (`fault/control/<template>@<route>`), judged like `baseline`.
   - A gateway that is already broken would refuse every faulted request and pass.
   - So if any control is not `restored` (`delivered` under `mask-only`), every fault attack is untrusted and no command runs.
2. **Then each fault, one at a time:**
   1. run `before`;
   2. wait `settle_ms`;
   3. send one non-streaming request per template and route (`fault/<fault>/<template>@<route>`);
   4. run `after`. This always happens, even when `before` failed or a request errored.

## Verdicts while a fault is in effect

| What happens | Verdict |
| --- | --- |
| A canary leaks upstream | fail |
| The gateway answers 4xx/5xx | `refused`: acceptable |
| The gateway answers 2xx and restores every value | `restored` if `expect` includes `restore`; otherwise untrusted ("fault had no effect") |
| The gateway answers 2xx but a value is not restored (or altered under `mask-only`) | fail |
| Timeout or connection error | untrusted |

## Commands

- **How they run:** with `/bin/sh -c`, in the directory where you started `canarywire run`, with your environment plus `CANARYWIRE_FAULT=<name>` and `CANARYWIRE_FAULT_HOOK=before|after`.
- **Output:** goes to `out/faults/<name>.before.log` and `….after.log`. The report's `faults` section lists each hook's exit code and duration.
- **Timeouts:** a command that exceeds `fault_command` is killed together with its whole process group.
- **Failures:**
  - a failing `before` makes that fault's attacks untrusted;
  - a failing `after` makes the run untrusted and skips every later fault, since the environment may still be broken.
- **Signals:** Ctrl-C or SIGTERM during a fault still runs its `after` hook. canarywire then exits with `128 + signal`, without writing a report.
- **SIGKILL** (for example, a CI job timeout) is the one case where `after` can't run. If that can happen, repeat your `after` commands in CI's post step.
