# In CI

| Phase | What happens |
| --- | --- |
| **pre** | `canarywire serve --detach` starts the capture and returns once it is ready; you start your gateway pointed at it |
| **test** | `canarywire run` attacks the gateway and writes reports |
| **post** | `canarywire stop` shuts the capture down and flushes its logs; you stop your gateway |

**Post must run even when the test fails:** that is when the capture logs matter most.

`run` always runs a fault's `after` hook, even on Ctrl-C or SIGTERM. The one exception is SIGKILL, for example from a CI job timeout. If that can happen, repeat your `after` commands in the post step.

GitHub Actions:

```yaml
- run: pip install canarywire
- run: canarywire serve --detach --listen 127.0.0.1:8765                       # pre
- run: ./start-gateway.sh --upstream http://127.0.0.1:8765 --listen 127.0.0.1:4000 --detach
- run: canarywire run --config canarywire.yaml --junit out/junit.xml            # test
- if: always()                                                                  # post
  run: canarywire stop && ./stop-gateway.sh
- if: always()
  uses: actions/upload-artifact@v4
  with: { name: canarywire-report, path: out/ }
```

A GitHub step summary from a custom template, alongside the built-in outputs — add
`ci/summary.md.mustache` to `canarywire.yaml`'s `report.outputs`:

```yaml
report:
  outputs:
    - {template: builtin:markdown, path: report.md}
    - {template: ci/summary.md.mustache, path: summary.md, escape: none}
```

JUnit still comes from `--junit out/junit.xml` on the command line; listing `builtin:junit` at
`junit.xml` here as well would be the same path twice, a config error.

Then the same `test` step also writes `out/summary.md`, and one more `post` step appends it to
the job's summary:

```yaml
- run: canarywire run --config canarywire.yaml --junit out/junit.xml            # test (as above)
- if: always()                                                                  # post
  run: cat out/summary.md >> "$GITHUB_STEP_SUMMARY"
```

GitLab CI:

```yaml
pii-boundary:
  before_script:
    - pip install canarywire
    - canarywire serve --detach --listen 127.0.0.1:8765
    - ./start-gateway.sh --upstream http://127.0.0.1:8765 --listen 127.0.0.1:4000 --detach
  script:
    - canarywire run --config canarywire.yaml --junit out/junit.xml
  after_script:                     # runs on success and on failure
    - canarywire stop
    - ./stop-gateway.sh
  artifacts:
    when: always
    paths: [out/]
    reports:
      junit: out/junit.xml
```

The capture is a separate process, so it can also run:
- as a sidecar, in docker-compose or Kubernetes — `examples/litellm-presidio/` (LiteLLM + Presidio), `examples/pasteguard/` (PasteGuard, GLiNER-based) and `examples/kiji/` (Dataiku Kiji, realistic fake values) are worked setups with a real gateway; run them yourself with their `evaluate.sh`;
- behind a tunnel, to test a hosted gateway.
