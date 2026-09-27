# canarywire — contributor notes

See `README.md` for what the tool does. User documentation lives in `docs/guide/`.

## Setup

```bash
uv sync                      # create .venv with dev deps
uv run pre-commit install    # lint/format/typecheck on commit
```

## Commands

```bash
uv run pytest                          # tests
uv run pytest --cov                    # tests + coverage
uv run ruff check --fix .              # lint
uv run ruff format .                   # format
uv run mypy                            # type check (strict)
uv run pre-commit run --all-files      # everything above except tests
uv run canarywire --help               # run the CLI
uv run pytest -m "not e2e"             # unit tests only (fast loop)
uv run pytest -m e2e                   # end-to-end suite only
```

## Conventions

- Python 3.10+ (`.python-version` pins 3.10 locally so we never use newer features by accident).
- `src/` layout; package is `src/canarywire/`.
- Full type hints everywhere; `mypy --strict` must pass. The package ships `py.typed`.
- Ruff is the only linter and formatter; config is in `pyproject.toml`. Google-style docstrings on public API.
- Tests mirror the package: `src/canarywire/<path>/<mod>.py` → `tests/<path>/test_<mod>.py`. No `__init__.py` in `tests/` (pytest runs with `--import-mode=importlib`).
- Warnings are errors in tests.
- Commit messages: one simple line, imperative mood (e.g. `Add JUnit output`); no body, no
  trailers, no attribution (`Co-Authored-By`, session links, "Generated with").
- Dependencies: runtime in `[project].dependencies`, tooling in `[dependency-groups].dev`. Add with `uv add` / `uv add --dev`; commit `uv.lock`.
- Never put real personal data in fixtures or canary values — synthetic values only.
- Async everywhere, including canarywire itself: `httpx.AsyncClient` for HTTP clients, Starlette + uvicorn for servers, anyio for tests.
- `tests/e2e/` is the one exception to mirroring: true end-to-end tests with real processes over TCP (POSIX-only).
  - `tests/e2e/gateways/refgw.py` is the reference gateway; it must never import `canarywire`. Each new generator lands with the `--bug` variant it catches.
  - Assert on exit codes and `out/report.json` fields; include `e2e.diagnostics()` in assertion messages.
- Shared unit-test helpers live in `tests/support/` (on pytest `pythonpath`, imported as `from live import ...`). Test file basenames must be unique across `tests/` (mypy keys modules by basename).
- The capture stays slim: it records and relays; canaries, templates, attacks and verdicts live in the runner (`src/canarywire/runner/`).
