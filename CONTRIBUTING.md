# Contributing

## Environment

Python 3.11 or newer.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
```

End users who only need the CLI should install without `-e` and without `[dev]`; see README. Tests import the installed `gha_threatlens` package, not `src/` via `PYTHONPATH`.

Optional: install [pre-commit](https://pre-commit.com/) and run `pre-commit install` to apply the hooks in `.pre-commit-config.yaml`. Hooks are not required to submit a change if you run the same `ruff` commands locally.

## Branch and commit guidance

Use short, imperative conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Keep unrelated refactors out of detection changes.

## Verification

```bash
.venv/bin/ruff format .
.venv/bin/ruff check .
.venv/bin/mypy src/gha_threatlens
.venv/bin/pytest --cov=gha_threatlens --cov-report=term-missing --cov-fail-under=90
```

`python -m build` rewrites `*.egg-info`. If an editable install then fails to import, run `pip install -e ".[dev]"` again.

Release-time checks (`python -m twine check dist/*`, `pip-audit` in an isolated environment that has the built wheel) are optional and are not runtime dependencies.

Do not lower the coverage gate to hide untested rule branches.

## Code style

Ruff is the formatter and linter. mypy runs in strict mode on `src/gha_threatlens`. Prefer precise names, frozen dataclasses, and deterministic ordering. Comments should explain security invariants, not restate syntax.

## Adding a rule

Follow [docs/rule-authoring.md](docs/rule-authoring.md). Register the class in `src/gha_threatlens/rules/__init__.py`. Update `CHANGELOG.md` and the README rule table. v0.1.0 intentionally ships only GHAT-001–004; additional rules need a clear threat, fixtures, and scoring notes.

## Documentation

Match implemented behaviour. Do not add badges, download counts, or features that are not in the tree. British or neutral technical English. Do not mention authorship tooling.

## Responsible rule design

- Do not execute workflow content in tests or in the scanner.
- Do not fabricate replacement commit SHAs in remediation.
- Do not treat missing `permissions` as write.
- Do not report `pull_request_target` alone as confirmed exploitation.
- Include a near-miss fixture for every new rule.
