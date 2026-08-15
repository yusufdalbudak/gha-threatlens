# Implementation plan (v0.1.0)

This plan records the delivery sequence used for the initial release. It is not a substitute for the architecture, risk model, or rule documentation.

## Identity check

| Registry | Name | Result |
| --- | --- | --- |
| PyPI | `gha-threatlens`, `gha_threatlens` | Not published (HTTP 404) |
| GitHub | repository search `gha-threatlens` | Zero matches |

Unrelated projects named ThreatLens exist (log triage, CTI pipelines). They do not occupy the `gha-threatlens` distribution or import name. The project proceeds with that identity.

## Milestones

1. Package skeleton: `pyproject.toml`, `src/` layout, licence, quality tooling.
2. Domain model, error hierarchy, discovery, safe YAML parsing, IR normalisation.
3. Trust catalogue, permission model, scoring and confidence.
4. Rules GHAT-001 through GHAT-004, fact emission, restrained correlation.
5. CLI contract, terminal/JSON/Markdown/SARIF reporters.
6. Fixture corpus, unit/rule/correlation/integration tests, golden JSON.
7. Documentation, CI workflow, Dependabot, editorial pass.

## Dependencies

Runtime:

- `ruamel.yaml` — YAML 1.2 round-trip load with line/column metadata. The `on` key remains a string. Arbitrary object construction is not used.
- `click` — command groups, option validation, and exit handling at the CLI boundary. Click is a single library; Typer would wrap the same surface.
- `rich` — terminal reporter only. Colour is disabled for `--no-color`, non-TTY stdout, and `NO_COLOR`. Structured formats never import Rich for rendering.

Development: `pytest`, `pytest-cov`, `ruff`, `mypy`, `build`.

## Risks

| Risk | Mitigation |
| --- | --- |
| Missing `permissions` misread as write | Explicit `UNSET` / `UNKNOWN`; never infer repository defaults |
| `pull_request_target` flagged alone | GHAT-004 requires checkout plus execution; correlation refuses incomplete chains |
| YAML 1.1 `on: true` | Force YAML 1.2; warn if a boolean `True` key is the only trigger candidate |
| Unstable report output | Sorted collections, relative paths, injected UTC clock for tests |
| Catastrophic regex | Size-capped files, bounded expression extraction, no nested unbounded recursion |
| CI third-party actions | Pin verified full commit SHAs resolved from upstream release tags |

## Decisions taken where the specification left a gap

- Default maximum workflow size is 1 MiB. The limit is a documented constant, not a CLI flag, unless a later release needs operator control.
- GHAT-001 covers reusable workflow Git refs (`owner/repo/.github/workflows/*.yml@ref`) with the same mutability rules as actions. Docker image tags are not labelled as Git refs; digest analysis is out of scope.
- A malformed workflow is reported as a diagnostic. Other files in the same scan still produce findings.
- `NO_COLOR` is honoured in addition to `--no-color` and non-TTY detection. Token environment variables are never read.

## Verification commands

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/mypy src/gha_threatlens
.venv/bin/pytest
.venv/bin/pytest --cov=gha_threatlens --cov-report=term-missing --cov-fail-under=90
.venv/bin/python -m build
.venv/bin/gha-threatlens --help
.venv/bin/gha-threatlens scan tests/fixtures/repositories/safe
```
