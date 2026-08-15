# GHA-ThreatLens

Offline static analysis and attack-path correlation for GitHub Actions workflows.

## Project status

v0.1.0. Supported runtimes: Python 3.11, 3.12, and 3.13.

The scanner is a local, deterministic CLI. It does not claim complete GitHub Actions coverage, zero false positives, or production certification.

## The security problem

A GitHub Actions workflow is a programme that can run untrusted input, execute repository or pull-request code, and hold a `GITHUB_TOKEN` with repository privileges. Isolated YAML checks (a dangerous trigger here, a write permission there) miss the path that actually matters: how an untrusted actor can move from an entry point to code execution, credential abuse, or a compromised build or release.

## What GHA-ThreatLens does differently

The tool records atomic security facts and correlates them only when the required edges are present. A typical linter might report `pull_request_target`, a pull-request checkout, `contents: write`, and a local script as four unrelated warnings. GHA-ThreatLens retains those facts and, when the chain is complete, emits an ordered attack path:

```
External pull request
  -> privileged pull_request_target workflow
  -> attacker-controlled head checkout
  -> checked-out code execution
  -> contents: write permission
  -> repository modification
```

If an essential edge is missing, the tool does not invent a complete path. Isolated indicators are not described as confirmed exploitation.

## Example

This workflow is a complete privileged pull-request chain:

```yaml
name: pr-target-chain
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./scripts/test.sh
```

GHA-ThreatLens reports GHAT-004 with evidence for the trigger, the head checkout, the local script, and `contents: write`. Correlation produces one attack path. Direct `./scripts/test.sh` execution is high confidence. The numeric score is a prioritisation aid, not a probability that an attacker will succeed.

The same trigger with a trusted base checkout and no subsequent execution of pull-request code does not produce a confirmed GHAT-004 path.

## Key capabilities

- Discovers `.github/workflows/*.yml` and `*.yaml` under a user-supplied directory.
- Parses YAML 1.2 without executing workflow content, expanding templates, or constructing Python objects from tags.
- Classifies trigger and expression trust explicitly (maintainer, collaborator, external, public, actor-dependent, unknown).
- Models `GITHUB_TOKEN` declarations including `read-all`, `write-all`, `{}`, job overrides, and missing keys as unknown rather than write.
- Ships four rules: mutable action refs, excessive token permissions, untrusted expressions in `run:`, and privileged pull-request code execution.
- Correlates the pull_request_target chain into an evidence-backed attack path.
- Emits terminal, JSON, Markdown, and SARIF 2.1.0 reports.
- Runs offline. Local scans make no network requests and do not read GitHub tokens.

## Installation

Local scanning requires no GitHub token. The scanner does not read `GITHUB_TOKEN`, `GH_TOKEN`, or personal access tokens.

End-user installation from a clone (no development extras):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install .
```

Installation from a built wheel:

```bash
python3 -m pip install dist/gha_threatlens-0.1.0-py3-none-any.whl
```

Contributor editable installation (Python 3.11, 3.12, or 3.13):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
```

The console command is `gha-threatlens`. SARIF upload to GitHub code scanning is an optional later step; it is not part of local installation.

## Quick start

```bash
gha-threatlens scan tests/fixtures/repositories/safe
gha-threatlens scan examples/vulnerable --format json
gha-threatlens rules list
gha-threatlens explain GHAT-004
```

`PATH` defaults to the current directory. Local scanning requires no GitHub token and performs no network requests. Workflow files and evidence remain in the local process. The tool does not collect telemetry.

## CLI usage

```text
gha-threatlens scan PATH
gha-threatlens rules list
gha-threatlens explain RULE_ID
gha-threatlens version
```

`scan` options:

| Option | Effect |
| --- | --- |
| `--format terminal\|json\|markdown\|sarif` | Report format. Default: `terminal`. |
| `--output PATH` | Write the report to a file instead of stdout. |
| `--fail-on informational\|low\|medium\|high\|critical` | Exit 1 when a finding or attack path meets the threshold. |
| `--min-severity informational\|low\|medium\|high\|critical` | Omit lower-severity results. |
| `--no-color` | Disable ANSI colour. Also honoured when stdout is not a TTY or `NO_COLOR` is set. |
| `--quiet` | Suppress the terminal summary; findings and paths are still printed. |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Scan completed; nothing met `--fail-on`, or no fail threshold was set. |
| 1 | Scan completed; at least one finding or attack path met `--fail-on`. |
| 2 | User input, target, or parsing prevented a valid requested scan. |
| 3 | Unexpected internal error. |

JSON, Markdown, and SARIF written to stdout contain only the report. A malformed workflow is recorded as a diagnostic; other files in the same scan are still analysed.

The default maximum workflow size is 1 MiB (`DEFAULT_MAX_WORKFLOW_BYTES`). Larger files are skipped with a diagnostic.

## GitHub Actions integration

Pin third-party actions to verified full commit SHAs. The SHAs below were resolved from the upstream repositories for the tagged releases shown in comments.

```yaml
name: gha-threatlens
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      - run: python -m pip install .
      - run: gha-threatlens scan . --fail-on high --no-color
```

GitHub may inject a repository-scoped `GITHUB_TOKEN` into the job. The scanner does not read `GITHUB_TOKEN`, `GH_TOKEN`, or personal access tokens. It does not use that token for analysis.

## SARIF upload example

SARIF display in private repositories depends on the GitHub plan and whether code scanning is enabled. Upload is a separate GitHub integration step; it is not performed by the scanner.

```yaml
name: gha-threatlens-sarif
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      - run: python -m pip install .
      - run: gha-threatlens scan . --format sarif --output results.sarif --no-color
      - uses: github/codeql-action/upload-sarif@f3712979fa5f215279b101dd0a2e3bdfb4353324 # v3.37.7
        with:
          sarif_file: results.sarif
```

`security-events: write` is required for the upload action. GHAT-002 reports explicit high-impact write scopes, including `security-events`. That finding flags breadth of token access; it does not prove the job is unnecessary.

## Supported rules

| ID | Title | Behaviour in v0.1.0 |
| --- | --- | --- |
| GHAT-001 | Mutable action reference | Flags remote GitHub Action and reusable-workflow Git refs that are not a full 40-character commit SHA. Local paths are ignored. Docker image tags are not treated as Git refs; digest analysis is not implemented. |
| GHAT-002 | Excessive token permissions | Flags `write-all` and explicit high-impact write scopes. A missing `permissions` key is unknown, not confirmed write access. |
| GHAT-003 | Untrusted expression in command interpreter | Flags untrusted `${{ }}` expressions interpolated into `run:`. Values passed only through `env` are not this finding. Moving a value to `env` does not eliminate every injection case. |
| GHAT-004 | Privileged execution of pull request code | Flags `pull_request_target` only when attacker-controlled checkout and subsequent execution are both present. The trigger alone is not a confirmed vulnerability. |

`gha-threatlens explain RULE_ID` prints remediation and references.

## Risk and confidence

The 0–100 score is a prioritisation score, not an exploit probability and not CVSS. Dimensions: exposure (0–20), exploitability (0–30), privilege (0–20), impact (0–20), chain evidence (0–10), applicable mitigations (0 to −20). Severity bands: 0–19 informational, 20–39 low, 40–59 medium, 60–79 high, 80–100 critical.

Confidence is separate: HIGH for direct parsed structure, MEDIUM for one defensible heuristic, LOW for naming-only or incomplete knowledge. Non-high results explain the uncertainty.

See [docs/risk-model.md](docs/risk-model.md).

## Architecture summary

Discovery stays inside the resolved scan root. A YAML 1.2 round-trip parser produces a typed workflow IR. Rules emit findings and facts. Correlation is a later phase. Reporters consume one canonical `ScanResult`. Details: [docs/architecture.md](docs/architecture.md).

## Privacy and token requirements

- Local scans require no GitHub token.
- Local scans make no network requests.
- Workflow content and evidence do not leave the local process.
- There is no telemetry.
- Remote private-repository access is out of scope for v0.1.0.

## Known limitations

- Repository, organisation, enterprise, fork, and Dependabot permission defaults are not visible from local YAML. Missing `permissions` stays unknown.
- Docker digest pinning is not analysed.
- Cache-poisoning and artefact-poisoning correlation are not implemented.
- Package manifests are not inspected; `npm test` after an attacker checkout is a heuristic execution sink (medium confidence).
- Organisation-wide scanning, GitHub Apps, OAuth, and automatic remote discovery are out of scope.
- The four rules do not cover every GitHub Actions weakness.
- SARIF output is tested for GitHub-required fields; the tool does not run a full OASIS schema validator.

## Development and verification

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/mypy src/gha_threatlens
.venv/bin/pytest --cov=gha_threatlens --cov-report=term-missing --cov-fail-under=90
.venv/bin/python -m build
.venv/bin/gha-threatlens --help
.venv/bin/gha-threatlens scan tests/fixtures/repositories/safe
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/rule-authoring.md](docs/rule-authoring.md).

## Security policy

See [SECURITY.md](SECURITY.md).

## Licence

MIT License. Copyright (c) 2026 Yusuf Dalbudak. See [LICENSE](LICENSE).
