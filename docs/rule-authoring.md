# Rule authoring

v0.1.0 ships exactly four rules. A new rule is a deliberate product change, not a drop-in plugin.

## Metadata

Authoritative metadata is YAML under `src/gha_threatlens/rules/metadata/ghat-00N.yml`. The Python class loads it through `load_rule_spec`. Do not duplicate titles or remediation in a second source.

Required fields:

| Field | Role |
| --- | --- |
| `id` | Stable identifier (`GHAT-00N`) |
| `title` | Short name |
| `summary` | One-sentence behaviour |
| `category` | `supply-chain`, `privileges`, `injection`, or `attack-path` |
| `default_severity` | Guidance only; scoring may override |
| `applicable` | IR node or analysis phase |
| `remediation` | Operator-facing fix; never an unverified SHA |
| `references` | Primary documentation URLs |
| `cwe_ids` | Only when the mapping is technically applicable |

## Implementation contract

Subclass `gha_threatlens.rules.base.Rule`:

```python
def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]: ...
```

Rules emit **findings** (user-visible) and **facts** (correlation input). Do not assemble a complete attack path inside a rule. Correlation in `correlation.py` is the only place that creates `AttackPath` objects.

Findings must include: rule ID, location, evidence excerpts, source/sink when known, impact, remediation, references, score breakdown, confidence, and a deterministic fingerprint.

## Evidence

Use `excerpt_at` on the workflow text and the IR location. Keep excerpts short. Do not log full untrusted payloads. Evidence kinds distinguish triggers, checkouts, commands, permissions, and action refs.

## Scoring

Call the functions in `scoring.py`. Do not invent ad hoc totals. If a guardrail is required, add it to `apply_severity_guardrail` with a test. Document the change in `docs/risk-model.md`.

## Fixtures and tests

Every rule needs:

1. Minimal positive fixture.
2. Realistic positive fixture.
3. Hardened negative fixture.
4. Near-miss fixture that must not be promoted to a confirmed vulnerability.

Assert location, severity band or relative rank, confidence, remediation content, and references. Correlation rules additionally need complete-chain, missing-edge, heuristic, and duplicate-fingerprint tests.

Place YAML under `tests/fixtures/{vulnerable,hardened,malformed}/`.

## Review criteria

- Does the rule describe what the YAML shows, or does it claim exploitation?
- Are unknown permissions left unknown?
- Is CWE used only when it applies (CWE-78 for command interpolation, not for every finding)?
- Are Docker tags distinguished from Git refs?
- Is `pull_request_target` alone left unflagged as a confirmed GHAT-004 path?
- Are fingerprints stable across identical rescans?
