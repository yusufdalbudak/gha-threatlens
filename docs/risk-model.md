# Risk model

The 0–100 total is a **prioritisation score**. It ranks which findings to inspect first. It is not a predicted probability of exploitation, not a likelihood, and not CVSS. CVSS measures vulnerability severity for software defects under a different set of metrics; workflow configuration risk does not map onto those metrics without invention.

## Formula

```
score = clamp(
    exposure
    + exploitability
    + privilege
    + impact
    + chain_evidence
    - applicable_mitigations,
    0,
    100,
)
```

Each dimension is clamped to its documented range before the human-readable breakdown is emitted. The total is clamped to 0–100.

## Dimensions

| Dimension | Range | Meaning | Starting calibration |
| --- | --- | --- | --- |
| Exposure | 0–20 | Who can reach or trigger the path | Public or external trigger: 20. Actor-dependent input: 10. Collaborator-influenceable: 8. Maintainer: 4. Unknown: 10. |
| Exploitability | 0–30 | Whether controlled input reaches executable behaviour | Direct interpreter interpolation or attacker-controlled code execution: 30. Heuristic execution (`npm test`, `make`, …): 18. Mutable Git ref alone: 8 (10 in release/deploy jobs). Broad permissions alone: 6. |
| Privilege | 0–20 | Reachable token, secret, OIDC, or runner privilege | `write-all`: 20. Explicit high-impact write: 16. Other explicit write: 10. Missing/unknown permissions: 8. Read or none: 4. OIDC (`id-token: write`), visible `secrets.*`, or self-hosted runner may add up to 4 each, capped at 20. |
| Impact | 0–20 | Consequence for repository, package, release, or deployment | Release/deploy or `write-all` with contents/packages: 20. `contents: write`: 16. Packages or OIDC: 16. Visible secrets: 12. Unknown defaults: 10. Other writes: 10. Read-level: 6. |
| Chain evidence | 0–10 | Strength and directness of the observed path | Direct AST/data-flow: 10 (expression in `run:`) or 8 (explicit `uses:` / `permissions:`). Heuristic command family: 4. |
| Applicable mitigations | 0 to −20 | Controls that actually constrain this path | `persist-credentials: false` on the attacker checkout: 8. A mitigation is applied only to a path it constrains. |

The same condition is not counted twice as both privilege and impact when the notes describe different questions (capability vs consequence), but a missing execution edge is never compensated with extra points to reach Critical.

## Severity mapping

| Total | Severity |
| --- | --- |
| 0–19 | Informational |
| 20–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

## Guardrails

Documented overrides, tested in `tests/unit/test_scoring.py`:

- GHAT-001 in a job classified as `test`: severity is capped at medium even if the numeric total would map to high.
- GHAT-002 in a `test` job: critical is lowered to high.

Guardrails change the displayed severity, not the numeric breakdown.

## Confidence (separate from score)

| Level | Meaning |
| --- | --- |
| HIGH | Confirmed by parsed structure and explicit data or control flow. |
| MEDIUM | Strong contextual correlation with one defensible heuristic. |
| LOW | Incomplete cross-file knowledge, naming heuristics, or ambiguous execution semantics. |

Every non-high result includes a rationale string. Confidence is not folded into the 0–100 total.

Examples:

- Untrusted `${{ github.event.issue.title }}` inside `run:`: HIGH for GHAT-003.
- `npm test` after attacker-controlled checkout: MEDIUM for GHAT-004 execution, unless a later release inspects `package.json`.
- A step named `deploy` with no observable deploy action: must not by itself create high impact.

## Worked examples (fixture calibration)

Values below are the model’s starting principles as implemented in `src/gha_threatlens/scoring.py`. Tests lock the function behaviour; exact totals for a full workflow also depend on declared permissions and job purpose.

### Direct privileged PR chain

Fixture: `tests/fixtures/vulnerable/pr_target_chain.yml`.

- Exposure 20 (external `pull_request_target`)
- Exploitability 30 (`./scripts/test.sh`)
- Privilege 16 (`contents: write`)
- Impact 16 (repository tampering)
- Chain 10
- Mitigations 0
- Total 92 → Critical, HIGH confidence

### Heuristic execution after attacker checkout

`npm test` instead of a local script: exploitability 18, chain 4. With the same privilege and impact, total 74 → High, MEDIUM confidence.

### Incomplete chain

`pull_request_target` with base checkout and no attacker execution: no GHAT-004 finding and no attack path. The model does not award Critical for the trigger alone.

### Mutable tag in a low-privilege test job

Push trigger (maintainer exposure 4), `contents: read` (privilege 4, impact 6), mutable `uses:` (exploitability 8, chain 8) → 30 Low. A release job with write scopes scores higher.

### Issue-title interpolation

Public issue trigger (20) + direct `run:` interpolation (30) + read token (4 + 6) + chain 10 → 70 High.

## Mitigation rules

- Apply a mitigation only when it constrains the path under analysis.
- `persist-credentials: false` reduces token reuse from the checkout directory; it does not remove code execution.
- Passing a value through `env` is not modelled as a GHAT-003 mitigation because GHAT-003 does not fire for `env:` interpolation. Unsafe later expansion remains possible and is documented in remediation text.

## Limitations

- Offline YAML cannot see repository default permissions, environment protection rules, or required reviewers.
- Self-hosted detection is label-based (`self-hosted` or non-GitHub-hosted names).
- Secrets are visible only when `secrets.` appears in step `run`, `env`, or `with` values.
- OIDC is visible only as `id-token: write`.

## Calibration method

Factors are defined in `scoring.py` and exercised by `tests/unit/test_scoring.py` plus the fixture corpus under `tests/fixtures/`. Adjustments must change both the documented table and the tests. Do not tune scores against unpublished examples hidden in rule bodies.
