# Examples

The `examples/` tree is illustrative. Automated assertions use `tests/fixtures/`.

## Vulnerable

`examples/vulnerable/.github/workflows/pr-target.yml` is a complete GHAT-004 chain: `pull_request_target`, head SHA checkout, local script, `contents: write`.

`examples/vulnerable/.github/workflows/issue-echo.yml` interpolates `github.event.issue.title` into `run:` (GHAT-003). The missing `permissions` key is unknown, not assumed write.

Scan:

```bash
gha-threatlens scan examples/vulnerable --format markdown
```

## Hardened

`examples/hardened/.github/workflows/ci.yml` pins `actions/checkout` and `actions/setup-python` to verified commit SHAs, declares `contents: read`, and does not interpolate untrusted expressions into the shell.

```bash
gha-threatlens scan examples/hardened --no-color
```

## Fixture corpus

| Path | Purpose |
| --- | --- |
| `tests/fixtures/vulnerable/mutable_action_minimal.yml` | GHAT-001 tag pin |
| `tests/fixtures/vulnerable/pr_target_chain.yml` | Complete attack path |
| `tests/fixtures/vulnerable/pr_target_heuristic.yml` | Medium-confidence execution |
| `tests/fixtures/hardened/pr_target_base_checkout.yml` | Trigger without attacker checkout |
| `tests/fixtures/hardened/pr_target_checkout_no_exec.yml` | Checkout without execution |
| `tests/fixtures/hardened/env_not_run_interpolation.yml` | Untrusted value in `env:` only |
| `tests/fixtures/hardened/near_miss_docker_tag.yml` | Docker tag is not a Git ref |
| `tests/fixtures/repositories/safe` | Scenario A: no high or critical findings |
| `tests/fixtures/repositories/empty` | No workflows |
| `tests/fixtures/repositories/malformed` | Diagnostics without a crash |
