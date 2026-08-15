## Summary

<!-- What changed and why. -->

## Test plan

- [ ] `ruff format --check .` and `ruff check .`
- [ ] `mypy src/gha_threatlens`
- [ ] `pytest --cov=gha_threatlens --cov-fail-under=90`
- [ ] `gha-threatlens scan tests/fixtures/repositories/safe` exits 0
- [ ] New or changed rules include positive, negative, and near-miss fixtures
