# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-16

### Added

- Offline CLI `gha-threatlens` with `scan`, `rules list`, `explain`, and `version`.
- Discovery of `.github/workflows/*.yml` and `*.yaml` confined to the scan root, with a 1 MiB size limit and symlink escape rejection.
- YAML 1.2 parser that preserves locations and treats `on` as a string.
- Trust catalogue for GitHub Actions events and selected `github.*` fields.
- `GITHUB_TOKEN` permission model with explicit unknown/default state.
- Rules GHAT-001 (mutable action and reusable-workflow Git refs), GHAT-002 (excessive token permissions), GHAT-003 (untrusted expressions in `run:`), and GHAT-004 (privileged pull-request code execution).
- Attack-path correlation for the complete `pull_request_target` checkout-and-execute chain.
- Prioritisation scoring (0–100) with machine-readable breakdowns; confidence reported separately.
- Terminal, JSON, Markdown, and SARIF 2.1.0 reporters.
- Fixture corpus, golden JSON for the safe repository, and CI on Python 3.11–3.13.
- PEP 639 licence metadata (`license = "MIT"` with `license-files`).
