# Threat model

This document covers two related systems: GitHub Actions workflows under analysis, and GHA-ThreatLens itself.

## Assets (workflows under analysis)

- Repository contents and Git history.
- `GITHUB_TOKEN` scopes reachable to a job.
- Repository and organisation secrets referenced by a workflow.
- OIDC tokens (`id-token: write`) that can federate to cloud roles.
- Package registries, release artefacts, and deployment environments.
- Self-hosted runners and any credentials on those hosts.

## Trust boundaries

| Zone | Examples |
| --- | --- |
| Maintainer-controlled | `push` to a protected branch, workflow files on the default branch, `github.sha` of the base repository |
| Collaborator | Commit messages on branches collaborators can push |
| External / fork | `pull_request` and `pull_request_target` head refs, SHAs, titles, bodies |
| Public user | Issue titles/bodies, comments, discussion content |
| Actor-dependent | `workflow_dispatch` / `workflow_call` inputs, `repository_dispatch` payloads |
| Unknown | Events not in the catalogue; missing permission keys |

Checked-out fork content is untrusted even when the job runs in the base repository context.

## Attacker capabilities (workflow)

An untrusted actor may open or update a pull request, file an issue, comment, or (where enabled) dispatch a workflow. They cannot edit workflow files on the default branch unless they already have write access. `pull_request_target` runs with the base repository’s token and secrets while still allowing the workflow author to check out the head SHA.

## Entry points

- `pull_request_target` with head checkout.
- Untrusted GitHub expressions in `run:` scripts.
- Mutable third-party actions that can change without a SHA pin.
- Over-broad `GITHUB_TOKEN` write scopes combined with an untrusted trigger.

## Execution sinks

- Local scripts (`./scripts/…`).
- Interpreters invoked on repository files.
- Local actions (`uses: ./…`) after an untrusted checkout.
- Package-manager and build commands that run lifecycle scripts (heuristic).

## Assumptions

- The scan target is a directory the operator can read.
- Workflow YAML is the source of truth for local analysis.
- GitHub’s documented semantics for `pull_request_target`, `permissions`, and contexts hold.
- The operator does not expect organisation-wide or remote private-repository coverage in v0.1.0.

## Out of scope (v0.1.0)

- Cache poisoning and artefact poisoning.
- GitHub App / OAuth / organisation policy.
- Runtime exploitation of findings.
- Automatic workflow modification.
- Machine-learning classification.

## Scanner assets and abuse cases

Assets: the operator’s workflow files (sensitive comments, embedded secrets), scan reports, and the Python process.

Abuse cases:

- A hostile workflow file crafted to hang the parser (size limit, bounded regex).
- A symlink that points outside the scan root (skipped).
- Report injection via issue titles or script snippets (Markdown and terminal escaping).
- Tricking an operator into treating a prioritisation score as proof of exploitability (documented repeatedly as a non-goal).

The scanner does not execute workflow steps, does not evaluate shell, and does not expand `${{ }}`.

## Controls in the tool

- Offline by default; no token environment variables are consumed.
- YAML 1.2 round-trip load without arbitrary object tags.
- Path confinement to the resolved scan root.
- 1 MiB workflow size cap.
- Least-privilege CI for this repository (`contents: read`, no `pull_request_target`).
- No telemetry.
