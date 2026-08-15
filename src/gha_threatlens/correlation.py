"""Restrained attack-path correlation for the v0.1.0 pull_request_target chain."""

from __future__ import annotations

from collections import defaultdict

from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    AttackPath,
    AttackPathNode,
    Confidence,
    Fact,
    FactKind,
    Finding,
    WorkflowIR,
)
from gha_threatlens.scoring import confidence_rationale, severity_from_score


def correlate(
    workflows: tuple[WorkflowIR, ...], findings: tuple[Finding, ...], facts: tuple[Fact, ...]
) -> tuple[AttackPath, ...]:
    by_job: dict[tuple[str, str], list[Fact]] = defaultdict(list)
    for fact in facts:
        if fact.job_id is None:
            continue
        by_job[(fact.workflow_path, fact.job_id)].append(fact)

    workflow_by_path = {item.path: item for item in workflows}
    finding_by_fp = {item.fingerprint: item for item in findings}
    paths: list[AttackPath] = []
    seen: set[str] = set()

    for (path, job_id), job_facts in sorted(by_job.items()):
        kinds = {item.kind for item in job_facts}
        required = {
            FactKind.PRIVILEGED_PR_TARGET,
            FactKind.ATTACKER_CHECKOUT,
            FactKind.EXECUTION_AFTER_CHECKOUT,
        }
        if not required.issubset(kinds):
            continue

        workflow = workflow_by_path.get(path)
        if workflow is None:
            continue
        job = next((item for item in workflow.jobs if item.job_id == job_id), None)
        if job is None:
            continue

        checkout = _first(job_facts, FactKind.ATTACKER_CHECKOUT)
        execution = _first(job_facts, FactKind.EXECUTION_AFTER_CHECKOUT)
        privilege = _first(job_facts, FactKind.REACHABLE_PRIVILEGE)
        trigger = _first(job_facts, FactKind.PRIVILEGED_PR_TARGET)
        if checkout is None or execution is None or trigger is None:
            continue

        related = [
            item
            for item in (
                trigger.finding_fingerprint,
                checkout.finding_fingerprint,
                execution.finding_fingerprint,
            )
            if item
        ]
        related = list(dict.fromkeys(related))
        primary = finding_by_fp.get(execution.finding_fingerprint or "")
        if primary is None and related:
            primary = finding_by_fp.get(related[0])
        if primary is None:
            continue

        heuristic = execution.details.get("heuristic") == "true"
        confidence = Confidence.MEDIUM if heuristic else Confidence.HIGH
        score = primary.score
        severity = severity_from_score(score.total)
        path_fp = fingerprint("path", path, job_id, *(related or [primary.fingerprint]))
        if path_fp in seen:
            continue
        seen.add(path_fp)

        nodes = (
            AttackPathNode(
                label="External or fork-controlled pull request",
                fact_kind=None,
                evidence=trigger.evidence,
                edge_reason="pull_request_target accepts pull requests, including from forks.",
            ),
            AttackPathNode(
                label="Privileged pull_request_target workflow",
                fact_kind=FactKind.PRIVILEGED_PR_TARGET,
                evidence=trigger.evidence,
                edge_reason="The workflow lists pull_request_target, which runs in the base repository context.",
            ),
            AttackPathNode(
                label="Attacker-controlled head checkout",
                fact_kind=FactKind.ATTACKER_CHECKOUT,
                evidence=checkout.evidence,
                edge_reason="actions/checkout is given a pull request head ref, SHA, or fork repository.",
            ),
            AttackPathNode(
                label="Checked-out code execution",
                fact_kind=FactKind.EXECUTION_AFTER_CHECKOUT,
                evidence=execution.evidence,
                edge_reason=(
                    "A later step runs a local script or interpreter against the checkout."
                    if not heuristic
                    else "A later step runs a package-manager or build command that commonly executes repository scripts."
                ),
                heuristic=heuristic,
            ),
            AttackPathNode(
                label="Reachable privilege or sensitive asset",
                fact_kind=FactKind.REACHABLE_PRIVILEGE,
                evidence=privilege.evidence if privilege else primary.evidence,
                edge_reason=(
                    "The job has explicit write scopes, secrets, OIDC, unknown defaults, or a self-hosted runner."
                ),
            ),
        )

        paths.append(
            AttackPath(
                path_id=f"PATH-{path_fp}",
                nodes=nodes,
                finding_ids=tuple(related),
                entry_point="pull_request_target from a fork or external contributor",
                execution_point=execution.details.get("sink", "execution"),
                affected_asset="repository contents, token, and reachable secrets",
                preconditions=(
                    "An untrusted actor can open or update a pull request.",
                    "The workflow uses pull_request_target.",
                    "The job checks out the pull request head.",
                    "A later step executes checked-out content.",
                ),
                severity=severity,
                confidence=confidence,
                confidence_rationale=confidence_rationale(
                    confidence,
                    "Direct local script execution after attacker checkout."
                    if not heuristic
                    else "Execution sink is a build or package-manager heuristic; package manifests were not inspected.",
                ),
                narrative=(
                    "External pull request -> privileged pull_request_target workflow -> "
                    "attacker-controlled head checkout -> checked-out code execution -> "
                    "reachable token privilege."
                ),
                remediation=primary.remediation,
                score=score,
                fingerprint=path_fp,
                location=primary.location,
            )
        )

    paths.sort(key=lambda item: (item.location.path, item.location.start_line, item.fingerprint))
    return tuple(paths)


def missing_edges(facts: tuple[Fact, ...], workflow_path: str, job_id: str) -> tuple[str, ...]:
    kinds = {
        item.kind for item in facts if item.workflow_path == workflow_path and item.job_id == job_id
    }
    missing: list[str] = []
    if FactKind.PRIVILEGED_PR_TARGET not in kinds:
        missing.append("pull_request_target trigger")
    if FactKind.ATTACKER_CHECKOUT not in kinds:
        missing.append("attacker-controlled checkout")
    if FactKind.EXECUTION_AFTER_CHECKOUT not in kinds:
        missing.append("execution after checkout")
    return tuple(missing)


def _first(facts: list[Fact], kind: FactKind) -> Fact | None:
    for item in facts:
        if item.kind is kind:
            return item
    return None
