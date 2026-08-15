"""GHAT-004: privileged pull_request_target checkout of attacker-controlled code."""

from __future__ import annotations

from gha_threatlens.execution import (
    ExecutionSink,
    classify_execution,
    persist_credentials,
    uses_secrets,
)
from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Fact,
    FactKind,
    Finding,
    JobIR,
    PermissionSet,
    StepIR,
    WorkflowIR,
)
from gha_threatlens.parser import excerpt_at
from gha_threatlens.permissions import effective_job_permissions, has_high_impact_write
from gha_threatlens.rules.base import Rule, load_rule_spec
from gha_threatlens.scoring import confidence_rationale, pr_chain_score, severity_from_score
from gha_threatlens.trust import (
    extract_expressions,
    is_pr_head_checkout_expression,
    is_pr_head_repository_expression,
)


class DangerousPrTargetRule(Rule):
    spec = load_rule_spec("GHAT-004")

    def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]:
        if not _has_pull_request_target(workflow):
            return (), ()

        findings: list[Finding] = []
        facts: list[Fact] = []
        trigger = next(
            item for item in workflow.triggers if item.event_name == "pull_request_target"
        )
        trigger_evidence = Evidence(
            excerpt=excerpt_at(workflow.raw_text, trigger.location),
            location=trigger.location,
            kind=EvidenceKind.TRIGGER,
        )

        for job in workflow.jobs:
            permissions = effective_job_permissions(workflow.permissions, job.permissions)
            checkouts = _attacker_checkouts(workflow, job)
            if not checkouts:
                continue
            for checkout in checkouts:
                facts.append(
                    Fact(
                        kind=FactKind.ATTACKER_CHECKOUT,
                        workflow_path=workflow.path,
                        job_id=job.job_id,
                        step_index=checkout.index,
                        evidence=(
                            trigger_evidence,
                            Evidence(
                                excerpt=excerpt_at(workflow.raw_text, checkout.location),
                                location=checkout.location,
                                kind=EvidenceKind.CHECKOUT,
                            ),
                        ),
                        details={"ref": checkout.inputs.get("ref", "")},
                        confidence=Confidence.HIGH,
                    )
                )
                execution = _execution_after(workflow, job, checkout)
                if execution is None:
                    continue
                step, sink = execution
                secrets = any(uses_secrets(item) for item in job.steps)
                oidc = permissions.has_explicit_write("id-token")
                persist = persist_credentials(checkout)
                score = pr_chain_score(
                    permissions=permissions,
                    purpose=job.purpose,
                    execution_direct=not sink.heuristic,
                    secrets_visible=secrets,
                    oidc=oidc,
                    self_hosted=job.is_self_hosted,
                    persist_credentials=persist,
                )
                severity = severity_from_score(score.total)
                confidence = sink.confidence
                spec = self.spec
                evidence = (
                    trigger_evidence,
                    Evidence(
                        excerpt=excerpt_at(workflow.raw_text, checkout.location),
                        location=checkout.location,
                        kind=EvidenceKind.CHECKOUT,
                    ),
                    Evidence(
                        excerpt=excerpt_at(workflow.raw_text, step.location),
                        location=step.location,
                        kind=EvidenceKind.RUN if step.run else EvidenceKind.USES,
                    ),
                )
                finding = Finding(
                    rule_id=spec.rule_id,
                    title=spec.title,
                    description=(
                        "A pull_request_target workflow checks out attacker-controlled "
                        "pull request code and later executes repository content. "
                        "pull_request_target runs in the base repository context, so "
                        "the job token and secrets are those of the target repository."
                    ),
                    severity=severity,
                    confidence=confidence,
                    confidence_rationale=confidence_rationale(confidence, sink.summary),
                    evidence=evidence,
                    affected_component=f"{workflow.path}:{job.job_id}",
                    source="github.event.pull_request.head",
                    sink=sink.kind,
                    impact=_impact_text(permissions, secrets, oidc, job.is_self_hosted),
                    remediation=spec.remediation.strip(),
                    references=spec.references,
                    score=score,
                    fingerprint=fingerprint(
                        spec.rule_id,
                        workflow.path,
                        job.job_id,
                        str(checkout.index),
                        str(step.index),
                    ),
                    location=checkout.location,
                    category=spec.category,
                    cwe_ids=spec.cwe_ids,
                )
                findings.append(finding)
                facts.append(
                    Fact(
                        kind=FactKind.EXECUTION_AFTER_CHECKOUT,
                        workflow_path=workflow.path,
                        job_id=job.job_id,
                        step_index=step.index,
                        evidence=evidence,
                        details={"sink": sink.kind, "heuristic": str(sink.heuristic).lower()},
                        confidence=confidence,
                        finding_fingerprint=finding.fingerprint,
                    )
                )
                facts.append(
                    Fact(
                        kind=FactKind.PRIVILEGED_PR_TARGET,
                        workflow_path=workflow.path,
                        job_id=job.job_id,
                        step_index=None,
                        evidence=(trigger_evidence,),
                        details={"event": "pull_request_target"},
                        confidence=Confidence.HIGH,
                        finding_fingerprint=finding.fingerprint,
                    )
                )
                facts.append(
                    Fact(
                        kind=FactKind.REACHABLE_PRIVILEGE,
                        workflow_path=workflow.path,
                        job_id=job.job_id,
                        step_index=None,
                        evidence=(
                            Evidence(
                                excerpt=excerpt_at(
                                    workflow.raw_text,
                                    permissions.location or workflow.location,
                                ),
                                location=permissions.location or workflow.location,
                                kind=EvidenceKind.PERMISSION,
                            ),
                        ),
                        details={
                            "preset": permissions.preset.value,
                            "secrets": str(secrets).lower(),
                            "oidc": str(oidc).lower(),
                        },
                        confidence=Confidence.HIGH,
                        finding_fingerprint=finding.fingerprint,
                    )
                )

        findings.sort(
            key=lambda item: (item.location.path, item.location.start_line, item.fingerprint)
        )
        return tuple(findings), tuple(facts)


def _has_pull_request_target(workflow: WorkflowIR) -> bool:
    return any(trigger.event_name == "pull_request_target" for trigger in workflow.triggers)


def _attacker_checkouts(workflow: WorkflowIR, job: JobIR) -> tuple[StepIR, ...]:
    found: list[StepIR] = []
    for step in job.steps:
        if step.uses is None:
            continue
        repo = f"{step.uses.owner}/{step.uses.repository}".lower() if step.uses.owner else ""
        if repo != "actions/checkout":
            continue
        ref = step.inputs.get("ref", "")
        repository = step.inputs.get("repository", "")
        expressions = extract_expressions(ref) + extract_expressions(repository)
        if any(is_pr_head_checkout_expression(item.inner) for item in extract_expressions(ref)):
            found.append(step)
            continue
        if any(
            is_pr_head_repository_expression(item.inner) for item in extract_expressions(repository)
        ):
            found.append(step)
            continue
        if expressions and any(
            is_pr_head_checkout_expression(item.inner)
            or is_pr_head_repository_expression(item.inner)
            for item in expressions
        ):
            found.append(step)
    return tuple(found)


def _execution_after(
    workflow: WorkflowIR,
    job: JobIR,
    checkout: StepIR,
) -> tuple[StepIR, ExecutionSink] | None:
    checkout_path = checkout.inputs.get("path")
    for step in job.steps:
        if step.index <= checkout.index:
            continue
        sink = classify_execution(step, checkout_path)
        if sink is not None:
            return step, sink
    return None


def _impact_text(permissions: PermissionSet, secrets: bool, oidc: bool, self_hosted: bool) -> str:
    parts = ["Attacker-controlled code runs in the base repository's pull_request_target context."]
    if has_high_impact_write(permissions) or permissions.write_scopes():
        parts.append(
            "Reachable write permissions can modify the repository, packages, or deployments."
        )
    elif permissions.preset.value == "unset":
        parts.append(
            "Token defaults are unknown from local YAML; impact is not assumed to be zero."
        )
    if secrets:
        parts.append("The job references secrets.")
    if oidc:
        parts.append("id-token write enables OIDC federation.")
    if self_hosted:
        parts.append("A self-hosted runner increases the blast radius.")
    return " ".join(parts)
