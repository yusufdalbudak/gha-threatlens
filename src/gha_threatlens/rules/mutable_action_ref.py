"""GHAT-001: remote action or reusable workflow not pinned to a full commit SHA."""

from __future__ import annotations

from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    ActionRef,
    ActionRefKind,
    Confidence,
    Evidence,
    EvidenceKind,
    Fact,
    FactKind,
    Finding,
    JobIR,
    JobPurpose,
    PermissionSet,
    SourceLocation,
    StepIR,
    TrustLevel,
    WorkflowIR,
)
from gha_threatlens.parser import excerpt_at
from gha_threatlens.permissions import effective_job_permissions
from gha_threatlens.rules.base import Rule, load_rule_spec
from gha_threatlens.scoring import (
    apply_severity_guardrail,
    confidence_rationale,
    highest_trigger_trust,
    mutable_action_score,
)


class MutableActionRefRule(Rule):
    spec = load_rule_spec("GHAT-001")

    def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]:
        findings: list[Finding] = []
        facts: list[Fact] = []
        trust = highest_trigger_trust(tuple(trigger.trust_level for trigger in workflow.triggers))
        for job in workflow.jobs:
            permissions = effective_job_permissions(workflow.permissions, job.permissions)
            if (
                job.reusable_workflow is not None
                and job.reusable_workflow.kind
                in {ActionRefKind.REUSABLE_WORKFLOW, ActionRefKind.GITHUB}
                and not job.reusable_workflow.is_immutable_sha
            ):
                finding = _finding(
                    workflow, job, job.reusable_workflow, job.location, permissions, trust
                )
                findings.append(finding)
                facts.append(_fact(workflow, job, None, finding, job.reusable_workflow))
            for step in job.steps:
                if step.uses is None:
                    continue
                if step.uses.kind in {
                    ActionRefKind.LOCAL,
                    ActionRefKind.DOCKER,
                    ActionRefKind.UNKNOWN,
                }:
                    continue
                if step.uses.is_immutable_sha:
                    continue
                finding = _finding(workflow, job, step.uses, step.location, permissions, trust)
                findings.append(finding)
                facts.append(_fact(workflow, job, step, finding, step.uses))
        findings.sort(
            key=lambda item: (item.location.path, item.location.start_line, item.fingerprint)
        )
        return tuple(findings), tuple(facts)


def _fact(
    workflow: WorkflowIR,
    job: JobIR,
    step: StepIR | None,
    finding: Finding,
    uses: ActionRef,
) -> Fact:
    return Fact(
        kind=FactKind.MUTABLE_ACTION,
        workflow_path=workflow.path,
        job_id=job.job_id,
        step_index=None if step is None else step.index,
        evidence=finding.evidence,
        details={"ref": uses.ref or "", "kind": uses.kind.value},
        confidence=Confidence.HIGH,
        finding_fingerprint=finding.fingerprint,
    )


def _finding(
    workflow: WorkflowIR,
    job: JobIR,
    uses: ActionRef,
    location: SourceLocation,
    permissions: PermissionSet,
    trust: TrustLevel,
) -> Finding:
    score, severity = apply_severity_guardrail(
        mutable_action_score(
            trust=trust,
            permissions=permissions,
            purpose=job.purpose,
            self_hosted=job.is_self_hosted,
        ),
        purpose=job.purpose,
        rule_id="GHAT-001",
    )
    spec = MutableActionRefRule.spec
    kind = uses.kind.value
    ref = uses.ref or "<missing ref>"
    excerpt = excerpt_at(workflow.raw_text, location)
    evidence = (Evidence(excerpt=excerpt, location=location, kind=EvidenceKind.USES),)
    description = (
        f"The {kind.replace('_', ' ')} reference `{uses.raw}` is not pinned to a full "
        f"40-character Git commit SHA (ref `{ref}`). Tags such as v4 and branch "
        "names such as main can be moved by the upstream maintainer or by an "
        "attacker who compromises the source repository."
    )
    if job.purpose is JobPurpose.TEST:
        description += " Severity is reduced because the job appears to be a test job."
    return Finding(
        rule_id=spec.rule_id,
        title=spec.title,
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        confidence_rationale=confidence_rationale(
            Confidence.HIGH,
            "The uses: value was parsed and the Git ref is not a 40-character hexadecimal SHA.",
        ),
        evidence=evidence,
        affected_component=f"{workflow.path}:{job.job_id}",
        source="mutable Git ref",
        sink="actions runtime resolution of uses:",
        impact=(
            "A retagged or force-pushed upstream ref can change the code that runs "
            "in this job, including any token permissions the job holds."
        ),
        remediation=spec.remediation.strip(),
        references=spec.references,
        score=score,
        fingerprint=fingerprint(spec.rule_id, workflow.path, str(location.start_line), uses.raw),
        location=location,
        category=spec.category,
        cwe_ids=spec.cwe_ids,
    )
