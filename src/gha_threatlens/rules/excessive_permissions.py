"""GHAT-002: clearly excessive GITHUB_TOKEN permission declarations."""

from __future__ import annotations

from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Fact,
    FactKind,
    Finding,
    JobIR,
    JobPurpose,
    PermissionPreset,
    PermissionSet,
    TrustLevel,
    WorkflowIR,
)
from gha_threatlens.parser import excerpt_at
from gha_threatlens.permissions import HIGH_IMPACT_WRITE_SCOPES
from gha_threatlens.rules.base import Rule, load_rule_spec
from gha_threatlens.scoring import (
    apply_severity_guardrail,
    confidence_rationale,
    excessive_permission_score,
    highest_trigger_trust,
    severity_from_score,
)


class ExcessivePermissionsRule(Rule):
    spec = load_rule_spec("GHAT-002")

    def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]:
        findings: list[Finding] = []
        facts: list[Fact] = []
        trust = highest_trigger_trust(tuple(trigger.trust_level for trigger in workflow.triggers))

        workflow_finding = _evaluate_set(
            workflow=workflow,
            job=None,
            permissions=workflow.permissions,
            trust=trust,
            purpose=JobPurpose.UNKNOWN,
            component=workflow.path,
        )
        if workflow_finding is not None:
            findings.append(workflow_finding)

        for job in workflow.jobs:
            if not job.permissions.declared:
                continue
            finding = _evaluate_set(
                workflow=workflow,
                job=job,
                permissions=job.permissions,
                trust=trust,
                purpose=job.purpose,
                component=f"{workflow.path}:{job.job_id}",
            )
            if finding is None:
                continue
            findings.append(finding)
            facts.append(
                Fact(
                    kind=FactKind.EXCESSIVE_PERMISSION,
                    workflow_path=workflow.path,
                    job_id=job.job_id,
                    step_index=None,
                    evidence=finding.evidence,
                    details={"preset": job.permissions.preset.value},
                    confidence=Confidence.HIGH,
                    finding_fingerprint=finding.fingerprint,
                )
            )

        findings.sort(
            key=lambda item: (item.location.path, item.location.start_line, item.fingerprint)
        )
        return tuple(findings), tuple(facts)


def _evaluate_set(
    *,
    workflow: WorkflowIR,
    job: JobIR | None,
    permissions: PermissionSet,
    trust: TrustLevel,
    purpose: JobPurpose,
    component: str,
) -> Finding | None:
    if permissions.preset is PermissionPreset.UNSET:
        return None
    if permissions.preset is PermissionPreset.EMPTY:
        return None
    if permissions.preset is PermissionPreset.READ_ALL:
        return None

    write_all = permissions.preset is PermissionPreset.WRITE_ALL
    high_writes = [
        scope
        for scope in permissions.write_scopes()
        if scope in HIGH_IMPACT_WRITE_SCOPES or scope == "write-all"
    ]
    if not write_all and not high_writes:
        return None

    spec = ExcessivePermissionsRule.spec
    location = permissions.location or workflow.location
    excerpt = excerpt_at(workflow.raw_text, location)
    score = excessive_permission_score(
        trust=trust,
        permissions=permissions,
        purpose=purpose,
        write_all=write_all,
    )
    score, severity = apply_severity_guardrail(score, purpose=purpose, rule_id="GHAT-002")
    if write_all and purpose in {JobPurpose.RELEASE, JobPurpose.DEPLOY}:
        severity = max(severity, severity_from_score(80), key=lambda item: item.rank)

    if write_all:
        description = (
            "The workflow declares `permissions: write-all`, granting write access "
            "to every available GITHUB_TOKEN scope. This is broader than almost any "
            "single job requires."
        )
        source = "permissions: write-all"
    else:
        description = (
            "The workflow declares high-impact GITHUB_TOKEN write scopes "
            f"({', '.join(high_writes)}). Write access can be appropriate for a "
            "publish job; the finding records breadth, not a proven lack of necessity."
        )
        source = ",".join(high_writes)

    if purpose is JobPurpose.RELEASE:
        description += " The job appears to be a release or publish job, which may legitimately need write access."

    return Finding(
        rule_id=spec.rule_id,
        title=spec.title,
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        confidence_rationale=confidence_rationale(
            Confidence.HIGH,
            "The permissions key is explicit in the workflow YAML.",
        ),
        evidence=(Evidence(excerpt=excerpt, location=location, kind=EvidenceKind.PERMISSION),),
        affected_component=component,
        source=source,
        sink="GITHUB_TOKEN",
        impact="A compromised job can use a broader token than the task requires.",
        remediation=spec.remediation.strip(),
        references=spec.references,
        score=score,
        fingerprint=fingerprint(spec.rule_id, workflow.path, component, source),
        location=location,
        category=spec.category,
        cwe_ids=spec.cwe_ids,
    )
