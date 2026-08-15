"""GHAT-003: untrusted GitHub expressions interpolated into run: scripts."""

from __future__ import annotations

from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Fact,
    FactKind,
    Finding,
    WorkflowIR,
)
from gha_threatlens.parser import excerpt_at
from gha_threatlens.permissions import effective_job_permissions
from gha_threatlens.rules.base import Rule, load_rule_spec
from gha_threatlens.scoring import (
    confidence_rationale,
    expression_injection_score,
    severity_from_score,
)
from gha_threatlens.trust import classify_expression, extract_expressions, shell_remediation


class ExpressionInjectionRule(Rule):
    spec = load_rule_spec("GHAT-003")

    def evaluate(self, workflow: WorkflowIR) -> tuple[tuple[Finding, ...], tuple[Fact, ...]]:
        findings: list[Finding] = []
        facts: list[Fact] = []
        events = tuple(trigger.event_name for trigger in workflow.triggers)
        spec = self.spec

        for job in workflow.jobs:
            permissions = effective_job_permissions(workflow.permissions, job.permissions)
            for step in job.steps:
                if not step.run:
                    continue
                for expression in extract_expressions(step.run):
                    source = classify_expression(expression.inner, events)
                    if source is None:
                        continue
                    location = step.location
                    excerpt = excerpt_at(workflow.raw_text, location)
                    score = expression_injection_score(
                        trust=source.trust,
                        permissions=permissions,
                        purpose=job.purpose,
                        self_hosted=job.is_self_hosted,
                    )
                    severity = severity_from_score(score.total)
                    finding = Finding(
                        rule_id=spec.rule_id,
                        title=spec.title,
                        description=(
                            f"The expression `{expression.raw}` expands "
                            f"{source.label} directly into a `{step.shell.value}` "
                            "script. GitHub substitutes the expression before the "
                            "shell starts, so YAML quotes do not contain the value."
                        ),
                        severity=severity,
                        confidence=Confidence.HIGH,
                        confidence_rationale=confidence_rationale(
                            Confidence.HIGH,
                            "The untrusted expression appears in the run: script text, not only in env:.",
                        ),
                        evidence=(
                            Evidence(
                                excerpt=excerpt,
                                location=location,
                                kind=EvidenceKind.EXPRESSION,
                            ),
                        ),
                        affected_component=f"{workflow.path}:{job.job_id}#step-{step.index}",
                        source=source.field,
                        sink=f"{step.shell.value} interpreter",
                        impact="An untrusted actor can inject shell syntax into the job script.",
                        remediation=f"{spec.remediation.strip()} {shell_remediation(step.shell)}",
                        references=spec.references,
                        score=score,
                        fingerprint=fingerprint(
                            spec.rule_id,
                            workflow.path,
                            str(step.index),
                            expression.normalised,
                        ),
                        location=location,
                        category=spec.category,
                        cwe_ids=spec.cwe_ids,
                    )
                    findings.append(finding)
                    facts.append(
                        Fact(
                            kind=FactKind.UNTRUSTED_EXPRESSION,
                            workflow_path=workflow.path,
                            job_id=job.job_id,
                            step_index=step.index,
                            evidence=finding.evidence,
                            details={"expression": expression.raw, "source": source.field},
                            confidence=Confidence.HIGH,
                            finding_fingerprint=finding.fingerprint,
                        )
                    )

        findings.sort(
            key=lambda item: (item.location.path, item.location.start_line, item.fingerprint)
        )
        return tuple(findings), tuple(facts)
