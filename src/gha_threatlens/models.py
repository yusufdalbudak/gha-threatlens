"""Immutable domain objects for workflow IR, findings, and scan results."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from gha_threatlens.constants import SCHEMA_VERSION, TOOL_NAME


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TrustLevel(StrEnum):
    MAINTAINER = "maintainer"
    COLLABORATOR = "collaborator"
    EXTERNAL = "external"
    PUBLIC_USER = "public_user"
    ACTOR_DEPENDENT = "actor_dependent"
    UNKNOWN = "unknown"


class PermissionAccess(StrEnum):
    UNSET = "unset"
    NONE = "none"
    READ = "read"
    WRITE = "write"
    UNKNOWN = "unknown"


class PermissionPreset(StrEnum):
    UNSET = "unset"
    READ_ALL = "read-all"
    WRITE_ALL = "write-all"
    EXPLICIT = "explicit"
    EMPTY = "empty"


class ActionRefKind(StrEnum):
    GITHUB = "github"
    LOCAL = "local"
    DOCKER = "docker"
    REUSABLE_WORKFLOW = "reusable_workflow"
    UNKNOWN = "unknown"


class EvidenceKind(StrEnum):
    TRIGGER = "trigger"
    CHECKOUT = "checkout"
    RUN = "run"
    USES = "uses"
    PERMISSION = "permission"
    EXPRESSION = "expression"
    ENV = "env"
    RUNNER = "runner"
    SECRET = "secret"
    CONDITION = "condition"


class DiagnosticKind(StrEnum):
    PARSE_ERROR = "parse_error"
    UNREADABLE = "unreadable"
    SIZE_LIMIT = "size_limit"
    SYMLINK_SKIPPED = "symlink_skipped"
    UNSUPPORTED = "unsupported"
    WARNING = "warning"


class ShellKind(StrEnum):
    BASH = "bash"
    SH = "sh"
    POWERSHELL = "powershell"
    PWSH = "pwsh"
    CMD = "cmd"
    PYTHON = "python"
    UNKNOWN = "unknown"


class JobPurpose(StrEnum):
    TEST = "test"
    BUILD = "build"
    RELEASE = "release"
    DEPLOY = "deploy"
    UNKNOWN = "unknown"


class FactKind(StrEnum):
    PRIVILEGED_PR_TARGET = "privileged_pr_target"
    ATTACKER_CHECKOUT = "attacker_checkout"
    EXECUTION_AFTER_CHECKOUT = "execution_after_checkout"
    REACHABLE_PRIVILEGE = "reachable_privilege"
    MUTABLE_ACTION = "mutable_action"
    EXCESSIVE_PERMISSION = "excessive_permission"
    UNTRUSTED_EXPRESSION = "untrusted_expression"


class ReportFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


@dataclass(frozen=True)
class SourceLocation:
    path: str
    start_line: int
    start_column: int
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, int | str | None]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(frozen=True)
class Evidence:
    excerpt: str
    location: SourceLocation
    kind: EvidenceKind

    def to_dict(self) -> dict[str, object]:
        return {
            "excerpt": self.excerpt,
            "kind": self.kind.value,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True)
class Reference:
    title: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return {"title": self.title, "url": self.url}


@dataclass(frozen=True)
class ScoreBreakdown:
    """Prioritisation score components. Totals are not exploit probabilities."""

    exposure: int
    exploitability: int
    privilege: int
    impact: int
    chain_evidence: int
    applicable_mitigations: int
    total: int
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "exposure": self.exposure,
            "exploitability": self.exploitability,
            "privilege": self.privilege,
            "impact": self.impact,
            "chain_evidence": self.chain_evidence,
            "applicable_mitigations": self.applicable_mitigations,
            "total": self.total,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class PermissionSet:
    """GITHUB_TOKEN permission declaration as visible in local YAML.

    Missing keys are UNSET, not write. Repository, organisation, and enterprise
    defaults are not visible to an offline scan and remain UNKNOWN.
    """

    preset: PermissionPreset
    scopes: Mapping[str, PermissionAccess] = field(default_factory=dict)
    declared: bool = False
    location: SourceLocation | None = None

    def access_for(self, scope: str) -> PermissionAccess:
        if self.preset is PermissionPreset.WRITE_ALL:
            return PermissionAccess.WRITE
        if self.preset is PermissionPreset.READ_ALL:
            return PermissionAccess.READ
        if self.preset is PermissionPreset.EMPTY:
            return PermissionAccess.NONE
        if self.preset is PermissionPreset.UNSET:
            return PermissionAccess.UNKNOWN
        return self.scopes.get(scope, PermissionAccess.NONE)

    def has_explicit_write(self, scope: str) -> bool:
        return self.access_for(scope) is PermissionAccess.WRITE

    def write_scopes(self) -> tuple[str, ...]:
        if self.preset is PermissionPreset.WRITE_ALL:
            return ("write-all",)
        if self.preset in {
            PermissionPreset.UNSET,
            PermissionPreset.READ_ALL,
            PermissionPreset.EMPTY,
        }:
            return ()
        return tuple(
            sorted(name for name, access in self.scopes.items() if access is PermissionAccess.WRITE)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "preset": self.preset.value,
            "declared": self.declared,
            "scopes": {name: access.value for name, access in sorted(self.scopes.items())},
        }


@dataclass(frozen=True)
class ActionRef:
    raw: str
    kind: ActionRefKind
    owner: str | None = None
    repository: str | None = None
    path: str | None = None
    ref: str | None = None
    is_immutable_sha: bool = False
    docker_image: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "kind": self.kind.value,
            "owner": self.owner,
            "repository": self.repository,
            "path": self.path,
            "ref": self.ref,
            "is_immutable_sha": self.is_immutable_sha,
            "docker_image": self.docker_image,
        }


@dataclass(frozen=True)
class TriggerIR:
    event_name: str
    configuration: Mapping[str, object]
    trust_level: TrustLevel
    location: SourceLocation

    def to_dict(self) -> dict[str, object]:
        return {
            "event_name": self.event_name,
            "trust_level": self.trust_level.value,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True)
class StepIR:
    index: int
    name: str | None
    uses: ActionRef | None
    run: str | None
    shell: ShellKind
    environment: Mapping[str, str]
    inputs: Mapping[str, str]
    location: SourceLocation
    if_condition: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "name": self.name,
            "uses": None if self.uses is None else self.uses.to_dict(),
            "run": self.run,
            "shell": self.shell.value,
            "environment": dict(self.environment),
            "inputs": dict(self.inputs),
            "location": self.location.to_dict(),
            "if": self.if_condition,
        }


@dataclass(frozen=True)
class JobIR:
    job_id: str
    name: str | None
    runner_labels: tuple[str, ...]
    permissions: PermissionSet
    environment: str | None
    needs: tuple[str, ...]
    if_condition: str | None
    steps: tuple[StepIR, ...]
    location: SourceLocation
    purpose: JobPurpose
    is_self_hosted: bool
    reusable_workflow: ActionRef | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "runner_labels": list(self.runner_labels),
            "permissions": self.permissions.to_dict(),
            "environment": self.environment,
            "needs": list(self.needs),
            "if": self.if_condition,
            "steps": [step.to_dict() for step in self.steps],
            "location": self.location.to_dict(),
            "purpose": self.purpose.value,
            "is_self_hosted": self.is_self_hosted,
            "reusable_workflow": None
            if self.reusable_workflow is None
            else self.reusable_workflow.to_dict(),
        }


@dataclass(frozen=True)
class WorkflowIR:
    name: str | None
    path: str
    triggers: tuple[TriggerIR, ...]
    permissions: PermissionSet
    jobs: tuple[JobIR, ...]
    parse_warnings: tuple[str, ...]
    location: SourceLocation
    raw_text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "triggers": [trigger.to_dict() for trigger in self.triggers],
            "permissions": self.permissions.to_dict(),
            "jobs": [job.to_dict() for job in self.jobs],
            "parse_warnings": list(self.parse_warnings),
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    confidence_rationale: str
    evidence: tuple[Evidence, ...]
    affected_component: str
    source: str | None
    sink: str | None
    impact: str
    remediation: str
    references: tuple[Reference, ...]
    score: ScoreBreakdown
    fingerprint: str
    location: SourceLocation
    category: str
    cwe_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_rationale": self.confidence_rationale,
            "evidence": [item.to_dict() for item in self.evidence],
            "affected_component": self.affected_component,
            "source": self.source,
            "sink": self.sink,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": [ref.to_dict() for ref in self.references],
            "score": self.score.to_dict(),
            "fingerprint": self.fingerprint,
            "location": self.location.to_dict(),
            "category": self.category,
            "cwe_ids": list(self.cwe_ids),
        }


@dataclass(frozen=True)
class AttackPathNode:
    label: str
    fact_kind: FactKind | None
    evidence: tuple[Evidence, ...]
    edge_reason: str
    heuristic: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "fact_kind": None if self.fact_kind is None else self.fact_kind.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "edge_reason": self.edge_reason,
            "heuristic": self.heuristic,
        }


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    nodes: tuple[AttackPathNode, ...]
    finding_ids: tuple[str, ...]
    entry_point: str
    execution_point: str
    affected_asset: str
    preconditions: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    confidence_rationale: str
    narrative: str
    remediation: str
    score: ScoreBreakdown
    fingerprint: str
    location: SourceLocation

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "finding_ids": list(self.finding_ids),
            "entry_point": self.entry_point,
            "execution_point": self.execution_point,
            "affected_asset": self.affected_asset,
            "preconditions": list(self.preconditions),
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_rationale": self.confidence_rationale,
            "narrative": self.narrative,
            "remediation": self.remediation,
            "score": self.score.to_dict(),
            "fingerprint": self.fingerprint,
            "location": self.location.to_dict(),
        }


@dataclass(frozen=True)
class Fact:
    kind: FactKind
    workflow_path: str
    job_id: str | None
    step_index: int | None
    evidence: tuple[Evidence, ...]
    details: Mapping[str, str]
    confidence: Confidence
    finding_fingerprint: str | None = None


@dataclass(frozen=True)
class Diagnostic:
    kind: DiagnosticKind
    path: str | None
    message: str
    location: SourceLocation | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "path": self.path,
            "message": self.message,
            "location": None if self.location is None else self.location.to_dict(),
        }


@dataclass(frozen=True)
class ScanSummary:
    files_scanned: int
    files_skipped: int
    findings: int
    attack_paths: int
    by_severity: Mapping[str, int]
    highest_severity: Severity | None

    def to_dict(self) -> dict[str, object]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": self.findings,
            "attack_paths": self.attack_paths,
            "by_severity": dict(self.by_severity),
            "highest_severity": None
            if self.highest_severity is None
            else self.highest_severity.value,
        }


@dataclass(frozen=True)
class ScanResult:
    schema_version: str
    tool_name: str
    tool_version: str
    target: str
    scanned_at: datetime
    files_scanned: tuple[str, ...]
    diagnostics: tuple[Diagnostic, ...]
    findings: tuple[Finding, ...]
    attack_paths: tuple[AttackPath, ...]
    summary: ScanSummary
    rule_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
            },
            "target": self.target,
            "scanned_at": self.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": list(self.files_scanned),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "findings": [item.to_dict() for item in self.findings],
            "attack_paths": [item.to_dict() for item in self.attack_paths],
            "summary": self.summary.to_dict(),
            "rules": list(self.rule_ids),
        }


def empty_summary() -> ScanSummary:
    return ScanSummary(
        files_scanned=0,
        files_skipped=0,
        findings=0,
        attack_paths=0,
        by_severity={severity.value: 0 for severity in Severity},
        highest_severity=None,
    )


def build_scan_result(
    *,
    tool_version: str,
    target: str,
    scanned_at: datetime,
    files_scanned: tuple[str, ...],
    diagnostics: tuple[Diagnostic, ...],
    findings: tuple[Finding, ...],
    attack_paths: tuple[AttackPath, ...],
    rule_ids: tuple[str, ...],
) -> ScanResult:
    by_severity = {severity.value: 0 for severity in Severity}
    highest: Severity | None = None
    for finding in findings:
        by_severity[finding.severity.value] += 1
        if highest is None or finding.severity.rank > highest.rank:
            highest = finding.severity
    for path in attack_paths:
        if highest is None or path.severity.rank > highest.rank:
            highest = path.severity
    skipped = sum(
        1
        for item in diagnostics
        if item.kind
        in {
            DiagnosticKind.PARSE_ERROR,
            DiagnosticKind.UNREADABLE,
            DiagnosticKind.SIZE_LIMIT,
            DiagnosticKind.SYMLINK_SKIPPED,
            DiagnosticKind.UNSUPPORTED,
        }
    )
    return ScanResult(
        schema_version=SCHEMA_VERSION,
        tool_name=TOOL_NAME,
        tool_version=tool_version,
        target=target,
        scanned_at=scanned_at,
        files_scanned=files_scanned,
        diagnostics=diagnostics,
        findings=findings,
        attack_paths=attack_paths,
        summary=ScanSummary(
            files_scanned=len(files_scanned),
            files_skipped=skipped,
            findings=len(findings),
            attack_paths=len(attack_paths),
            by_severity=by_severity,
            highest_severity=highest,
        ),
        rule_ids=rule_ids,
    )
