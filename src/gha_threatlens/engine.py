"""Scan orchestration. Library functions never call sys.exit."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from gha_threatlens.constants import DEFAULT_MAX_WORKFLOW_BYTES, TOOL_ID
from gha_threatlens.correlation import correlate
from gha_threatlens.discovery import discover_workflows
from gha_threatlens.errors import InvalidTargetError, UnsupportedStructureError, YamlParseError
from gha_threatlens.models import (
    Diagnostic,
    DiagnosticKind,
    Fact,
    Finding,
    ScanResult,
    Severity,
    WorkflowIR,
    build_scan_result,
)
from gha_threatlens.normalizer import normalise_workflow
from gha_threatlens.parser import load_yaml_document
from gha_threatlens.rules import all_rules, rule_ids


@dataclass(frozen=True)
class ScanOptions:
    max_bytes: int = DEFAULT_MAX_WORKFLOW_BYTES
    min_severity: Severity = Severity.INFORMATIONAL
    clock: Callable[[], datetime] | None = None


def tool_version() -> str:
    try:
        return version(TOOL_ID)
    except PackageNotFoundError:
        return "0.1.0"


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanResult:
    settings = options or ScanOptions()
    discovery = discover_workflows(target, max_bytes=settings.max_bytes)
    display_target = _display_target(target)

    workflows: list[WorkflowIR] = []
    diagnostics = list(discovery.diagnostics)
    scanned: list[str] = []

    for item in discovery.files:
        try:
            document = load_yaml_document(item.path, item.relative_path)
            workflow = normalise_workflow(document.data, item.relative_path, document.text)
        except YamlParseError as exc:
            diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.PARSE_ERROR, path=item.relative_path, message=exc.message
                )
            )
            continue
        except UnsupportedStructureError as exc:
            diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.UNSUPPORTED, path=item.relative_path, message=exc.message
                )
            )
            continue
        except OSError as exc:
            diagnostics.append(
                Diagnostic(
                    kind=DiagnosticKind.UNREADABLE,
                    path=item.relative_path,
                    message=f"Could not read workflow: {exc}",
                )
            )
            continue
        for warning in workflow.parse_warnings:
            diagnostics.append(
                Diagnostic(kind=DiagnosticKind.WARNING, path=item.relative_path, message=warning)
            )
        workflows.append(workflow)
        scanned.append(item.relative_path)

    findings: list[Finding] = []
    facts: list[Fact] = []
    for workflow in workflows:
        for rule in all_rules():
            rule_findings, rule_facts = rule.evaluate(workflow)
            findings.extend(rule_findings)
            facts.extend(rule_facts)

    findings.sort(
        key=lambda item: (
            item.location.path,
            item.location.start_line,
            item.rule_id,
            item.fingerprint,
        )
    )
    paths = correlate(tuple(workflows), tuple(findings), tuple(facts))

    min_rank = settings.min_severity.rank
    visible_findings = [item for item in findings if item.severity.rank >= min_rank]
    visible_paths = [item for item in paths if item.severity.rank >= min_rank]

    clock = settings.clock or utcnow
    scanned_at = clock()
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    scanned_at = scanned_at.astimezone(UTC).replace(microsecond=0)

    return build_scan_result(
        tool_version=tool_version(),
        target=display_target,
        scanned_at=scanned_at,
        files_scanned=tuple(scanned),
        diagnostics=tuple(diagnostics),
        findings=tuple(visible_findings),
        attack_paths=tuple(visible_paths),
        rule_ids=rule_ids(),
    )


def meets_fail_on(result: ScanResult, threshold: Severity) -> bool:
    rank = threshold.rank
    if any(item.severity.rank >= rank for item in result.findings):
        return True
    return any(item.severity.rank >= rank for item in result.attack_paths)


def _display_target(target: str | Path) -> str:
    path = Path(target)
    try:
        relative = path.resolve().relative_to(Path.cwd().resolve())
        rendered = relative.as_posix()
        return "." if rendered == "." else rendered
    except (ValueError, InvalidTargetError, OSError):
        return Path(target).as_posix()
