"""Markdown report with escaped untrusted evidence."""

from __future__ import annotations

import re

from gha_threatlens.models import AttackPath, Finding, ScanResult, ScoreBreakdown, Severity

_MD_ESCAPE = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>])")


def render_markdown(result: ScanResult) -> str:
    lines = [
        f"# {result.tool_name} report",
        "",
        f"Tool version `{_esc(result.tool_version)}`. Schema `{_esc(result.schema_version)}`.",
        f"Target `{_esc(result.target)}`. Scanned at `{result.scanned_at.strftime('%Y-%m-%dT%H:%M:%SZ')}` UTC.",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Files scanned | {result.summary.files_scanned} |",
        f"| Files skipped | {result.summary.files_skipped} |",
        f"| Findings | {result.summary.findings} |",
        f"| Attack paths | {result.summary.attack_paths} |",
    ]
    for severity in Severity:
        lines.append(f"| {severity.value} | {result.summary.by_severity.get(severity.value, 0)} |")
    lines.extend(["", "The score is a prioritisation aid, not an exploit probability.", ""])

    if result.diagnostics:
        lines.extend(["## Diagnostics", ""])
        for item in result.diagnostics:
            diag_path = _esc(item.path or "-")
            lines.append(f"- `{_esc(item.kind.value)}` `{diag_path}`: {_esc(item.message)}")
        lines.append("")

    if result.attack_paths:
        lines.extend(["## Attack paths", ""])
        for path in result.attack_paths:
            lines.extend(_path_section(path))

    if result.findings:
        lines.extend(["## Findings", ""])
        for finding in result.findings:
            lines.extend(_finding_section(finding))

    if not result.findings and not result.attack_paths:
        lines.extend(["No findings at the selected severity threshold.", ""])
    return "\n".join(lines).rstrip() + "\n"


def _finding_section(finding: Finding) -> list[str]:
    loc = finding.location
    lines = [
        f"### {_esc(finding.rule_id)} — {_esc(finding.title)}",
        "",
        f"- Severity: `{finding.severity.value}` (score {finding.score.total})",
        f"- Confidence: `{finding.confidence.value}`",
        f"- Location: `{_esc(loc.path)}:{loc.start_line}:{loc.start_column}`",
        f"- Fingerprint: `{finding.fingerprint}`",
        "",
        _esc(finding.description),
        "",
        f"**Source:** {_esc(finding.source or '-')}",
        f"**Sink:** {_esc(finding.sink or '-')}",
        f"**Impact:** {_esc(finding.impact)}",
        "",
        "**Evidence**",
        "",
    ]
    for item in finding.evidence:
        lines.append(
            f"- `{_esc(item.kind.value)}` `{_esc(item.location.path)}:{item.location.start_line}`: `{_esc(item.excerpt)}`"
        )
    lines.extend(
        [
            "",
            "**Score breakdown**",
            "",
            _score_line(finding.score),
            "",
            f"**Confidence rationale:** {_esc(finding.confidence_rationale)}",
            "",
            f"**Remediation:** {_esc(finding.remediation)}",
            "",
        ]
    )
    return lines


def _path_section(path: AttackPath) -> list[str]:
    lines = [
        f"### {_esc(path.path_id)}",
        "",
        f"- Severity: `{path.severity.value}` (score {path.score.total})",
        f"- Confidence: `{path.confidence.value}`",
        f"- Entry: {_esc(path.entry_point)}",
        f"- Execution: {_esc(path.execution_point)}",
        f"- Asset: {_esc(path.affected_asset)}",
        "",
        _esc(path.narrative),
        "",
        "**Nodes**",
        "",
    ]
    for index, node in enumerate(path.nodes, start=1):
        flag = " (heuristic)" if node.heuristic else ""
        lines.append(f"{index}. {_esc(node.label)}{flag} — {_esc(node.edge_reason)}")
    lines.extend(
        [
            "",
            _score_line(path.score),
            "",
            f"**Remediation:** {_esc(path.remediation)}",
            "",
        ]
    )
    return lines


def _score_line(score: ScoreBreakdown) -> str:
    return (
        f"exposure {score.exposure} + exploitability {score.exploitability} + "
        f"privilege {score.privilege} + impact {score.impact} + chain {score.chain_evidence} "
        f"- mitigations {score.applicable_mitigations} = {score.total}"
    )


def _esc(value: str) -> str:
    return _MD_ESCAPE.sub(r"\\\1", value)
