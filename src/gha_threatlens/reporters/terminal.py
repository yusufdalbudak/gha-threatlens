"""Terminal reporter. Colour is optional and never the only signal."""

from __future__ import annotations

from gha_threatlens.models import ScanResult, ScoreBreakdown, Severity

try:
    from rich.console import Console
except ImportError:  # pragma: no cover
    Console = None  # type: ignore[assignment,misc]


_SEVERITY_LABEL = {
    Severity.INFORMATIONAL: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MED",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRIT",
}

_SEVERITY_STYLE = {
    Severity.INFORMATIONAL: "cyan",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def render_terminal(result: ScanResult, *, color: bool, quiet: bool) -> str:
    if Console is None:
        return _plain(result, quiet=quiet)
    buffer: list[str] = []
    console = Console(
        file=_ListFile(buffer),  # type: ignore[arg-type]
        color_system="standard" if color else None,
        highlight=False,
        width=120,
        force_terminal=color,
        no_color=not color,
    )
    if not quiet:
        console.print(
            f"{result.tool_name} {result.tool_version}  files={result.summary.files_scanned}  "
            f"findings={result.summary.findings}  paths={result.summary.attack_paths}"
        )
        counts = "  ".join(
            f"{severity.value}={result.summary.by_severity.get(severity.value, 0)}"
            for severity in Severity
        )
        console.print(counts)
        console.print("Score is a prioritisation aid, not an exploit probability.")
        if result.diagnostics:
            for item in result.diagnostics:
                console.print(f"diagnostic [{item.kind.value}] {item.path or '-'}: {item.message}")

    for path in result.attack_paths:
        console.print()
        console.print(
            f"PATH {_SEVERITY_LABEL[path.severity]} {path.path_id} score={path.score.total} conf={path.confidence.value}"
        )
        console.print(f"  {path.narrative}")
        for node in path.nodes:
            marker = "~" if node.heuristic else ">"
            console.print(f"  {marker} {node.label}")
        console.print(f"  score {_format_score(path.score)}")
        console.print(f"  remediation: {path.remediation}")

    for finding in result.findings:
        console.print()
        loc = finding.location
        console.print(
            f"{_SEVERITY_LABEL[finding.severity]} {finding.rule_id} {loc.path}:{loc.start_line}:{loc.start_column} "
            f"score={finding.score.total} conf={finding.confidence.value}"
        )
        console.print(f"  {finding.title}")
        if finding.evidence:
            console.print(f"  evidence: {finding.evidence[0].excerpt}")
        console.print(f"  {_format_score(finding.score)}")
        console.print(f"  remediation: {finding.remediation}")

    if quiet and not result.findings and not result.attack_paths and not result.diagnostics:
        return ""
    if not result.findings and not result.attack_paths and not quiet:
        console.print("No findings at the selected severity threshold.")
    return "".join(buffer)


def _plain(result: ScanResult, *, quiet: bool) -> str:
    lines: list[str] = []
    if not quiet:
        lines.append(
            f"{result.tool_name} {result.tool_version}  files={result.summary.files_scanned}  "
            f"findings={result.summary.findings}  paths={result.summary.attack_paths}"
        )
        lines.append(
            "  ".join(
                f"{severity.value}={result.summary.by_severity.get(severity.value, 0)}"
                for severity in Severity
            )
        )
        lines.append("Score is a prioritisation aid, not an exploit probability.")
        for item in result.diagnostics:
            lines.append(f"diagnostic [{item.kind.value}] {item.path or '-'}: {item.message}")
    for path in result.attack_paths:
        lines.append("")
        lines.append(
            f"PATH {_SEVERITY_LABEL[path.severity]} {path.path_id} score={path.score.total} conf={path.confidence.value}"
        )
        lines.append(f"  {path.narrative}")
        for node in path.nodes:
            marker = "~" if node.heuristic else ">"
            lines.append(f"  {marker} {node.label}")
        lines.append(f"  score {_format_score(path.score)}")
        lines.append(f"  remediation: {path.remediation}")
    for finding in result.findings:
        loc = finding.location
        lines.append("")
        lines.append(
            f"{_SEVERITY_LABEL[finding.severity]} {finding.rule_id} {loc.path}:{loc.start_line}:{loc.start_column} "
            f"score={finding.score.total} conf={finding.confidence.value}"
        )
        lines.append(f"  {finding.title}")
        if finding.evidence:
            lines.append(f"  evidence: {finding.evidence[0].excerpt}")
        lines.append(f"  {_format_score(finding.score)}")
        lines.append(f"  remediation: {finding.remediation}")
    if not result.findings and not result.attack_paths and not quiet:
        lines.append("No findings at the selected severity threshold.")
    text = "\n".join(line for line in lines if line is not None).rstrip()
    return f"{text}\n" if text else ""


def _format_score(score: ScoreBreakdown) -> str:
    return (
        f"exp {score.exposure} + expl {score.exploitability} + priv {score.privilege} "
        f"+ imp {score.impact} + chain {score.chain_evidence} - mit {score.applicable_mitigations} "
        f"= {score.total}"
    )


class _ListFile:
    def __init__(self, buffer: list[str]) -> None:
        self.buffer = buffer

    def write(self, data: str) -> int:
        self.buffer.append(data)
        return len(data)

    def flush(self) -> None:
        return None
