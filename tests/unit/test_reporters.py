from __future__ import annotations

import json
from datetime import UTC, datetime

from gha_threatlens.models import (
    Confidence,
    Diagnostic,
    DiagnosticKind,
    Evidence,
    EvidenceKind,
    Finding,
    Reference,
    ScanResult,
    ScoreBreakdown,
    Severity,
    SourceLocation,
    build_scan_result,
)
from gha_threatlens.reporters.json_reporter import render_json
from gha_threatlens.reporters.markdown import render_markdown
from gha_threatlens.reporters.sarif import render_sarif
from gha_threatlens.reporters.terminal import render_terminal


def _result() -> ScanResult:
    location = SourceLocation(path=".github/workflows/ci.yml", start_line=4, start_column=7)
    evidence = Evidence(excerpt='run: echo "<script>"', location=location, kind=EvidenceKind.RUN)
    finding = Finding(
        rule_id="GHAT-003",
        title="Untrusted expression in command interpreter",
        description="Injected title",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        confidence_rationale="direct",
        evidence=(evidence,),
        affected_component="ci.yml:job",
        source="event.issue.title",
        sink="bash",
        impact="command injection",
        remediation="Use env.",
        references=(
            Reference(title="CWE-78", url="https://cwe.mitre.org/data/definitions/78.html"),
        ),
        score=ScoreBreakdown(20, 30, 8, 10, 10, 0, 78, ("n",)),
        fingerprint="abc123",
        location=location,
        category="injection",
        cwe_ids=("CWE-78",),
    )
    return build_scan_result(
        tool_version="0.1.0",
        target=".",
        scanned_at=datetime(2026, 1, 15, 12, 0, tzinfo=UTC),
        files_scanned=(".github/workflows/ci.yml",),
        diagnostics=(
            Diagnostic(
                kind=DiagnosticKind.WARNING, path=".github/workflows/ci.yml", message="note"
            ),
        ),
        findings=(finding,),
        attack_paths=(),
        rule_ids=("GHAT-001", "GHAT-002", "GHAT-003", "GHAT-004"),
    )


def test_json_is_stable_and_relative() -> None:
    payload = json.loads(render_json(_result()))
    assert payload["schema_version"] == "1.0.0"
    dumped = json.dumps(payload)
    assert "/Users/" not in dumped
    assert payload["findings"][0]["location"]["path"] == ".github/workflows/ci.yml"


def test_markdown_escapes_html_and_pipes() -> None:
    text = render_markdown(_result())
    assert "<script>" not in text
    assert "\\<script\\>" in text or "\\<" in text


def test_sarif_required_fields() -> None:
    payload = json.loads(render_sarif(_result()))
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")
    driver = payload["runs"][0]["tool"]["driver"]
    assert driver["rules"]
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "GHAT-003"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 4
    assert region["startColumn"] == 7
    assert result["partialFingerprints"]["primaryLocationLineHash"] == "abc123"
    assert result["properties"]["confidence"] == "high"


def test_terminal_no_color_and_quiet() -> None:
    colourful = render_terminal(_result(), color=False, quiet=False)
    assert "GHAT-003" in colourful
    quiet = render_terminal(_result(), color=False, quiet=True)
    assert "GHAT-003" in quiet
