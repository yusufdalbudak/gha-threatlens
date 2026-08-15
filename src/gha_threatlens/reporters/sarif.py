"""SARIF 2.1.0 report for GitHub code scanning uploads."""

from __future__ import annotations

import json

from gha_threatlens.constants import SARIF_SCHEMA_URI, SARIF_VERSION, TOOL_ID, TOOL_NAME
from gha_threatlens.models import Finding, ScanResult, Severity
from gha_threatlens.rules import all_rules

_LEVEL = {
    Severity.INFORMATIONAL: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_sarif(result: ScanResult) -> str:
    rules = []
    for rule in all_rules():
        spec = rule.spec
        rules.append(
            {
                "id": spec.rule_id,
                "name": spec.title.replace(" ", ""),
                "shortDescription": {"text": spec.title},
                "fullDescription": {"text": spec.summary},
                "helpUri": spec.references[0].url if spec.references else None,
                "help": {"text": spec.remediation.strip()},
                "properties": {
                    "category": spec.category,
                    "precision": "high",
                    "tags": ["security", spec.category, *spec.cwe_ids],
                },
            }
        )

    results = [_finding_result(item) for item in result.findings]
    for path in result.attack_paths:
        results.append(
            {
                "ruleId": "GHAT-004",
                "ruleIndex": 3,
                "level": _LEVEL[path.severity],
                "message": {"text": path.narrative},
                "locations": [
                    _location(
                        path.location.path, path.location.start_line, path.location.start_column
                    )
                ],
                "partialFingerprints": {"primaryLocationLineHash": path.fingerprint},
                "properties": {
                    "security-severity": str(path.score.total),
                    "confidence": path.confidence.value,
                    "category": "attack-path",
                    "attackPathId": path.path_id,
                    "score": path.score.to_dict(),
                },
            }
        )

    document = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": "https://github.com/yusufdalbudak/gha-threatlens",
                        "version": result.tool_version,
                        "semanticVersion": result.tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": TOOL_ID,
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def _finding_result(finding: Finding) -> dict[str, object]:
    rule_index = {"GHAT-001": 0, "GHAT-002": 1, "GHAT-003": 2, "GHAT-004": 3}[finding.rule_id]
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.description},
        "locations": [
            _location(
                finding.location.path, finding.location.start_line, finding.location.start_column
            )
        ],
        "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        "properties": {
            "security-severity": str(finding.score.total),
            "confidence": finding.confidence.value,
            "category": finding.category,
            "attackPathId": None,
            "score": finding.score.to_dict(),
        },
    }


def _location(path: str, line: int, column: int) -> dict[str, object]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
            "region": {
                "startLine": max(line, 1),
                "startColumn": max(column, 1),
            },
        }
    }
