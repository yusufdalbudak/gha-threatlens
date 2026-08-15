from __future__ import annotations

from gha_threatlens.models import Confidence, Severity
from tests.conftest import fixture_text, scan_workflow_text


def test_ghat001_minimal(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("vulnerable", "mutable_action_minimal.yml"))
    matches = [item for item in result.findings if item.rule_id == "GHAT-001"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.location.start_line >= 1
    assert finding.confidence is Confidence.HIGH
    assert "SHA" in finding.remediation
    assert "3d3c42e5" not in finding.remediation
    assert finding.references


def test_ghat001_realistic_release_job(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("vulnerable", "mutable_action_realistic.yml")
    )
    matches = [item for item in result.findings if item.rule_id == "GHAT-001"]
    assert len(matches) >= 2
    assert any(item.severity.rank >= Severity.MEDIUM.rank for item in matches)


def test_ghat001_hardened_negative(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "pinned_actions.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-001"] == []


def test_ghat001_docker_near_miss(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "near_miss_docker_tag.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-001"] == []


def test_ghat002_write_all(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("vulnerable", "excessive_permissions_minimal.yml")
    )
    matches = [item for item in result.findings if item.rule_id == "GHAT-002"]
    assert matches
    assert matches[0].confidence is Confidence.HIGH
    assert "write-all" in matches[0].description.lower() or "write-all" in (matches[0].source or "")


def test_ghat002_high_impact_write(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("vulnerable", "excessive_permissions_realistic.yml")
    )
    matches = [item for item in result.findings if item.rule_id == "GHAT-002"]
    assert matches
    assert any(
        "contents" in (item.source or "") or "id-token" in (item.source or "") for item in matches
    )


def test_ghat002_hardened_negative(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "least_privilege.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-002"] == []


def test_ghat002_missing_permissions_not_write(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "missing_permissions.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-002"] == []


def test_ghat003_minimal_issue_title(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("vulnerable", "expression_injection_minimal.yml")
    )
    matches = [item for item in result.findings if item.rule_id == "GHAT-003"]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.source and "issue.title" in finding.source
    assert finding.sink and "bash" in finding.sink
    assert "CWE-78" in finding.cwe_ids
    assert "env" in finding.remediation.lower()


def test_ghat003_realistic(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("vulnerable", "expression_injection_realistic.yml")
    )
    matches = [item for item in result.findings if item.rule_id == "GHAT-003"]
    assert matches
    assert matches[0].confidence is Confidence.HIGH


def test_ghat003_env_near_miss(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "env_not_run_interpolation.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-003"] == []


def test_ghat004_complete_chain(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("vulnerable", "pr_target_chain.yml"))
    matches = [item for item in result.findings if item.rule_id == "GHAT-004"]
    assert matches
    finding = matches[0]
    assert finding.confidence is Confidence.HIGH
    assert finding.severity is Severity.CRITICAL
    assert result.attack_paths
    path = result.attack_paths[0]
    assert path.severity is Severity.CRITICAL
    assert path.confidence is Confidence.HIGH
    assert len(path.nodes) >= 5
    assert path.score.notes


def test_ghat004_prt_alone_is_not_exploitation(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "pr_target_base_checkout.yml"))
    assert [item for item in result.findings if item.rule_id == "GHAT-004"] == []
    assert result.attack_paths == ()


def test_ghat004_checkout_without_execution(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("hardened", "pr_target_checkout_no_exec.yml")
    )
    assert [item for item in result.findings if item.rule_id == "GHAT-004"] == []
    assert result.attack_paths == ()


def test_ghat004_heuristic_npm(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("vulnerable", "pr_target_heuristic.yml"))
    matches = [item for item in result.findings if item.rule_id == "GHAT-004"]
    assert matches
    assert matches[0].confidence is Confidence.MEDIUM
    assert result.attack_paths
    assert result.attack_paths[0].confidence is Confidence.MEDIUM
