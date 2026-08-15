from __future__ import annotations

from gha_threatlens.models import Confidence, Severity
from tests.conftest import fixture_text, scan_workflow_text


def test_complete_chain_one_deterministic_path(tmp_path) -> None:
    first = scan_workflow_text(tmp_path / "a", fixture_text("vulnerable", "pr_target_chain.yml"))
    second = scan_workflow_text(tmp_path / "b", fixture_text("vulnerable", "pr_target_chain.yml"))
    assert len(first.attack_paths) == 1
    assert first.attack_paths[0].fingerprint == second.attack_paths[0].fingerprint
    assert first.findings[0].fingerprint == second.findings[0].fingerprint


def test_trigger_without_checkout_has_no_path(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "pr_target_base_checkout.yml"))
    assert result.attack_paths == ()


def test_checkout_without_execution_has_no_path(tmp_path) -> None:
    result = scan_workflow_text(
        tmp_path, fixture_text("hardened", "pr_target_checkout_no_exec.yml")
    )
    assert result.attack_paths == ()


def test_readonly_execution_is_not_zero_risk(tmp_path) -> None:
    text = fixture_text("vulnerable", "pr_target_heuristic.yml")
    result = scan_workflow_text(tmp_path, text)
    assert result.attack_paths
    path = result.attack_paths[0]
    assert path.score.total > 0
    assert path.severity.rank >= Severity.LOW.rank


def test_heuristic_sink_lowers_confidence(tmp_path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("vulnerable", "pr_target_heuristic.yml"))
    assert result.attack_paths[0].confidence is Confidence.MEDIUM
    assert any(node.heuristic for node in result.attack_paths[0].nodes)
