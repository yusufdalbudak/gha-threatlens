from __future__ import annotations

from gha_threatlens.fingerprints import fingerprint
from gha_threatlens.models import (
    JobPurpose,
    PermissionPreset,
    PermissionSet,
    Severity,
    TrustLevel,
)
from gha_threatlens.scoring import (
    apply_severity_guardrail,
    breakdown,
    clamp,
    expression_injection_score,
    mutable_action_score,
    pr_chain_score,
    severity_from_score,
)


def test_clamp_and_severity_boundaries() -> None:
    assert clamp(-4) == 0
    assert clamp(140) == 100
    assert severity_from_score(0) is Severity.INFORMATIONAL
    assert severity_from_score(19) is Severity.INFORMATIONAL
    assert severity_from_score(20) is Severity.LOW
    assert severity_from_score(39) is Severity.LOW
    assert severity_from_score(40) is Severity.MEDIUM
    assert severity_from_score(59) is Severity.MEDIUM
    assert severity_from_score(60) is Severity.HIGH
    assert severity_from_score(79) is Severity.HIGH
    assert severity_from_score(80) is Severity.CRITICAL
    assert severity_from_score(100) is Severity.CRITICAL


def test_breakdown_subtracts_mitigations_once() -> None:
    score = breakdown(
        exposure=20,
        exploitability=30,
        privilege=20,
        impact=20,
        chain_evidence=10,
        applicable_mitigations=10,
        notes=("n",),
    )
    assert score.total == 90
    assert score.applicable_mitigations == 10


def test_mutable_ref_has_lower_exploitability_than_injection() -> None:
    unset = PermissionSet(preset=PermissionPreset.UNSET)
    mutable = mutable_action_score(
        trust=TrustLevel.MAINTAINER,
        permissions=unset,
        purpose=JobPurpose.TEST,
        self_hosted=False,
    )
    injection = expression_injection_score(
        trust=TrustLevel.PUBLIC_USER,
        permissions=unset,
        purpose=JobPurpose.UNKNOWN,
        self_hosted=False,
    )
    assert mutable.exploitability < injection.exploitability
    assert injection.exploitability == 30


def test_pr_chain_heuristic_lowers_chain_evidence() -> None:
    write = PermissionSet(
        preset=PermissionPreset.EXPLICIT,
        declared=True,
        scopes={
            "contents": __import__(
                "gha_threatlens.models", fromlist=["PermissionAccess"]
            ).PermissionAccess.WRITE
        },
    )
    direct = pr_chain_score(
        permissions=write,
        purpose=JobPurpose.UNKNOWN,
        execution_direct=True,
        secrets_visible=False,
        oidc=False,
        self_hosted=False,
        persist_credentials=True,
    )
    heuristic = pr_chain_score(
        permissions=write,
        purpose=JobPurpose.UNKNOWN,
        execution_direct=False,
        secrets_visible=False,
        oidc=False,
        self_hosted=False,
        persist_credentials=True,
    )
    assert direct.chain_evidence == 10
    assert heuristic.chain_evidence == 4
    assert direct.total > heuristic.total
    assert severity_from_score(direct.total) is Severity.CRITICAL


def test_ghat001_test_job_guardrail() -> None:
    write_all = PermissionSet(preset=PermissionPreset.WRITE_ALL, declared=True)
    score = mutable_action_score(
        trust=TrustLevel.EXTERNAL,
        permissions=write_all,
        purpose=JobPurpose.TEST,
        self_hosted=False,
    )
    _, severity = apply_severity_guardrail(score, purpose=JobPurpose.TEST, rule_id="GHAT-001")
    assert severity.rank < Severity.HIGH.rank or severity is Severity.MEDIUM


def test_fingerprint_is_stable() -> None:
    assert fingerprint("a", "b") == fingerprint("a", "b")
    assert fingerprint("a", "b") != fingerprint("b", "a")
