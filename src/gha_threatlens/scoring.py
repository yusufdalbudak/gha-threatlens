"""Prioritisation scoring. The total is not an exploit probability and is not CVSS."""

from __future__ import annotations

from gha_threatlens.models import (
    Confidence,
    JobPurpose,
    PermissionPreset,
    PermissionSet,
    ScoreBreakdown,
    Severity,
    TrustLevel,
)
from gha_threatlens.permissions import has_high_impact_write, permission_uncertainty

SEVERITY_BOUNDARIES: tuple[tuple[int, int, Severity], ...] = (
    (0, 19, Severity.INFORMATIONAL),
    (20, 39, Severity.LOW),
    (40, 59, Severity.MEDIUM),
    (60, 79, Severity.HIGH),
    (80, 100, Severity.CRITICAL),
)


def clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def severity_from_score(total: int) -> Severity:
    score = clamp(total)
    for low, high, severity in SEVERITY_BOUNDARIES:
        if low <= score <= high:
            return severity
    return Severity.CRITICAL


def breakdown(
    *,
    exposure: int,
    exploitability: int,
    privilege: int,
    impact: int,
    chain_evidence: int,
    applicable_mitigations: int,
    notes: tuple[str, ...],
) -> ScoreBreakdown:
    total = clamp(
        exposure + exploitability + privilege + impact + chain_evidence - applicable_mitigations
    )
    return ScoreBreakdown(
        exposure=clamp(exposure, 0, 20),
        exploitability=clamp(exploitability, 0, 30),
        privilege=clamp(privilege, 0, 20),
        impact=clamp(impact, 0, 20),
        chain_evidence=clamp(chain_evidence, 0, 10),
        applicable_mitigations=clamp(applicable_mitigations, 0, 20),
        total=total,
        notes=notes,
    )


def exposure_for_trust(trust: TrustLevel) -> tuple[int, str]:
    mapping = {
        TrustLevel.PUBLIC_USER: (20, "Public user-controlled trigger content."),
        TrustLevel.EXTERNAL: (20, "External or fork-controlled pull request trigger."),
        TrustLevel.ACTOR_DEPENDENT: (10, "Manually supplied input; trust depends on the actor."),
        TrustLevel.COLLABORATOR: (8, "Collaborator-influenceable content."),
        TrustLevel.MAINTAINER: (4, "Maintainer-controlled trigger."),
        TrustLevel.UNKNOWN: (10, "Trigger trust could not be classified."),
    }
    return mapping[trust]


def highest_trigger_trust(trusts: tuple[TrustLevel, ...]) -> TrustLevel:
    order = [
        TrustLevel.PUBLIC_USER,
        TrustLevel.EXTERNAL,
        TrustLevel.ACTOR_DEPENDENT,
        TrustLevel.UNKNOWN,
        TrustLevel.COLLABORATOR,
        TrustLevel.MAINTAINER,
    ]
    for candidate in order:
        if candidate in trusts:
            return candidate
    return TrustLevel.UNKNOWN


def privilege_points(
    permissions: PermissionSet, *, oidc: bool, secrets_visible: bool, self_hosted: bool
) -> tuple[int, str]:
    if permissions.preset is PermissionPreset.WRITE_ALL:
        return 20, "write-all token declaration."
    writes = permissions.write_scopes()
    high = has_high_impact_write(permissions)
    points = 0
    reasons: list[str] = []
    if high:
        points = 16
        reasons.append(f"explicit high-impact write: {', '.join(writes)}.")
    elif writes:
        points = 10
        reasons.append(f"explicit write scopes: {', '.join(writes)}.")
    elif permission_uncertainty(permissions):
        points = 8
        reasons.append("token permissions are unknown because the key is missing.")
    else:
        points = 4
        reasons.append("declared permissions are read or none.")

    if oidc and points < 18:
        points = min(20, points + 4)
        reasons.append("id-token write (OIDC) is declared.")
    if secrets_visible and points < 18:
        points = min(20, points + 4)
        reasons.append("workflow references secrets in a reachable job.")
    if self_hosted and points < 20:
        points = min(20, points + 4)
        reasons.append("job may run on a self-hosted runner.")
    return points, " ".join(reasons)


def impact_points(
    *,
    permissions: PermissionSet,
    purpose: JobPurpose,
    secrets_visible: bool,
    oidc: bool,
) -> tuple[int, str]:
    writes = set(permissions.write_scopes())
    if permissions.preset is PermissionPreset.WRITE_ALL or purpose in {
        JobPurpose.RELEASE,
        JobPurpose.DEPLOY,
    }:
        if (
            "packages" in writes
            or "contents" in writes
            or permissions.preset is PermissionPreset.WRITE_ALL
        ):
            return 20, "Release, package, or repository write path is reachable."
        if purpose is JobPurpose.DEPLOY:
            return 20, "Deployment job can affect downstream environments."
    if "contents" in writes:
        return 16, "contents: write enables repository tampering."
    if "packages" in writes or "id-token" in writes or oidc:
        return 16, "Package publish or OIDC federation is reachable."
    if secrets_visible:
        return 12, "Reachable secrets increase credential-exposure impact."
    if permission_uncertainty(permissions):
        return 10, "Impact is uncertain because token defaults are not visible."
    if writes:
        return 10, "Write scopes can modify repository metadata."
    return 6, "Visible impact is limited to read-level token access."


def mutable_action_score(
    *,
    trust: TrustLevel,
    permissions: PermissionSet,
    purpose: JobPurpose,
    self_hosted: bool,
) -> ScoreBreakdown:
    exposure, exposure_note = exposure_for_trust(trust)
    privilege, privilege_note = privilege_points(
        permissions, oidc=False, secrets_visible=False, self_hosted=self_hosted
    )
    impact, impact_note = impact_points(
        permissions=permissions, purpose=purpose, secrets_visible=False, oidc=False
    )
    # Mutable dependency is not direct input-to-shell execution.
    exploitability = 10 if purpose in {JobPurpose.RELEASE, JobPurpose.DEPLOY} else 8
    chain = 8
    return breakdown(
        exposure=exposure,
        exploitability=exploitability,
        privilege=privilege,
        impact=impact,
        chain_evidence=chain,
        applicable_mitigations=0,
        notes=(
            exposure_note,
            "Mutable Git ref; exploitability is lower than direct interpreter interpolation.",
            privilege_note,
            impact_note,
            "Direct uses: pin evidence.",
        ),
    )


def excessive_permission_score(
    *,
    trust: TrustLevel,
    permissions: PermissionSet,
    purpose: JobPurpose,
    write_all: bool,
) -> ScoreBreakdown:
    exposure, exposure_note = exposure_for_trust(trust)
    privilege = 20 if write_all else 16
    impact = 16 if purpose in {JobPurpose.RELEASE, JobPurpose.DEPLOY} or write_all else 12
    exploitability = 6
    return breakdown(
        exposure=exposure,
        exploitability=exploitability,
        privilege=privilege,
        impact=impact,
        chain_evidence=8,
        applicable_mitigations=0,
        notes=(
            exposure_note,
            "Broad token declaration is not by itself code execution.",
            "Declared write privilege is explicit in YAML.",
            "Impact reflects reachable token capability, not proven business misuse.",
            "Direct permissions: evidence.",
        ),
    )


def expression_injection_score(
    *,
    trust: TrustLevel,
    permissions: PermissionSet,
    purpose: JobPurpose,
    self_hosted: bool,
) -> ScoreBreakdown:
    exposure, exposure_note = exposure_for_trust(trust)
    privilege, privilege_note = privilege_points(
        permissions, oidc=False, secrets_visible=False, self_hosted=self_hosted
    )
    impact, impact_note = impact_points(
        permissions=permissions, purpose=purpose, secrets_visible=False, oidc=False
    )
    return breakdown(
        exposure=exposure,
        exploitability=30,
        privilege=privilege,
        impact=impact,
        chain_evidence=10,
        applicable_mitigations=0,
        notes=(
            exposure_note,
            "Untrusted expression is interpolated directly into the interpreter script.",
            privilege_note,
            impact_note,
            "Direct data-flow evidence from expression to run:.",
        ),
    )


def pr_chain_score(
    *,
    permissions: PermissionSet,
    purpose: JobPurpose,
    execution_direct: bool,
    secrets_visible: bool,
    oidc: bool,
    self_hosted: bool,
    persist_credentials: bool,
) -> ScoreBreakdown:
    exposure = 20
    exploitability = 30 if execution_direct else 18
    privilege, privilege_note = privilege_points(
        permissions, oidc=oidc, secrets_visible=secrets_visible, self_hosted=self_hosted
    )
    impact, impact_note = impact_points(
        permissions=permissions,
        purpose=purpose,
        secrets_visible=secrets_visible,
        oidc=oidc,
    )
    chain = 10 if execution_direct else 4
    mitigations = 0
    mitigation_notes: list[str] = []
    if not persist_credentials:
        mitigations += 8
        mitigation_notes.append(
            "checkout persist-credentials is false, reducing token reuse from disk."
        )
    notes = (
        "Public or fork pull_request_target exposure.",
        "Direct attacker-controlled code execution."
        if execution_direct
        else "Execution sink is heuristic, not a confirmed local script path.",
        privilege_note,
        impact_note,
        "Direct structural chain." if execution_direct else "Naming or command-family heuristic.",
        *mitigation_notes,
    )
    return breakdown(
        exposure=exposure,
        exploitability=exploitability,
        privilege=privilege,
        impact=impact,
        chain_evidence=chain,
        applicable_mitigations=mitigations,
        notes=notes,
    )


def apply_severity_guardrail(
    score: ScoreBreakdown,
    *,
    purpose: JobPurpose,
    rule_id: str,
) -> tuple[ScoreBreakdown, Severity]:
    """Documented overrides that stop a low-privilege test job being called Critical."""

    severity = severity_from_score(score.total)
    if rule_id == "GHAT-001" and purpose is JobPurpose.TEST and severity.rank >= Severity.HIGH.rank:
        severity = Severity.MEDIUM
    if rule_id == "GHAT-002" and purpose is JobPurpose.TEST and severity is Severity.CRITICAL:
        severity = Severity.HIGH
    return score, severity


def confidence_rationale(confidence: Confidence, detail: str) -> str:
    prefix = {
        Confidence.HIGH: "HIGH: confirmed by parsed structure and explicit data or control flow.",
        Confidence.MEDIUM: "MEDIUM: strong contextual correlation with one defensible heuristic.",
        Confidence.LOW: "LOW: incomplete knowledge, naming heuristic, or ambiguous execution semantics.",
    }[confidence]
    return f"{prefix} {detail}"
