"""Explicit trust classification for GitHub Actions expressions and events.

Not every `github.*` field is untrusted. Classification is source-specific and
further constrained by the workflow triggers that can populate the field.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from gha_threatlens.constants import MAX_EXPRESSION_LENGTH
from gha_threatlens.models import ShellKind, TrustLevel

# Bounded, non-nested extraction of GitHub expressions.
EXPRESSION_PATTERN = re.compile(r"\$\{\{(.{1," + str(MAX_EXPRESSION_LENGTH) + r"}?)\}\}", re.DOTALL)

UNTRUSTED_PUBLIC_EVENTS = frozenset(
    {
        "issues",
        "issue_comment",
        "discussion",
        "discussion_comment",
        "public",
        "watch",
        "fork",
    }
)

EXTERNAL_PR_EVENTS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request_comment",
    }
)

ACTOR_DEPENDENT_EVENTS = frozenset(
    {
        "workflow_dispatch",
        "workflow_call",
        "repository_dispatch",
    }
)

MAINTAINER_EVENTS = frozenset(
    {
        "push",
        "schedule",
        "release",
        "create",
        "delete",
        "deployment",
        "deployment_status",
        "page_build",
        "workflow_run",
        "merge_group",
        "check_run",
        "check_suite",
        "gollum",
        "label",
        "milestone",
        "project",
        "project_card",
        "project_column",
        "registry_package",
        "status",
        "branch_protection_rule",
    }
)

# Field suffixes after github. / github.event. normalisation.
# Values are the trust of the *content*, not of the actor who triggered the job.
SOURCE_CATALOGUE: dict[str, TrustLevel] = {
    "event.pull_request.title": TrustLevel.EXTERNAL,
    "event.pull_request.body": TrustLevel.EXTERNAL,
    "event.pull_request.head.ref": TrustLevel.EXTERNAL,
    "event.pull_request.head.sha": TrustLevel.EXTERNAL,
    "event.pull_request.head.label": TrustLevel.EXTERNAL,
    "event.pull_request.head.repo.clone_url": TrustLevel.EXTERNAL,
    "event.pull_request.head.repo.full_name": TrustLevel.EXTERNAL,
    "event.pull_request.head.repo.name": TrustLevel.EXTERNAL,
    "event.pull_request.head.repo.default_branch": TrustLevel.EXTERNAL,
    "event.pull_request.user.login": TrustLevel.EXTERNAL,
    "event.pull_request.label.name": TrustLevel.EXTERNAL,
    "head_ref": TrustLevel.EXTERNAL,
    "event.issue.title": TrustLevel.PUBLIC_USER,
    "event.issue.body": TrustLevel.PUBLIC_USER,
    "event.comment.body": TrustLevel.PUBLIC_USER,
    "event.review.body": TrustLevel.EXTERNAL,
    "event.review_comment.body": TrustLevel.EXTERNAL,
    "event.discussion.title": TrustLevel.PUBLIC_USER,
    "event.discussion.body": TrustLevel.PUBLIC_USER,
    "event.discussion_comment.body": TrustLevel.PUBLIC_USER,
    "event.inputs": TrustLevel.ACTOR_DEPENDENT,
    "event.client_payload": TrustLevel.ACTOR_DEPENDENT,
    "event.head_commit.message": TrustLevel.COLLABORATOR,
    "event.head_commit.author.name": TrustLevel.COLLABORATOR,
    "event.head_commit.author.email": TrustLevel.COLLABORATOR,
    "event.commits.message": TrustLevel.COLLABORATOR,
}

# Trusted or not inherently attacker-controlled in isolation.
TRUSTED_OR_NEUTRAL_PREFIXES: tuple[str, ...] = (
    "repository",
    "repository_owner",
    "workspace",
    "server_url",
    "api_url",
    "graphql_url",
    "retention_days",
    "run_id",
    "run_number",
    "run_attempt",
    "job",
    "job_workflow_sha",
    "workflow",
    "workflow_ref",
    "workflow_sha",
    "ref_protected",
    "ref_type",
    "ref_name",
    "base_ref",
    "sha",
    "token",
    "event_name",
    "event.repository",
    "event.organization",
    "event.pull_request.base",
    "event.pull_request.number",
    "secret_source",
    "runner",
    "hashfiles",
)

PR_HEAD_CHECKOUT_FIELDS = frozenset(
    {
        "event.pull_request.head.sha",
        "event.pull_request.head.ref",
        "event.pull_request.head.label",
        "head_ref",
    }
)

PR_HEAD_REPO_FIELDS = frozenset(
    {
        "event.pull_request.head.repo.full_name",
        "event.pull_request.head.repo.clone_url",
        "event.pull_request.head.repo.name",
    }
)


@dataclass(frozen=True)
class ExpressionMatch:
    raw: str
    inner: str
    normalised: str


@dataclass(frozen=True)
class UntrustedSource:
    field: str
    trust: TrustLevel
    label: str


def infer_event_trust(event_name: str) -> TrustLevel:
    name = event_name.lower()
    if name in EXTERNAL_PR_EVENTS:
        return TrustLevel.EXTERNAL
    if name in UNTRUSTED_PUBLIC_EVENTS:
        return TrustLevel.PUBLIC_USER
    if name in ACTOR_DEPENDENT_EVENTS:
        return TrustLevel.ACTOR_DEPENDENT
    if name in MAINTAINER_EVENTS:
        return TrustLevel.MAINTAINER
    return TrustLevel.UNKNOWN


def extract_expressions(text: str) -> tuple[ExpressionMatch, ...]:
    matches: list[ExpressionMatch] = []
    for match in EXPRESSION_PATTERN.finditer(text):
        inner = match.group(1).strip()
        if not inner or len(inner) > MAX_EXPRESSION_LENGTH:
            continue
        matches.append(
            ExpressionMatch(
                raw=match.group(0),
                inner=inner,
                normalised=_normalise_expression(inner),
            )
        )
    return tuple(matches)


def classify_expression(inner: str, trigger_events: tuple[str, ...]) -> UntrustedSource | None:
    normalised = _normalise_expression(inner)
    if not normalised.startswith("github.") and not normalised.startswith("github["):
        # secrets.*, env.*, steps.*, inputs.* are not automatically untrusted
        # public content. workflow_call inputs remain actor-dependent.
        if normalised.startswith("inputs.") or normalised == "inputs":
            if _trigger_allows(trigger_events, ACTOR_DEPENDENT_EVENTS):
                return UntrustedSource(
                    field=normalised,
                    trust=TrustLevel.ACTOR_DEPENDENT,
                    label="workflow input (actor-dependent)",
                )
            return None
        return None

    field = normalised.removeprefix("github.")
    if any(
        field == prefix or field.startswith(f"{prefix}.") for prefix in TRUSTED_OR_NEUTRAL_PREFIXES
    ):
        return None

    if field.startswith("event.inputs") or field == "event.inputs":
        if _trigger_allows(trigger_events, ACTOR_DEPENDENT_EVENTS):
            return UntrustedSource(
                field=field,
                trust=TrustLevel.ACTOR_DEPENDENT,
                label="workflow_dispatch or workflow_call input",
            )
        return None

    for catalogue_field, trust in SOURCE_CATALOGUE.items():
        if field == catalogue_field or field.startswith(f"{catalogue_field}."):
            if not _source_applies(catalogue_field, trigger_events):
                return None
            return UntrustedSource(
                field=field,
                trust=trust,
                label=_source_label(catalogue_field, trust),
            )
    return None


def is_pr_head_checkout_expression(inner: str) -> bool:
    field = _normalise_expression(inner).removeprefix("github.")
    return field in PR_HEAD_CHECKOUT_FIELDS or any(
        field.startswith(f"{item}.") for item in PR_HEAD_CHECKOUT_FIELDS
    )


def is_pr_head_repository_expression(inner: str) -> bool:
    field = _normalise_expression(inner).removeprefix("github.")
    return field in PR_HEAD_REPO_FIELDS


def default_shell(runner_labels: tuple[str, ...], explicit: str | None) -> ShellKind:
    if explicit:
        lowered = explicit.strip().lower()
        mapping = {
            "bash": ShellKind.BASH,
            "sh": ShellKind.SH,
            "powershell": ShellKind.POWERSHELL,
            "pwsh": ShellKind.PWSH,
            "cmd": ShellKind.CMD,
            "python": ShellKind.PYTHON,
        }
        return mapping.get(lowered, ShellKind.UNKNOWN)
    joined = " ".join(label.lower() for label in runner_labels)
    if "windows" in joined:
        return ShellKind.PWSH
    return ShellKind.BASH


def shell_remediation(shell: ShellKind) -> str:
    if shell in {ShellKind.BASH, ShellKind.SH}:
        return (
            "Pass the value through `env` and expand the environment variable as data. "
            'Prefer `printf %s "$VAR"` or quoted expansion; do not splice untrusted '
            "content into a Bash script with `${{ }}`. Environment assignment does not "
            "remove every injection case if the variable is later expanded unquoted."
        )
    if shell in {ShellKind.POWERSHELL, ShellKind.PWSH}:
        return (
            "Pass the value through `env` and read `$env:VAR` as data. "
            "Avoid interpolating `${{ }}` into PowerShell source. EncodedCommand and "
            "Invoke-Expression remain unsafe if they consume the untrusted string."
        )
    if shell is ShellKind.CMD:
        return (
            "Pass the value through `env` and use `%VAR%` only with care: cmd.exe "
            "metacharacters in environment values can still be interpreted. "
            "Prefer a safer shell or structured processing."
        )
    return (
        "Pass untrusted values through `env` and handle them as data in the selected "
        "interpreter. Moving a value to `env` does not by itself eliminate injection."
    )


def _normalise_expression(inner: str) -> str:
    compact = re.sub(r"\s+", "", inner.strip())
    compact = compact.replace("['", ".").replace('["', ".")
    compact = compact.replace("']", "").replace('"]', "")
    return compact.lower()


def _trigger_allows(trigger_events: tuple[str, ...], allowed: frozenset[str]) -> bool:
    return any(event.lower() in allowed for event in trigger_events)


def _source_applies(field: str, trigger_events: tuple[str, ...]) -> bool:
    events = {event.lower() for event in trigger_events}
    if field.startswith(("event.pull_request", "event.review")) or field == "head_ref":
        return bool(events & EXTERNAL_PR_EVENTS)
    if field.startswith(("event.issue", "event.comment")):
        return bool(events & {"issues", "issue_comment", "pull_request", "pull_request_target"})
    if field.startswith("event.discussion"):
        return bool(events & {"discussion", "discussion_comment"})
    if field.startswith(("event.inputs", "event.client_payload")):
        return bool(events & ACTOR_DEPENDENT_EVENTS)
    if field.startswith(("event.head_commit", "event.commits")):
        return bool(events & {"push", "pull_request"})
    return True


def _source_label(field: str, trust: TrustLevel) -> str:
    if trust is TrustLevel.PUBLIC_USER:
        return f"public user-controlled content ({field})"
    if trust is TrustLevel.EXTERNAL:
        return f"fork or pull-request controlled content ({field})"
    if trust is TrustLevel.ACTOR_DEPENDENT:
        return f"manually supplied workflow input ({field})"
    if trust is TrustLevel.COLLABORATOR:
        return f"collaborator-influenceable content ({field})"
    return field
