"""Classify whether a step can execute checked-out repository content."""

from __future__ import annotations

import re
from dataclasses import dataclass

from gha_threatlens.models import ActionRefKind, Confidence, StepIR

_DIRECT = (
    re.compile(r"(?:^|[;\n&|]\s*)\./"),
    re.compile(r"(?:^|[;\n&|]\s*)(?:bash|sh|zsh)\s+\./"),
    re.compile(r"(?:^|[;\n&|]\s*)(?:python|python3|python2|node|ruby|perl|php)\s+\S+"),
    re.compile(r"(?:^|[;\n&|]\s*)(?:pwsh|powershell)(?:\.exe)?\s+-file\s+", re.I),
    re.compile(r"(?:^|[;\n&|]\s*)(?:cmd(?:\.exe)?)\s+/c\s+", re.I),
)

_HEURISTIC = (
    re.compile(r"\bnpm\s+(?:ci|install|test|run)\b"),
    re.compile(r"\byarn\b"),
    re.compile(r"\bpnpm\b"),
    re.compile(r"\bmake\b"),
    re.compile(r"\bpytest\b"),
    re.compile(r"\bpip(?:3)?\s+install\b"),
    re.compile(r"\bpoetry\s+install\b"),
    re.compile(r"\bhatch\s+run\b"),
    re.compile(r"\btox\b"),
    re.compile(r"\bnox\b"),
    re.compile(r"\bgo\s+(?:test|build|run)\b"),
    re.compile(r"\bcargo\s+(?:test|build|run)\b"),
    re.compile(r"\bmvnw?\b"),
    re.compile(r"\bgradlew\b"),
    re.compile(r"\bdotnet\s+(?:test|build|run)\b"),
    re.compile(r"\bbundle\s+install\b"),
    re.compile(r"\bcomposer\s+install\b"),
)


@dataclass(frozen=True)
class ExecutionSink:
    kind: str
    confidence: Confidence
    summary: str
    heuristic: bool


def classify_execution(step: StepIR, checkout_path: str | None) -> ExecutionSink | None:
    if step.uses is not None and step.uses.kind is ActionRefKind.LOCAL:
        return ExecutionSink(
            kind="local_action",
            confidence=Confidence.HIGH,
            summary="Local composite or JavaScript action from the checked-out tree.",
            heuristic=False,
        )
    if not step.run:
        return None
    script = step.run.strip()
    path_token = checkout_path.rstrip("/") if checkout_path else ""
    if (
        path_token
        and path_token in script
        and (
            _matches(_DIRECT, script)
            or re.search(rf"{re.escape(path_token)}/.+\.(sh|py|js|ps1)", script)
        )
    ):
        return ExecutionSink(
            kind="direct_path",
            confidence=Confidence.HIGH,
            summary=f"Command references the checkout path {path_token}.",
            heuristic=False,
        )
    if _matches(_DIRECT, script):
        return ExecutionSink(
            kind="direct_interpreter",
            confidence=Confidence.HIGH,
            summary="Local script or interpreter invocation against repository files.",
            heuristic=False,
        )
    if _matches(_HEURISTIC, script):
        return ExecutionSink(
            kind="lifecycle_or_build",
            confidence=Confidence.MEDIUM,
            summary="Package-manager or build command that commonly runs repository-controlled scripts.",
            heuristic=True,
        )
    return None


def uses_secrets(step: StepIR) -> bool:
    haystack = " ".join(
        [
            step.run or "",
            " ".join(step.environment.values()),
            " ".join(step.inputs.values()),
        ]
    )
    return (
        "secrets." in haystack.replace(" ", "").lower()
        or "${{secrets" in haystack.replace(" ", "").lower()
    )


def persist_credentials(step: StepIR) -> bool:
    if step.uses is None:
        return True
    if not _is_checkout(step):
        return True
    value = step.inputs.get("persist-credentials", "true").strip().lower()
    return value not in {"false", "0", "no"}


def _is_checkout(step: StepIR) -> bool:
    if step.uses is None:
        return False
    repo = f"{step.uses.owner}/{step.uses.repository}".lower() if step.uses.owner else ""
    return repo == "actions/checkout" or (step.uses.raw.lower().startswith("actions/checkout"))


def _matches(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)
