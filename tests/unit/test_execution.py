from __future__ import annotations

from gha_threatlens.execution import classify_execution
from gha_threatlens.models import (
    ActionRef,
    ActionRefKind,
    Confidence,
    ShellKind,
    SourceLocation,
    StepIR,
)


def _step(
    *, run: str | None = None, uses: ActionRef | None = None, inputs: dict[str, str] | None = None
) -> StepIR:
    return StepIR(
        index=1,
        name=None,
        uses=uses,
        run=run,
        shell=ShellKind.BASH,
        environment={},
        inputs=inputs or {},
        location=SourceLocation(path="w.yml", start_line=1, start_column=1),
    )


def test_direct_script_is_high_confidence() -> None:
    sink = classify_execution(_step(run="./scripts/test.sh"), None)
    assert sink is not None
    assert sink.confidence is Confidence.HIGH
    assert sink.heuristic is False


def test_npm_is_heuristic() -> None:
    sink = classify_execution(_step(run="npm test"), None)
    assert sink is not None
    assert sink.confidence is Confidence.MEDIUM
    assert sink.heuristic is True


def test_echo_is_not_execution() -> None:
    assert classify_execution(_step(run='echo "no repository script execution"'), None) is None


def test_local_action_is_execution() -> None:
    sink = classify_execution(
        _step(
            uses=ActionRef(
                raw="./.github/actions/x", kind=ActionRefKind.LOCAL, path="./.github/actions/x"
            )
        ),
        None,
    )
    assert sink is not None
    assert sink.kind == "local_action"
