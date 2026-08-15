from __future__ import annotations

from gha_threatlens.models import ActionRefKind, JobPurpose
from gha_threatlens.normalizer import infer_job_purpose, parse_action_ref
from tests.conftest import scan_workflow_text


def test_reusable_workflow_mutable_ref(tmp_path) -> None:
    parsed = parse_action_ref("org/repo/.github/workflows/ci.yml@v1")
    assert parsed.kind is ActionRefKind.REUSABLE_WORKFLOW
    assert parsed.is_immutable_sha is False
    result = scan_workflow_text(
        tmp_path,
        """
name: reuse
on: workflow_call
permissions:
  contents: read
jobs:
  call:
    uses: org/repo/.github/workflows/ci.yml@v1
""".lstrip(),
    )
    assert any(item.rule_id == "GHAT-001" for item in result.findings)


def test_job_purpose_inference() -> None:
    assert infer_job_purpose("publish", "Release to PyPI", ()) is JobPurpose.RELEASE
    assert infer_job_purpose("unit-tests", None, ()) is JobPurpose.TEST
    assert infer_job_purpose("compile", None, ()) is JobPurpose.BUILD
