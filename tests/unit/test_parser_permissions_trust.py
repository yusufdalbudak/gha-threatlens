from __future__ import annotations

from gha_threatlens.models import ActionRefKind, PermissionAccess, PermissionPreset, TrustLevel
from gha_threatlens.normalizer import normalise_workflow, parse_action_ref
from gha_threatlens.parser import load_yaml_document
from gha_threatlens.permissions import effective_job_permissions, parse_permissions
from gha_threatlens.trust import classify_expression, extract_expressions, infer_event_trust


def _ir(tmp_path, text: str):
    path = tmp_path / "w.yml"
    path.write_text(text, encoding="utf-8")
    document = load_yaml_document(path, "w.yml", text)
    return normalise_workflow(document.data, "w.yml", text)


def test_on_key_is_string_not_boolean(tmp_path) -> None:
    ir = _ir(
        tmp_path,
        "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo x\n",
    )
    assert ir.triggers[0].event_name == "push"


def test_on_list_and_mapping_forms(tmp_path) -> None:
    listed = _ir(tmp_path, "on: [push, pull_request]\njobs: {}\n")
    assert [t.event_name for t in listed.triggers] == ["pull_request", "push"]
    mapped = _ir(
        tmp_path,
        "on:\n  pull_request_target:\n  workflow_dispatch:\njobs: {}\n",
    )
    assert {t.event_name for t in mapped.triggers} == {"pull_request_target", "workflow_dispatch"}


def test_source_locations_are_one_based(tmp_path) -> None:
    ir = _ir(
        tmp_path,
        "name: demo\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
    )
    assert ir.location.start_line >= 1
    assert ir.jobs[0].steps[0].location.start_line >= 1
    assert ir.jobs[0].steps[0].location.start_column >= 1


def test_permissions_unset_is_unknown_not_write() -> None:
    parsed = parse_permissions(None, "w.yml", ir_location())
    assert parsed.preset is PermissionPreset.UNSET
    assert parsed.access_for("contents") is PermissionAccess.UNKNOWN


def test_permissions_empty_disables_all() -> None:
    parsed = parse_permissions({}, "w.yml", ir_location())
    assert parsed.preset is PermissionPreset.EMPTY
    assert parsed.access_for("contents") is PermissionAccess.NONE


def test_permissions_write_all_and_job_override() -> None:
    workflow = parse_permissions("write-all", "w.yml", ir_location())
    job = parse_permissions({"contents": "read"}, "w.yml", ir_location())
    assert workflow.access_for("packages") is PermissionAccess.WRITE
    effective = effective_job_permissions(workflow, job)
    assert effective.access_for("contents") is PermissionAccess.READ
    assert effective.access_for("packages") is PermissionAccess.NONE


def test_action_ref_kinds() -> None:
    remote = parse_action_ref("actions/checkout@v4")
    assert remote.kind is ActionRefKind.GITHUB
    assert remote.is_immutable_sha is False
    sha = parse_action_ref("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
    assert sha.is_immutable_sha is True
    local = parse_action_ref("./local-action")
    assert local.kind is ActionRefKind.LOCAL
    docker = parse_action_ref("docker://node:20")
    assert docker.kind is ActionRefKind.DOCKER
    reusable = parse_action_ref("org/repo/.github/workflows/ci.yml@main")
    assert reusable.kind is ActionRefKind.REUSABLE_WORKFLOW
    assert reusable.is_immutable_sha is False


def test_untrusted_expression_classification() -> None:
    issue = classify_expression("github.event.issue.title", ("issues",))
    assert issue is not None
    assert issue.trust is TrustLevel.PUBLIC_USER
    repo = classify_expression("github.repository", ("issues",))
    assert repo is None
    pr = classify_expression("github.event.pull_request.head.sha", ("pull_request_target",))
    assert pr is not None
    assert pr.trust is TrustLevel.EXTERNAL
    ignored = classify_expression("github.event.issue.title", ("push",))
    assert ignored is None


def test_extract_expressions_preserves_inner() -> None:
    matches = extract_expressions('echo "${{ github.event.issue.title }}"')
    assert len(matches) == 1
    assert "github.event.issue.title" in matches[0].normalised


def test_event_trust_catalogue() -> None:
    assert infer_event_trust("pull_request_target") is TrustLevel.EXTERNAL
    assert infer_event_trust("issues") is TrustLevel.PUBLIC_USER
    assert infer_event_trust("workflow_dispatch") is TrustLevel.ACTOR_DEPENDENT
    assert infer_event_trust("push") is TrustLevel.MAINTAINER


def ir_location():
    from gha_threatlens.models import SourceLocation

    return SourceLocation(path="w.yml", start_line=1, start_column=1)
