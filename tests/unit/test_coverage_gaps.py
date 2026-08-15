from __future__ import annotations

import json
from datetime import datetime
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from gha_threatlens.cli import _use_color, _write_output, cli, main
from gha_threatlens.constants import EXIT_INTERNAL, EXIT_USER
from gha_threatlens.correlation import _first, missing_edges
from gha_threatlens.discovery import discover_workflows
from gha_threatlens.engine import ScanOptions, scan, tool_version
from gha_threatlens.errors import ThreatLensError
from gha_threatlens.execution import classify_execution, persist_credentials, uses_secrets
from gha_threatlens.models import (
    ActionRef,
    ActionRefKind,
    Confidence,
    DiagnosticKind,
    Fact,
    FactKind,
    JobPurpose,
    PermissionAccess,
    PermissionPreset,
    PermissionSet,
    ReportFormat,
    ShellKind,
    SourceLocation,
    StepIR,
    TrustLevel,
)
from gha_threatlens.normalizer import parse_action_ref
from gha_threatlens.permissions import (
    has_high_impact_write,
    mapping_from_permission_set,
    parse_permissions,
    privilege_label,
)
from gha_threatlens.reporters import render
from gha_threatlens.reporters.json_reporter import render_json
from gha_threatlens.reporters.markdown import render_markdown
from gha_threatlens.reporters.terminal import _plain, render_terminal
from gha_threatlens.scoring import (
    apply_severity_guardrail,
    breakdown,
    impact_points,
    privilege_points,
)
from gha_threatlens.trust import (
    classify_expression,
    default_shell,
    extract_expressions,
    infer_event_trust,
    is_pr_head_repository_expression,
    shell_remediation,
)
from tests.conftest import fixture_text, scan_workflow_text


def test_shell_remediation_variants() -> None:
    assert "printf" in shell_remediation(ShellKind.BASH)
    assert "PowerShell" in shell_remediation(ShellKind.PWSH)
    assert "cmd.exe" in shell_remediation(ShellKind.CMD)
    assert "env" in shell_remediation(ShellKind.UNKNOWN).lower()
    assert default_shell(("windows-latest",), None) is ShellKind.PWSH
    assert default_shell(("ubuntu-latest",), "pwsh") is ShellKind.PWSH


def test_bracket_expression_normalisation() -> None:
    matches = extract_expressions("${{ github['event']['issue']['title'] }}")
    assert matches
    source = classify_expression(matches[0].inner, ("issues",))
    assert source is not None


def test_workflow_dispatch_input_in_run(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: dispatch
on: workflow_dispatch
permissions:
  contents: read
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.inputs.name }}"
""".lstrip(),
    )
    assert any(item.rule_id == "GHAT-003" for item in result.findings)


def test_permission_helpers() -> None:
    location = SourceLocation(path="w.yml", start_line=1, start_column=1)
    write_all = parse_permissions("write-all", "w.yml", location)
    assert privilege_label(write_all) == "write-all"
    read_all = parse_permissions("read-all", "w.yml", location)
    assert privilege_label(read_all) == "read-all"
    empty = parse_permissions({}, "w.yml", location)
    assert privilege_label(empty) == "none"
    weird = parse_permissions("maybe", "w.yml", location)
    assert privilege_label(weird) == "unknown-default"
    explicit = parse_permissions({"contents": "write", "issues": "read"}, "w.yml", location)
    assert "contents" in privilege_label(explicit)
    assert mapping_from_permission_set(explicit)["contents"] is PermissionAccess.WRITE
    unknown_scope = parse_permissions({"contents": "other"}, "w.yml", location)
    assert unknown_scope.scopes["contents"] is PermissionAccess.UNKNOWN
    read_only = parse_permissions({"contents": "read"}, "w.yml", location)
    assert privilege_label(read_only) == "read"
    none_explicit = parse_permissions({"contents": "none"}, "w.yml", location)
    assert privilege_label(none_explicit) == "none"
    assert has_high_impact_write(write_all) is True
    listed = parse_permissions(["nope"], "w.yml", location)
    assert listed.preset is PermissionPreset.UNSET


def test_scoring_privilege_additions() -> None:
    unset = PermissionSet(preset=PermissionPreset.UNSET)
    points, note = privilege_points(unset, oidc=True, secrets_visible=True, self_hosted=True)
    assert points >= 8
    assert "unknown" in note.lower() or "OIDC" in note or "self-hosted" in note
    impact, _ = impact_points(
        permissions=PermissionSet(
            preset=PermissionPreset.EXPLICIT,
            declared=True,
            scopes={"packages": PermissionAccess.WRITE},
        ),
        purpose=JobPurpose.RELEASE,
        secrets_visible=True,
        oidc=True,
    )
    assert impact >= 16


def test_runs_on_list_and_environment_mapping(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: env
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: [self-hosted, linux]
    environment:
      name: production
    needs: [setup]
    if: success()
    steps:
      - run: echo hi
""".lstrip(),
    )
    assert result.summary.files_scanned == 1


def test_boolean_on_key_warning(tmp_path: Path) -> None:
    from gha_threatlens.normalizer import normalise_workflow
    from gha_threatlens.parser import load_yaml_document

    text = "true: push\njobs: {}\n"
    path = tmp_path / "w.yml"
    path.write_text(text, encoding="utf-8")
    document = load_yaml_document(path, "w.yml", text)
    # Construct a mapping with boolean True if the parser kept `true`.
    data = document.data
    if True in data or "true" in data:
        ir = normalise_workflow(data, "w.yml", text)
        assert ir.triggers or ir.parse_warnings


def test_persist_credentials_and_secrets() -> None:
    step = StepIR(
        index=0,
        name=None,
        uses=ActionRef(
            raw="actions/checkout@abc",
            kind=ActionRefKind.GITHUB,
            owner="actions",
            repository="checkout",
        ),
        run=None,
        shell=ShellKind.BASH,
        environment={"TOKEN": "${{ secrets.NPM_TOKEN }}"},
        inputs={"persist-credentials": "false"},
        location=SourceLocation(path="w.yml", start_line=1, start_column=1),
    )
    assert persist_credentials(step) is False
    assert uses_secrets(step) is True


def test_checkout_path_execution(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: path
on: pull_request_target
permissions:
  contents: write
  id-token: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: pr
          persist-credentials: false
      - run: ./pr/scripts/test.sh
      - run: echo ${{ secrets.DEPLOY_KEY }}
""".lstrip(),
    )
    assert any(item.rule_id == "GHAT-004" for item in result.findings)


def test_markdown_includes_attack_path(tmp_path: Path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("vulnerable", "pr_target_chain.yml"))
    text = render_markdown(result)
    assert "Attack paths" in text
    assert "PATH" in text
    payload = render_json(result)
    parsed = json.loads(payload)
    assert parsed["attack_paths"]
    assert parsed["findings"]


def test_terminal_plain_and_empty(tmp_path: Path) -> None:
    result = scan_workflow_text(tmp_path, fixture_text("hardened", "least_privilege.yml"))
    plain = _plain(result, quiet=False)
    assert "GHA-ThreatLens" in plain
    quiet = _plain(result, quiet=True)
    colourful = render_terminal(result, color=True, quiet=False)
    assert "files=" in colourful or "GHA-ThreatLens" in colourful
    assert isinstance(quiet, str)
    chain = scan_workflow_text(tmp_path, fixture_text("vulnerable", "pr_target_chain.yml"))
    with_findings = _plain(chain, quiet=False)
    assert "GHAT-004" in with_findings
    assert "PATH" in with_findings
    markdown = render(chain, ReportFormat.MARKDOWN, color=False, quiet=False)
    assert markdown.startswith("#")


def test_missing_edges_helper() -> None:
    facts = (
        Fact(
            kind=FactKind.PRIVILEGED_PR_TARGET,
            workflow_path="w.yml",
            job_id="t",
            step_index=None,
            evidence=(),
            details={},
            confidence=Confidence.HIGH,
        ),
    )
    missing = missing_edges(facts, "w.yml", "t")
    assert "attacker-controlled checkout" in missing
    assert "execution after checkout" in missing


def test_missing_trigger_edge() -> None:
    facts = (
        Fact(
            kind=FactKind.ATTACKER_CHECKOUT,
            workflow_path="w.yml",
            job_id="t",
            step_index=0,
            evidence=(),
            details={},
            confidence=Confidence.HIGH,
        ),
    )
    missing = missing_edges(facts, "w.yml", "t")
    assert "pull_request_target trigger" in missing
    assert _first([], FactKind.ATTACKER_CHECKOUT) is None


def test_cli_output_to_file(tmp_path: Path) -> None:
    runner = CliRunner()
    dest = tmp_path / "out" / "report.json"
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        fixture_text("hardened", "least_privilege.yml"), encoding="utf-8"
    )
    result = runner.invoke(cli, ["scan", str(repo), "--format", "json", "--output", str(dest)])
    assert result.exit_code == 0
    assert dest.exists()
    as_dir = tmp_path / "dir"
    as_dir.mkdir()
    failed = runner.invoke(cli, ["scan", str(repo), "--output", str(as_dir)])
    assert failed.exit_code == 2


def test_malformed_yaml_diagnostic(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "bad.yml").write_text("this is not: [ valid\n  yaml:\n", encoding="utf-8")
    (workflows / "ok.yml").write_text(
        fixture_text("hardened", "least_privilege.yml"), encoding="utf-8"
    )
    result = scan(tmp_path, ScanOptions(clock=lambda: datetime(2026, 1, 1)))
    assert result.diagnostics
    assert result.summary.files_scanned >= 1


def test_unsupported_list_document(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "list.yml").write_text("- just\n- a list\n", encoding="utf-8")
    result = scan(tmp_path)
    assert any(item.kind.value == "unsupported" for item in result.diagnostics)


def test_parse_action_unknown() -> None:
    assert parse_action_ref("not a ref @@").kind is ActionRefKind.UNKNOWN


def test_commit_message_on_push(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: push
on: push
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
""".lstrip(),
    )
    assert any(item.rule_id == "GHAT-003" for item in result.findings)


def test_trusted_github_sha_not_flagged(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: sha
on: issues
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
""".lstrip(),
    )
    assert [item for item in result.findings if item.rule_id == "GHAT-003"] == []


def test_runner_group_mapping(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: group
on: push
permissions:
  contents: read
jobs:
  t:
    runs-on:
      group: acme-runners
      labels: [self-hosted, linux]
    steps:
      - run: echo hi
""".lstrip(),
    )
    assert result.summary.files_scanned == 1


def test_persist_credentials_non_checkout() -> None:
    step = StepIR(
        index=0,
        name=None,
        uses=None,
        run="echo hi",
        shell=ShellKind.BASH,
        environment={},
        inputs={},
        location=SourceLocation(path="w.yml", start_line=1, start_column=1),
    )
    assert persist_credentials(step) is True


def test_tool_version_fallback() -> None:
    with patch("gha_threatlens.engine.version", side_effect=PackageNotFoundError):
        assert tool_version() == "0.1.0"


def test_workflows_path_is_file(tmp_path: Path) -> None:
    github = tmp_path / ".github"
    github.mkdir()
    (github / "workflows").write_text("not a directory", encoding="utf-8")
    result = discover_workflows(tmp_path)
    assert result.files == ()
    assert any(item.kind is DiagnosticKind.UNSUPPORTED for item in result.diagnostics)


def test_hidden_and_non_yaml_entries_ignored(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / ".hidden.yml").write_text("name: hidden\n", encoding="utf-8")
    (workflows / "notes.txt").write_text("ignore", encoding="utf-8")
    (workflows / "nested").mkdir()
    result = discover_workflows(tmp_path)
    assert result.files == ()


def test_discussion_expression(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: d
on: discussion
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.discussion.title }}"
""".lstrip(),
    )
    assert any(item.rule_id == "GHAT-003" for item in result.findings)


def test_trust_catalogue_edges() -> None:
    assert infer_event_trust("not-a-real-event") is TrustLevel.UNKNOWN
    assert classify_expression("inputs.name", ("workflow_call",)) is not None
    assert classify_expression("inputs.name", ("push",)) is None
    assert classify_expression("github.event.inputs.x", ("push",)) is None
    assert classify_expression("github.event.not_a_field", ("issues",)) is None
    assert extract_expressions("${{   }}") == ()
    assert is_pr_head_repository_expression("github.event.pull_request.head.repo.full_name")
    assert (
        classify_expression("github.event.client_payload.x", ("repository_dispatch",)) is not None
    )


def test_job_level_write_and_empty_permissions(tmp_path: Path) -> None:
    job_write = scan_workflow_text(
        tmp_path,
        """
name: job-write
on: push
permissions:
  contents: read
jobs:
  publish:
    permissions:
      contents: write
      packages: write
    runs-on: ubuntu-latest
    steps:
      - run: echo publish
""".lstrip(),
        name="job-write.yml",
    )
    assert any(item.rule_id == "GHAT-002" for item in job_write.findings)
    empty = scan_workflow_text(
        tmp_path / "empty_repo",
        """
name: empty
on: push
permissions: {}
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""".lstrip(),
        name="empty.yml",
    )
    assert [item for item in empty.findings if item.rule_id == "GHAT-002"] == []


def test_execution_helpers() -> None:
    local = StepIR(
        index=0,
        name=None,
        uses=ActionRef(raw="./action", kind=ActionRefKind.LOCAL, path="./action"),
        run=None,
        shell=ShellKind.BASH,
        environment={},
        inputs={},
        location=SourceLocation(path="w.yml", start_line=1, start_column=1),
    )
    sink = classify_execution(local, None)
    assert sink is not None and sink.kind == "local_action"
    other = StepIR(
        index=1,
        name=None,
        uses=ActionRef(
            raw="actions/setup-python@abc",
            kind=ActionRefKind.GITHUB,
            owner="actions",
            repository="setup-python",
        ),
        run=None,
        shell=ShellKind.BASH,
        environment={},
        inputs={},
        location=SourceLocation(path="w.yml", start_line=2, start_column=1),
    )
    assert persist_credentials(other) is True
    checkout = StepIR(
        index=2,
        name=None,
        uses=ActionRef(raw="actions/checkout@abc", kind=ActionRefKind.GITHUB),
        run=None,
        shell=ShellKind.BASH,
        environment={},
        inputs={},
        location=SourceLocation(path="w.yml", start_line=3, start_column=1),
    )
    assert persist_credentials(checkout) is True


def test_cli_color_and_output_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert _use_color(no_color=False, fmt=ReportFormat.TERMINAL, output=None) is False
    monkeypatch.delenv("NO_COLOR")
    assert _use_color(no_color=True, fmt=ReportFormat.TERMINAL, output=None) is False
    assert _use_color(no_color=False, fmt=ReportFormat.JSON, output=None) is False
    assert _use_color(no_color=False, fmt=ReportFormat.TERMINAL, output=tmp_path / "x") is False
    with pytest.raises(ThreatLensError):
        _write_output("x", tmp_path, ReportFormat.JSON)
    _write_output("no-nl", None, ReportFormat.TERMINAL)


def test_cli_oserror_and_internal_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk")

    monkeypatch.setattr("gha_threatlens.cli.scan", boom)
    failed = runner.invoke(cli, ["scan", str(tmp_path), "--no-color"])
    assert failed.exit_code == EXIT_USER

    def explode(**_kwargs: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr("gha_threatlens.cli.cli.main", explode)
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == EXIT_INTERNAL


def test_import_main_module() -> None:
    import gha_threatlens.__main__ as module

    assert callable(module.main)


def test_workflows_directory_symlink_outside(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    scan_root = tmp_path / "scan"
    github = scan_root / ".github"
    github.mkdir(parents=True)
    (github / "workflows").symlink_to(outside)
    result = discover_workflows(scan_root)
    assert result.files == ()
    assert any(item.kind is DiagnosticKind.SYMLINK_SKIPPED for item in result.diagnostics)


def test_symlink_to_directory_inside_root(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    inner = tmp_path / "inner"
    inner.mkdir()
    (workflows / "nested.yml").symlink_to(inner)
    result = discover_workflows(tmp_path)
    assert any(item.kind is DiagnosticKind.UNREADABLE for item in result.diagnostics)


def test_scoring_remaining_branches() -> None:
    deploy = impact_points(
        permissions=PermissionSet(
            preset=PermissionPreset.EXPLICIT,
            declared=True,
            scopes={"pull-requests": PermissionAccess.WRITE},
        ),
        purpose=JobPurpose.DEPLOY,
        secrets_visible=False,
        oidc=False,
    )
    assert deploy[0] == 20
    oidc = impact_points(
        permissions=PermissionSet(
            preset=PermissionPreset.EXPLICIT,
            declared=True,
            scopes={"id-token": PermissionAccess.WRITE},
        ),
        purpose=JobPurpose.UNKNOWN,
        secrets_visible=False,
        oidc=True,
    )
    assert oidc[0] == 16
    secrets = impact_points(
        permissions=PermissionSet(preset=PermissionPreset.EMPTY, declared=True),
        purpose=JobPurpose.TEST,
        secrets_visible=True,
        oidc=False,
    )
    assert secrets[0] == 12
    score = breakdown(
        exposure=20,
        exploitability=30,
        privilege=20,
        impact=20,
        chain_evidence=10,
        applicable_mitigations=0,
        notes=("n",),
    )
    guarded = apply_severity_guardrail(score, purpose=JobPurpose.TEST, rule_id="GHAT-002")
    assert guarded[1].value == "high"


def test_jobs_not_mapping_warning(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: bad-jobs
on: push
jobs: []
""".lstrip(),
    )
    assert result.diagnostics
