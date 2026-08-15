from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from gha_threatlens.cli import cli
from gha_threatlens.constants import EXIT_OK, EXIT_THRESHOLD, EXIT_USER
from gha_threatlens.engine import ScanOptions, scan
from gha_threatlens.models import Severity
from gha_threatlens.reporters.json_reporter import render_json
from gha_threatlens.reporters.markdown import render_markdown
from tests.conftest import FIXTURES, FROZEN_TIME, scan_workflow_text

SAFE = FIXTURES / "repositories" / "safe"
PR_CHAIN = FIXTURES / "repositories" / "pr_chain"
MALFORMED = FIXTURES / "repositories" / "malformed"
MIXED = FIXTURES / "repositories" / "mixed"
GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "safe.json"


def test_cli_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_rules_list_and_explain() -> None:
    runner = CliRunner()
    listed = runner.invoke(cli, ["rules", "list"])
    assert listed.exit_code == 0
    assert "GHAT-001" in listed.output
    assert "GHAT-004" in listed.output
    explained = runner.invoke(cli, ["explain", "GHAT-003"])
    assert explained.exit_code == 0
    assert "CWE-78" in explained.output or "interpreter" in explained.output.lower()
    missing = runner.invoke(cli, ["explain", "GHAT-999"])
    assert missing.exit_code == EXIT_USER


def test_scenario_a_safe_repository() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(SAFE), "--no-color"])
    assert result.exit_code == EXIT_OK
    assert "CRIT" not in result.output
    assert "HIGH" not in result.output.split()


def test_scenario_f_fail_on(tmp_path: Path) -> None:
    runner = CliRunner()
    high = runner.invoke(cli, ["scan", str(PR_CHAIN), "--fail-on", "high", "--no-color"])
    assert high.exit_code == EXIT_THRESHOLD
    safe = runner.invoke(cli, ["scan", str(SAFE), "--fail-on", "high", "--no-color"])
    assert safe.exit_code == EXIT_OK


def test_cli_json_stdout_is_pure_json() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(SAFE), "--format", "json"])
    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1.0.0"
    assert payload["tool"]["name"] == "GHA-ThreatLens"
    assert "files_scanned" in payload
    assert isinstance(payload["findings"], list)


def test_cli_sarif_output_file(tmp_path: Path) -> None:
    runner = CliRunner()
    dest = tmp_path / "results.sarif"
    result = runner.invoke(
        cli,
        ["scan", str(PR_CHAIN), "--format", "sarif", "--output", str(dest), "--no-color"],
    )
    assert result.exit_code == EXIT_OK
    assert result.output == ""
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert payload["$schema"]
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "GHA-ThreatLens"
    assert run["tool"]["driver"]["rules"]
    locations = run["results"][0]["locations"][0]["physicalLocation"]
    assert "startLine" in locations["region"]
    assert locations["region"]["startLine"] >= 1
    assert not locations["artifactLocation"]["uri"].startswith("/")


def test_cli_min_severity_and_quiet() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(PR_CHAIN), "--min-severity", "critical", "--quiet", "--no-color"],
    )
    assert result.exit_code == EXIT_OK
    assert "GHAT-002" not in result.output or "CRIT" in result.output


def test_malformed_does_not_crash() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(MALFORMED), "--format", "json"])
    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["diagnostics"]
    assert payload["summary"]["files_scanned"] == 0


def test_mixed_malformed_still_reports_valid() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(MIXED), "--format", "json"])
    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert payload["summary"]["files_scanned"] >= 1
    assert payload["diagnostics"]


def test_empty_repository(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--no-color"])
    assert result.exit_code == EXIT_OK


def test_invalid_path() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "/definitely/missing/gha-threatlens-target"])
    assert result.exit_code == EXIT_USER


def test_markdown_escapes_untrusted_content(tmp_path: Path) -> None:
    result = scan_workflow_text(
        tmp_path,
        """
name: issues
on: issues
permissions:
  contents: read
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
""".lstrip(),
    )
    rendered = render_markdown(result)
    assert "<script>" not in rendered
    assert json.loads(json.dumps({"report": rendered}))


def test_json_golden_safe_repository() -> None:
    result = scan(SAFE, ScanOptions(clock=lambda: FROZEN_TIME))
    payload = json.loads(render_json(result))
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert payload["findings"] == expected["findings"]
    assert payload["attack_paths"] == expected["attack_paths"]
    assert payload["summary"]["highest_severity"] == expected["summary"]["highest_severity"]
    assert payload["schema_version"] == expected["schema_version"]


def test_engine_scan_options_min_severity(tmp_path: Path) -> None:
    from tests.conftest import fixture_text

    text = fixture_text("vulnerable", "mutable_action_minimal.yml")
    full = scan_workflow_text(tmp_path, text)
    directory = tmp_path / "repo"
    workflows = directory / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "w.yml").write_text(text, encoding="utf-8")
    filtered = scan(
        directory, ScanOptions(min_severity=Severity.CRITICAL, clock=lambda: FROZEN_TIME)
    )
    assert full.findings
    assert filtered.findings == () or all(
        item.severity is Severity.CRITICAL for item in filtered.findings
    )
