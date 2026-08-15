"""Click CLI. Exit handling stays here; library functions do not call sys.exit."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TextIO

import click

from gha_threatlens.constants import EXIT_INTERNAL, EXIT_OK, EXIT_THRESHOLD, EXIT_USER, TOOL_NAME
from gha_threatlens.engine import ScanOptions, meets_fail_on, scan, tool_version
from gha_threatlens.errors import ThreatLensError
from gha_threatlens.models import ReportFormat, Severity
from gha_threatlens.reporters import render
from gha_threatlens.rules import all_rules, rule_by_id

FORMAT_CHOICES = [item.value for item in ReportFormat]
SEVERITY_CHOICES = [item.value for item in Severity]


class OrderedGroup(click.Group):
    def list_commands(self, ctx: click.Context) -> list[str]:
        return list(self.commands)


@click.group(cls=OrderedGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(tool_version(), prog_name="gha-threatlens")
def cli() -> None:
    """Offline static analysis and attack-path correlation for GitHub Actions workflows."""


@cli.command("scan")
@click.argument(
    "path",
    required=False,
    default=".",
    metavar="PATH",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(FORMAT_CHOICES, case_sensitive=False),
    default=ReportFormat.TERMINAL.value,
    show_default=True,
    help="Report format.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the report to PATH instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_CHOICES, case_sensitive=False),
    default=None,
    help="Exit 1 when a finding or attack path meets this severity or higher.",
)
@click.option(
    "--min-severity",
    type=click.Choice(SEVERITY_CHOICES, case_sensitive=False),
    default=Severity.INFORMATIONAL.value,
    show_default=True,
    help="Omit findings and paths below this severity from the report.",
)
@click.option("--no-color", is_flag=True, help="Disable ANSI colour in terminal output.")
@click.option("--quiet", is_flag=True, help="Suppress the terminal summary; still print findings.")
def scan_command(
    path: str,
    fmt: str,
    output: Path | None,
    fail_on: str | None,
    min_severity: str,
    no_color: bool,
    quiet: bool,
) -> None:
    """Scan PATH for GitHub Actions workflow risks.

    PATH defaults to the current directory. Local scans make no network
    requests and do not read GitHub tokens.
    """

    report_format = ReportFormat(fmt.lower())
    color = _use_color(no_color=no_color, fmt=report_format, output=output)
    try:
        result = scan(path, ScanOptions(min_severity=Severity(min_severity.lower())))
        text = render(result, report_format, color=color, quiet=quiet)
        _write_output(text, output, report_format)
    except ThreatLensError as exc:
        click.echo(exc.message, err=True)
        raise SystemExit(EXIT_USER) from exc
    except OSError as exc:
        click.echo(f"Could not complete the scan: {exc}", err=True)
        raise SystemExit(EXIT_USER) from exc

    if fail_on is not None and meets_fail_on(result, Severity(fail_on.lower())):
        raise SystemExit(EXIT_THRESHOLD)
    raise SystemExit(EXIT_OK)


@cli.group("rules")
def rules_group() -> None:
    """Inspect shipped detection rules."""


@rules_group.command("list")
def rules_list() -> None:
    """List shipped rule identifiers."""

    for rule in all_rules():
        click.echo(f"{rule.spec.rule_id}  {rule.spec.title}")


@cli.command("explain")
@click.argument("rule_id")
def explain_command(rule_id: str) -> None:
    """Print metadata and remediation for RULE_ID."""

    rule = rule_by_id(rule_id)
    if rule is None:
        click.echo(
            f"Unknown rule ID {rule_id!r}. Use `gha-threatlens rules list` for valid identifiers.",
            err=True,
        )
        raise SystemExit(EXIT_USER)
    spec = rule.spec
    click.echo(f"{spec.rule_id}: {spec.title}")
    click.echo(spec.summary)
    click.echo(f"Category: {spec.category}")
    click.echo(f"Default severity guidance: {spec.default_severity}")
    click.echo(f"Applies to: {spec.applicable}")
    click.echo("Remediation:")
    click.echo(spec.remediation.strip())
    if spec.references:
        click.echo("References:")
        for item in spec.references:
            click.echo(f"- {item.title}: {item.url}")


@cli.command("version")
def version_command() -> None:
    """Print the tool version."""

    click.echo(f"{TOOL_NAME} {tool_version()}")


def _use_color(*, no_color: bool, fmt: ReportFormat, output: Path | None) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if fmt is not ReportFormat.TERMINAL:
        return False
    if output is not None:
        return False
    return sys.stdout.isatty()


def _write_output(text: str, output: Path | None, fmt: ReportFormat) -> None:
    if output is None:
        stream: TextIO = sys.stdout
        stream.write(text)
        if not text.endswith("\n") and fmt is ReportFormat.TERMINAL:
            stream.write("\n")
        return
    if output.exists() and output.is_dir():
        raise ThreatLensError(f"Output path is a directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main() -> None:
    try:
        cli.main(standalone_mode=True)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"Internal error: {exc}", err=True)
        raise SystemExit(EXIT_INTERNAL) from exc
