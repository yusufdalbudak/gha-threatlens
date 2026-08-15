from gha_threatlens.models import ReportFormat, ScanResult
from gha_threatlens.reporters.json_reporter import render_json
from gha_threatlens.reporters.markdown import render_markdown
from gha_threatlens.reporters.sarif import render_sarif
from gha_threatlens.reporters.terminal import render_terminal


def render(result: ScanResult, fmt: ReportFormat, *, color: bool, quiet: bool) -> str:
    if fmt is ReportFormat.JSON:
        return render_json(result)
    if fmt is ReportFormat.MARKDOWN:
        return render_markdown(result)
    if fmt is ReportFormat.SARIF:
        return render_sarif(result)
    return render_terminal(result, color=color, quiet=quiet)
