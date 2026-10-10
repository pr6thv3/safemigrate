"""Report formatters for SafeMigrate."""

import io
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from safemigrate.formatters.json import format_json
from safemigrate.formatters.sarif import format_sarif
from safemigrate.models import OutputFormat, ScanReport, Severity


def render_terminal_report(report: ScanReport, console: Console = None) -> str:
    """Renders human-readable report with Rich formatting or plain text."""
    if console is None:
        console = Console(no_color=not sys.stdout.isatty())

    # Header Panel
    header_text = (
        f"[bold blue]SafeMigrate[/bold blue] v{report.tool.get('version', '0.1.0')} "
        f"— PostgreSQL Migration Risk Analyzer\n"
        f"Target Engine: [cyan]{report.target_engine}[/cyan] (v{report.pg_version}) | "
        f"Runner Mode: [cyan]{report.migration_transaction_mode.value}[/cyan]"
    )
    console.print(Panel(header_text, title="SafeMigrate Scan", border_style="blue"))

    # Summary Table
    summary_table = Table(title="Scan Summary", show_header=True, header_style="bold")
    summary_table.add_column("Files Scanned", justify="center")
    summary_table.add_column("Statements", justify="center")
    summary_table.add_column("Findings", justify="center")
    summary_table.add_column("Critical", justify="center", style="bold red")
    summary_table.add_column("High", justify="center", style="red")
    summary_table.add_column("Medium", justify="center", style="yellow")
    summary_table.add_column("Low", justify="center", style="blue")
    summary_table.add_column("Parse Errors", justify="center", style="magenta")

    summary_table.add_row(
        str(report.summary.total_files),
        str(report.summary.total_statements),
        str(report.summary.total_findings),
        str(report.summary.severities.get("critical", 0)),
        str(report.summary.severities.get("high", 0)),
        str(report.summary.severities.get("medium", 0)),
        str(report.summary.severities.get("low", 0)),
        str(report.summary.parse_errors),
    )
    console.print(summary_table)

    # Diagnostics Callout
    if report.diagnostics:
        console.print("\n[bold magenta]Diagnostics / Notices:[/bold magenta]")
        for diag in report.diagnostics:
            loc = f"{diag.file}:{diag.line}:{diag.column}" if diag.file else "unknown"
            console.print(f" • [{diag.type.value.upper()}] at {loc}: {diag.message}")

    # Findings Table
    if report.findings:
        console.print("\n[bold red]Migration Findings:[/bold red]")
        findings_table = Table(show_header=True, header_style="bold")
        findings_table.add_column("Rule", justify="left")
        findings_table.add_column("Sev", justify="center")
        findings_table.add_column("Conf", justify="center")
        findings_table.add_column("Location", justify="left")
        findings_table.add_column("Statement", justify="left")

        for f in report.findings:
            sev_style = "bold red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
            findings_table.add_row(
                f.rule_id,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.confidence.value,
                f"{f.file}:{f.line}:{f.column}",
                f.statement[:60] + ("..." if len(f.statement) > 60 else ""),
            )
        console.print(findings_table)

        # Detailed Recommendations Panel
        for idx, f in enumerate(report.findings, start=1):
            details = (
                f"[bold]Rule:[/bold] {f.rule_id} — {f.rule_title}\n"
                f"[bold]Location:[/bold] {f.file}:{f.line}:{f.column}\n"
                f"[bold]Statement:[/bold] {f.statement}\n"
                f"[bold]Evidence:[/bold] {f.evidence}\n"
                f"[bold]Explanation:[/bold] {f.explanation}\n"
                f"[bold green]Recommendation:[/bold green] {f.recommendation}"
            )
            console.print(Panel(details, title=f"Finding #{idx} ({f.rule_id})", border_style="red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"))

    # Policy Banner
    if report.policy.exit_code == 0:
        console.print(Panel("[bold green]PASSED: No findings breached policy threshold.[/bold green]", border_style="green"))
    elif report.policy.exit_code == 1:
        console.print(Panel(f"[bold red]FAILED (POLICY): Findings breached policy threshold ({report.policy.fail_on.value}).[/bold red]", border_style="red"))
    elif report.policy.exit_code == 2:
        console.print(Panel("[bold magenta]FAILED (PARSE/SYNTAX): Input could not be reliably analyzed. Failing closed.[/bold magenta]", border_style="magenta"))
    else:
        console.print(Panel("[bold red]FAILED (RUNTIME): Unexpected analyzer error.[/bold red]", border_style="red"))

    return ""


def format_report(report: ScanReport, fmt: OutputFormat) -> str:
    """Formats report according to requested OutputFormat."""
    if fmt == OutputFormat.JSON:
        return format_json(report)
    elif fmt == OutputFormat.SARIF:
        return format_sarif(report)
    else:
        # text / human format
        string_io = io.StringIO()
        string_io_console = Console(file=string_io, record=True, width=100)
        render_terminal_report(report, string_io_console)
        return string_io_console.export_text()
