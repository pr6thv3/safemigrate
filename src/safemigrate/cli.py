"""SafeMigrate CLI built with Typer and Rich."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from safemigrate import __version__
from safemigrate.analyzer import MigrationAnalyzer
from safemigrate.formatters import format_report, render_terminal_report
from safemigrate.formatters.json import format_json
from safemigrate.formatters.sarif import format_sarif
from safemigrate.models import OutputFormat, Severity, TransactionMode
from safemigrate.rules import get_all_rules_info, get_rule_info

app = typer.Typer(
    name="safemigrate",
    help="SafeMigrate — Automated PostgreSQL schema migration risk analyzer using SQLGlot AST parsing",
    add_completion=False,
    no_args_is_help=True,
)

rules_app = typer.Typer(
    name="rules",
    help="Inspect SafeMigrate rule catalogue and documentation",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(rules_app, name="rules")


def version_callback(value: bool):
    if value:
        typer.echo(f"safemigrate {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show SafeMigrate version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """SafeMigrate CLI: Pure-static PostgreSQL schema migration risk analyzer."""
    pass


@app.command(name="scan")
def scan_command(
    path: Path = typer.Argument(
        ...,
        help="Path to SQL migration file or directory of migrations to analyze.",
    ),
    fail_on: Severity = typer.Option(
        Severity.HIGH,
        "--fail-on",
        help="Minimum severity threshold triggering policy failure (Exit Code 1).",
    ),
    migration_transaction_mode: TransactionMode = typer.Option(
        TransactionMode.UNKNOWN,
        "--migration-transaction-mode",
        help="External migration runner transaction wrapping mode [wrapped|not_wrapped|unknown].",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.HUMAN,
        "--format",
        "-f",
        help="Output report format [human|text|json|sarif].",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Optional destination file path to write report to (defaults to stdout).",
    ),
    pg_version: int = typer.Option(
        18,
        "--pg-version",
        help="Target major PostgreSQL version.",
    ),
    deterministic: bool = typer.Option(
        False,
        "--deterministic",
        help="Enable bit-for-bit deterministic output (nullifies timestamps).",
    ),
):
    """Statically scans PostgreSQL migration files for schema risks, lock hazards, and incompatibilities."""
    try:
        analyzer = MigrationAnalyzer(
            pg_version=pg_version,
            migration_transaction_mode=migration_transaction_mode,
            fail_on=fail_on,
            deterministic=deterministic,
        )

        report = analyzer.scan_path(path)

        # Format report
        if format == OutputFormat.JSON:
            output_content = format_json(report)
        elif format == OutputFormat.SARIF:
            output_content = format_sarif(report)
        else:
            # human or text
            output_content = format_report(report, format)

        # Write or print
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(output_content, encoding="utf-8")
            if format == OutputFormat.HUMAN:
                render_terminal_report(report)
        else:
            if format in (OutputFormat.JSON, OutputFormat.SARIF, OutputFormat.TEXT):
                sys.stdout.write(output_content + "\n")
            else:
                render_terminal_report(report)

        # Exit with policy exit code
        sys.exit(report.policy.exit_code)

    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"SafeMigrate unexpected runtime error: {exc}\n")
        sys.exit(3)


@rules_app.command(name="list")
def rules_list():
    """Lists all registered rules in the SafeMigrate catalogue."""
    rules = get_all_rules_info()
    table = Table(title="SafeMigrate Rule Catalogue", show_header=True, header_style="bold")
    table.add_column("Rule ID", justify="left", style="bold cyan")
    table.add_column("Title", justify="left")
    table.add_column("Default Sev", justify="center")
    table.add_column("Conf", justify="center")
    table.add_column("Release Status", justify="left")
    table.add_column("Description", justify="left")

    for r in rules:
        sev_color = "red" if r.default_severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
        table.add_row(
            r.rule_id,
            r.title,
            f"[{sev_color}]{r.default_severity.value}[/{sev_color}]",
            r.confidence.value,
            r.status,
            r.description,
        )

    console = Console()
    console.print(table)
    raise typer.Exit(code=0)


@rules_app.command(name="show")
def rules_show(
    rule_id: str = typer.Argument(..., help="Rule identifier to inspect (e.g. SM001, SM002)."),
):
    """Displays detailed documentation, rationale, and remediation patterns for a rule."""
    rule = get_rule_info(rule_id)
    if not rule:
        sys.stderr.write(f"Error: Unknown rule '{rule_id}'. Use 'safemigrate rules list' to inspect catalog.\n")
        sys.exit(2)

    console = Console()
    overview = (
        f"[bold cyan]ID:[/bold cyan] {rule.rule_id}\n"
        f"[bold]Title:[/bold] {rule.title}\n"
        f"[bold]Version:[/bold] {rule.version}\n"
        f"[bold]Default Severity:[/bold] {rule.default_severity.value}\n"
        f"[bold]Confidence:[/bold] {rule.confidence.value}\n"
        f"[bold]Release Status:[/bold] {rule.status}\n"
        f"[bold]Summary:[/bold] {rule.description}"
    )
    console.print(Panel(overview, title=f"Rule Specification — {rule.rule_id}", border_style="cyan"))

    console.print(Panel(rule.hazard_rationale, title="Hazard Rationale & Locking Impact", border_style="red"))
    console.print(Panel(rule.positive_example, title="Positive Example (Triggers Rule)", border_style="yellow"))
    console.print(Panel(rule.negative_example, title="Negative Example (Safe Pattern / Near-Miss)", border_style="green"))
    console.print(Panel(rule.remediation, title="Remediation Strategy & Staged Pattern", border_style="blue"))
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
