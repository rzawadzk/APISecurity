"""CLI interface for API Scout."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .database import Database
from .inventory import APIInventory
from .models import APIStatus, AuthMethod
from .parsers import ALBLogParser, APIGatewayLogParser, GenericLogParser, NginxLogParser
from .scanner import scan_network

console = Console()

PARSERS = {
    "nginx": NginxLogParser,
    "alb": ALBLogParser,
    "apigateway": APIGatewayLogParser,
    "generic": GenericLogParser,
    "auto": None,  # Will try all parsers
}


def auto_detect_parser(file_path: Path):
    """Try each parser on the first 10 lines to find the best match.

    Specific parsers (Nginx, ALB, API Gateway) are tried first.
    GenericLogParser is only used as a fallback if none of the specific parsers match.
    """
    specific_parsers = [NginxLogParser(), ALBLogParser(), APIGatewayLogParser()]

    with open(file_path, "r", errors="replace") as f:
        sample_lines = [line.strip() for line in f if line.strip()][:10]

    best_parser = None
    best_count = 0

    for parser in specific_parsers:
        count = sum(1 for line in sample_lines if parser.parse_line(line) is not None)
        if count > best_count:
            best_count = count
            best_parser = parser

    # Fall back to generic if no specific parser matched well
    if best_count < len(sample_lines) * 0.3:
        return GenericLogParser()

    return best_parser or GenericLogParser()


@click.group()
@click.version_option(version="0.1.0", prog_name="api-scout")
@click.option("--db", "db_path", default="api_scout.db", help="Database file path")
@click.pass_context
def main(ctx, db_path: str):
    """API Scout — Discover and inventory all APIs in your environment."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db_path


def get_db(ctx) -> Database:
    return Database(ctx.obj["db_path"])


@main.command()
@click.argument("log_files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(list(PARSERS.keys())),
    default="auto",
    help="Log format (auto-detected if not specified)",
)
@click.option("--output", "-o", type=click.Path(), help="Save report as JSON")
@click.option("--zombie-days", default=30, help="Days without traffic before marking as zombie")
@click.pass_context
def analyze(ctx, log_files: tuple[str, ...], format: str, output: str | None, zombie_days: int):
    """Analyze access logs to discover API endpoints."""
    db = get_db(ctx)
    inventory = APIInventory(zombie_threshold_days=zombie_days)

    # Load existing endpoints from DB
    for ep in db.get_all_endpoints():
        inventory._endpoints[ep.endpoint_id] = ep

    total_records = 0
    total_new = 0
    scan_id = db.start_scan("log_analysis", ",".join(str(f) for f in log_files))

    for log_file in log_files:
        path = Path(log_file)
        console.print(f"\n[bold blue]Parsing:[/] {path.name}")

        if format == "auto":
            parser = auto_detect_parser(path)
            console.print(f"  Auto-detected format: [cyan]{parser.__class__.__name__}[/]")
        else:
            parser = PARSERS[format]()

        records = list(parser.parse_file(path))
        total_records += len(records)

        new_endpoints = inventory.ingest_traffic(records)
        total_new += new_endpoints

        # Persist traffic records
        path_patterns = {r.path: inventory.normalize_path(r.path) for r in records}
        db.log_traffic(records, path_patterns)

        console.print(f"  Parsed [green]{len(records)}[/] records, [yellow]{new_endpoints}[/] new endpoints")

    # Classify, save, generate alerts
    report = inventory.generate_report()
    db.save_endpoints(report.endpoints)
    db.save_alerts(report.alerts)
    db.complete_scan(scan_id, report.total_endpoints, total_new, len(report.alerts))

    _print_report_from_data(report, output)
    console.print(f"\n[dim]Total: {total_records} log records processed, saved to {ctx.obj['db_path']}[/]")


@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--ports", "-p", default=None, help="Comma-separated ports to scan (default: common HTTP ports)")
@click.option("--concurrency", "-c", default=20, help="Max concurrent scans")
@click.option("--output", "-o", type=click.Path(), help="Save report as JSON")
@click.pass_context
def scan(ctx, targets: tuple[str, ...], ports: str | None, concurrency: int, output: str | None):
    """Actively scan hosts/networks for API services and OpenAPI specs."""
    db = get_db(ctx)
    port_list = [int(p) for p in ports.split(",")] if ports else None

    console.print(f"\n[bold blue]Scanning {len(targets)} target(s)...[/]")
    scan_id = db.start_scan("network", ",".join(targets))

    results = asyncio.run(scan_network(list(targets), port_list, concurrency))

    inventory = APIInventory()
    # Load existing
    for ep in db.get_all_endpoints():
        inventory._endpoints[ep.endpoint_id] = ep

    new_count = inventory.ingest_scan_results(results)

    # Print scan results
    http_services = [r for r in results if r.is_http]
    specs_found = [r for r in results if r.openapi_spec_url]

    console.print(f"\n  HTTP services found: [green]{len(http_services)}[/]")
    console.print(f"  OpenAPI specs found: [green]{len(specs_found)}[/]")
    console.print(f"  Endpoints discovered: [yellow]{new_count}[/]")

    for spec in specs_found:
        console.print(f"  [cyan]Spec:[/] {spec.openapi_spec_url}")

    report = inventory.generate_report()
    db.save_endpoints(report.endpoints)
    db.save_alerts(report.alerts)
    db.complete_scan(scan_id, report.total_endpoints, new_count, len(report.alerts))

    _print_report_from_data(report, output)


@main.command()
@click.argument("log_files", nargs=-1, type=click.Path(exists=True))
@click.option("--scan-targets", "-s", multiple=True, help="Hosts/CIDRs to scan")
@click.option("--format", "-f", type=click.Choice(list(PARSERS.keys())), default="auto")
@click.option("--ports", "-p", default=None, help="Comma-separated ports for scanning")
@click.option("--output", "-o", type=click.Path(), help="Save report as JSON")
@click.option("--zombie-days", default=30, help="Days without traffic before marking as zombie")
@click.pass_context
def full(
    ctx,
    log_files: tuple[str, ...],
    scan_targets: tuple[str, ...],
    format: str,
    ports: str | None,
    output: str | None,
    zombie_days: int,
):
    """Run both log analysis and active scanning, then correlate results."""
    db = get_db(ctx)
    inventory = APIInventory(zombie_threshold_days=zombie_days)

    for ep in db.get_all_endpoints():
        inventory._endpoints[ep.endpoint_id] = ep

    # Phase 1: Log analysis
    if log_files:
        console.print("\n[bold]Phase 1: Log Analysis[/]")
        for log_file in log_files:
            path = Path(log_file)
            parser = auto_detect_parser(path) if format == "auto" else PARSERS[format]()
            records = list(parser.parse_file(path))
            new = inventory.ingest_traffic(records)
            path_patterns = {r.path: inventory.normalize_path(r.path) for r in records}
            db.log_traffic(records, path_patterns)
            console.print(f"  {path.name}: {len(records)} records, {new} new endpoints")

    # Phase 2: Active scanning
    if scan_targets:
        console.print("\n[bold]Phase 2: Active Scanning[/]")
        port_list = [int(p) for p in ports.split(",")] if ports else None
        results = asyncio.run(scan_network(list(scan_targets), port_list))
        new = inventory.ingest_scan_results(results)
        console.print(f"  Scan complete: {new} new endpoints from specs")

    report = inventory.generate_report()
    db.save_endpoints(report.endpoints)
    db.save_alerts(report.alerts)

    _print_report_from_data(report, output)


# ── Scheduled Mode ──


@main.command()
@click.option("--logs", "-l", multiple=True, type=click.Path(exists=True), help="Log files to watch")
@click.option("--scan-targets", "-s", multiple=True, help="Hosts/CIDRs for periodic scanning")
@click.option("--format", "-f", type=click.Choice(list(PARSERS.keys())), default="auto")
@click.option("--ports", "-p", default=None, help="Comma-separated ports for scanning")
@click.option("--log-interval", default=30, help="Seconds between log checks (default: 30)")
@click.option("--scan-interval", default=3600, help="Seconds between network scans (default: 3600)")
@click.option("--zombie-days", default=30, help="Days without traffic before marking as zombie")
@click.pass_context
def watch(
    ctx,
    logs: tuple[str, ...],
    scan_targets: tuple[str, ...],
    format: str,
    ports: str | None,
    log_interval: int,
    scan_interval: int,
    zombie_days: int,
):
    """Continuously watch log files and run periodic scans."""
    from .scheduler import Scheduler

    db = get_db(ctx)

    # Determine parser
    if logs:
        if format == "auto":
            parser = auto_detect_parser(Path(logs[0]))
        else:
            parser = PARSERS[format]()
    else:
        parser = None

    port_list = [int(p) for p in ports.split(",")] if ports else None

    scheduler = Scheduler(
        db=db,
        log_files=[Path(l) for l in logs],
        parser=parser,
        scan_targets=list(scan_targets),
        scan_ports=port_list,
        log_interval=log_interval,
        scan_interval=scan_interval,
        zombie_days=zombie_days,
    )

    # Handle Ctrl+C gracefully
    def handle_signal(*_):
        console.print("\n[yellow]Shutting down...[/]")
        scheduler.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    asyncio.run(scheduler.run())


# ── Web Dashboard ──


@main.command()
@click.option("--host", "-h", default="127.0.0.1", help="Dashboard host (default: 127.0.0.1)")
@click.option("--port", "-p", default=8080, type=int, help="Dashboard port (default: 8080)")
@click.pass_context
def dashboard(ctx, host: str, port: int):
    """Launch the web dashboard."""
    import uvicorn

    from .dashboard import create_app

    db = get_db(ctx)
    app = create_app(db)

    console.print(Panel(
        f"[bold green]API Scout Dashboard[/]\n"
        f"  URL: [link=http://{host}:{port}]http://{host}:{port}[/link]\n"
        f"  DB:  {ctx.obj['db_path']}\n\n"
        f"  Press Ctrl+C to stop",
        border_style="green",
    ))

    uvicorn.run(app, host=host, port=port, log_level="warning")


# ── DB Query Commands ──


@main.command()
@click.pass_context
def status(ctx):
    """Show current inventory status from the database."""
    db = get_db(ctx)
    summary = db.get_dashboard_summary()

    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")
    summary_table.add_row("Total Endpoints", str(summary["total_endpoints"]))
    summary_table.add_row("Active", f"[green]{summary['active']}[/]")
    summary_table.add_row("Shadow (not in spec)", f"[red]{summary['shadow']}[/]")
    summary_table.add_row("Zombie (no traffic)", f"[yellow]{summary['zombie']}[/]")
    summary_table.add_row("Undocumented", f"[dim]{summary['undocumented']}[/]")
    summary_table.add_row("Unauthenticated", f"[red]{summary['unauthenticated']}[/]")
    summary_table.add_row("Active Alerts", f"[red]{summary['active_alerts']}[/]")

    console.print(Panel(summary_table, title="[bold]API Inventory Status[/]", border_style="blue"))

    # Recent scans
    if summary["recent_scans"]:
        scan_table = Table(title="Recent Scans")
        scan_table.add_column("Type")
        scan_table.add_column("Targets")
        scan_table.add_column("Found", justify="right")
        scan_table.add_column("New", justify="right")
        scan_table.add_column("Status")
        scan_table.add_column("Time")

        for s in summary["recent_scans"]:
            status_style = "green" if s["status"] == "completed" else "yellow" if s["status"] == "running" else "red"
            scan_table.add_row(
                s["scan_type"],
                s["targets"] or "-",
                str(s["endpoints_found"]),
                str(s["new_endpoints"]),
                f"[{status_style}]{s['status']}[/]",
                s["started_at"] or "",
            )
        console.print(scan_table)


@main.command()
@click.option("--unacknowledged", "-u", is_flag=True, help="Show only unacknowledged alerts")
@click.pass_context
def alerts(ctx, unacknowledged: bool):
    """Show alerts from the database."""
    db = get_db(ctx)
    alert_list = db.get_alerts(unacknowledged_only=unacknowledged)

    if not alert_list:
        console.print("[dim]No alerts found.[/]")
        return

    table = Table(title=f"Alerts ({len(alert_list)})")
    table.add_column("ID", width=5)
    table.add_column("Severity", width=8)
    table.add_column("Type", width=16)
    table.add_column("Message")
    table.add_column("Time", width=20)
    table.add_column("Ack", width=5)

    severity_colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}

    for a in alert_list:
        color = severity_colors.get(a["severity"], "white")
        ack = "[green]Yes[/]" if a["acknowledged"] else "[red]No[/]"
        table.add_row(
            str(a["id"]),
            f"[{color}]{a['severity']}[/]",
            a["alert_type"],
            a["message"],
            a["created_at"] or "",
            ack,
        )

    console.print(table)


@main.command()
@click.argument("query")
@click.pass_context
def search(ctx, query: str):
    """Search endpoints in the database."""
    db = get_db(ctx)
    endpoints = db.search_endpoints(query)

    if not endpoints:
        console.print(f"[dim]No endpoints matching '{query}'[/]")
        return

    table = Table(title=f"Search: '{query}' ({len(endpoints)} results)")
    table.add_column("Status", width=14)
    table.add_column("Method", width=8)
    table.add_column("Path", min_width=30)
    table.add_column("Host", width=20)
    table.add_column("Calls", justify="right", width=8)

    status_colors = {
        APIStatus.ACTIVE: "green", APIStatus.SHADOW: "red",
        APIStatus.ZOMBIE: "yellow", APIStatus.UNDOCUMENTED: "dim",
        APIStatus.DEPRECATED: "magenta",
    }

    for ep in endpoints:
        color = status_colors.get(ep.status, "white")
        table.add_row(
            f"[{color}]{ep.status.value}[/]",
            ep.method,
            ep.path_pattern,
            ep.host or "-",
            str(ep.total_calls),
        )

    console.print(table)


# ── CI/CD Validation ──


@main.command()
@click.argument("spec_file", type=click.Path(exists=True))
@click.option("--fail-on-breaking/--warn-on-breaking", default=True, help="Fail CI on breaking changes")
@click.option("--fail-on-shadow/--warn-on-shadow", default=True, help="Fail CI on shadow policy violations")
@click.option("--output", "-o", type=click.Path(), help="Save results as JSON")
@click.option("--github-annotations", is_flag=True, help="Output GitHub Actions annotation format")
@click.pass_context
def validate(ctx, spec_file: str, fail_on_breaking: bool, fail_on_shadow: bool, output: str, github_annotations: bool):
    """Validate an OpenAPI spec against the live inventory (CI/CD integration)."""
    from .cicd import validate_spec_against_inventory, generate_github_annotations

    db = get_db(ctx)
    result = validate_spec_against_inventory(
        Path(spec_file), db,
        fail_on_breaking=fail_on_breaking,
        fail_on_shadow=fail_on_shadow,
    )

    if github_annotations:
        console.print(generate_github_annotations(result))
    else:
        # Pretty print
        status_icon = "[green]PASSED[/]" if result.passed else "[red]FAILED[/]"
        console.print(f"\n  Validation: {status_icon}")
        console.print(f"  Spec endpoints: {result.spec_endpoints}")
        console.print(f"  Inventory endpoints: {result.inventory_endpoints}")
        console.print(f"  New in spec: [cyan]{result.new_in_spec}[/]")
        console.print(f"  Removed from spec: [yellow]{result.removed_from_spec}[/]")
        console.print(f"  Errors: [red]{len(result.errors)}[/]")
        console.print(f"  Warnings: [yellow]{len(result.warnings)}[/]")

        if result.violations:
            table = Table(title="Violations")
            table.add_column("Severity", width=10)
            table.add_column("Rule", width=24)
            table.add_column("Endpoint", width=30)
            table.add_column("Message")

            sev_colors = {"error": "red", "warning": "yellow", "info": "dim"}
            for v in result.violations:
                color = sev_colors.get(v.severity.value, "white")
                table.add_row(
                    f"[{color}]{v.severity.value}[/]",
                    v.rule,
                    v.endpoint or "-",
                    v.message,
                )
            console.print(table)

    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n[green]Results saved to {output}[/]")

    if not result.passed:
        sys.exit(1)


# ── Auto-Remediation ──


@main.command(name="generate-waf")
@click.option("--format", "-f", type=click.Choice(["nginx", "modsecurity", "aws"]), default="nginx")
@click.option("--output", "-o", type=click.Path(), help="Save rules to file")
@click.pass_context
def generate_waf(ctx, format: str, output: str):
    """Generate WAF rules to block shadow APIs."""
    from .remediation import WAFRuleGenerator

    db = get_db(ctx)
    gen = WAFRuleGenerator(db)

    if format == "nginx":
        rules = gen.generate_nginx_rules()
    elif format == "modsecurity":
        rules = gen.generate_modsecurity_rules()
    else:
        rules = json.dumps(gen.generate_aws_waf_rules(), indent=2)

    if output:
        Path(output).write_text(rules)
        console.print(f"[green]WAF rules saved to {output}[/]")
    else:
        console.print(rules)


@main.command(name="generate-spec")
@click.option("--undocumented-only", "-u", is_flag=True, help="Only generate for undocumented endpoints")
@click.option("--title", "-t", default="Auto-Generated API Spec", help="Spec title")
@click.option("--output", "-o", type=click.Path(), default="openapi-generated.json", help="Output file")
@click.pass_context
def generate_spec(ctx, undocumented_only: bool, title: str, output: str):
    """Auto-generate an OpenAPI spec from observed traffic."""
    from .remediation import SpecGenerator

    db = get_db(ctx)
    gen = SpecGenerator(db)

    if undocumented_only:
        spec = gen.generate_for_undocumented(title=title)
    else:
        spec = gen.generate_spec(title=title)

    Path(output).write_text(json.dumps(spec, indent=2, default=str))
    endpoint_count = len(spec.get("paths", {}))
    console.print(f"[green]OpenAPI spec generated: {output} ({endpoint_count} paths)[/]")


# ── Dependency Graph ──


@main.command(name="graph")
@click.option("--format", "-f", type=click.Choice(["mermaid", "json", "summary"]), default="summary")
@click.option("--output", "-o", type=click.Path(), help="Save to file")
@click.pass_context
def graph_cmd(ctx, format: str, output: str):
    """Show service dependency graph and blast radius analysis."""
    from .graph import DependencyGraph

    db = get_db(ctx)
    graph = DependencyGraph()
    graph.build_from_database(db)

    if format == "mermaid":
        result = graph.to_mermaid()
        if output:
            Path(output).write_text(result)
            console.print(f"[green]Mermaid diagram saved to {output}[/]")
        else:
            console.print(result)

    elif format == "json":
        result = json.dumps(graph.to_dict(), indent=2, default=str)
        if output:
            Path(output).write_text(result)
            console.print(f"[green]Graph JSON saved to {output}[/]")
        else:
            console.print(result)

    else:
        data = graph.to_dict()
        console.print(f"\n[bold]Dependency Graph[/]")
        console.print(f"  Nodes: {data['stats']['total_nodes']}")
        console.print(f"  Edges: {data['stats']['total_edges']}")
        console.print(f"  Services: {data['stats']['services']}")
        console.print(f"  Third parties: {data['stats']['third_parties']}")

        critical = graph.find_critical_paths()
        if critical:
            table = Table(title="Critical Services (most dependents)")
            table.add_column("Service")
            table.add_column("Calls", justify="right")
            table.add_column("Endpoints", justify="right")
            for n in critical[:5]:
                table.add_row(n.name, str(n.total_calls), str(n.endpoint_count))
            console.print(table)

        spofs = graph.find_single_points_of_failure()
        if spofs:
            console.print(Panel(
                "\n".join(f"[red]{s['service']}[/] — affects {s['affected_percentage']}% of services" for s in spofs),
                title="Single Points of Failure",
                border_style="red",
            ))

        orphans = graph.find_orphaned_services()
        if orphans:
            console.print(f"\n[yellow]Orphaned services:[/] {', '.join(n.name for n in orphans)}")


# ── Report Rendering ──


def _print_report_from_data(report, output_path: str | None = None):
    """Render a report to terminal and optionally to JSON."""
    # Summary panel
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("Metric", style="bold")
    summary.add_column("Value", justify="right")
    summary.add_row("Total Endpoints", str(report.total_endpoints))
    summary.add_row("Active", f"[green]{report.active_endpoints}[/]")
    summary.add_row("Shadow (not in spec)", f"[red]{report.shadow_endpoints}[/]")
    summary.add_row("Zombie (no traffic)", f"[yellow]{report.zombie_endpoints}[/]")
    summary.add_row("Undocumented", f"[dim]{report.undocumented_endpoints}[/]")
    summary.add_row("Unauthenticated", f"[red]{report.unauthenticated_endpoints}[/]")
    summary.add_row("New (last 24h)", f"[cyan]{report.new_last_24h}[/]")

    console.print(Panel(summary, title="[bold]API Inventory Summary[/]", border_style="blue"))

    # Alerts
    if report.alerts:
        console.print(Panel(
            "\n".join(report.alerts),
            title=f"[bold]Alerts ({len(report.alerts)})[/]",
            border_style="red",
        ))

    # Endpoint table
    if report.endpoints:
        table = Table(title="Discovered Endpoints", show_lines=False)
        table.add_column("Status", width=14)
        table.add_column("Method", width=8)
        table.add_column("Path", min_width=30)
        table.add_column("Host", width=20)
        table.add_column("Calls", justify="right", width=8)
        table.add_column("Err%", justify="right", width=6)
        table.add_column("Auth", width=10)
        table.add_column("Consumers", justify="right", width=10)
        table.add_column("Source", width=12)

        status_colors = {
            APIStatus.ACTIVE: "green", APIStatus.SHADOW: "red",
            APIStatus.ZOMBIE: "yellow", APIStatus.UNDOCUMENTED: "dim",
            APIStatus.DEPRECATED: "magenta",
        }

        for ep in report.endpoints:
            color = status_colors.get(ep.status, "white")
            auth_display = ", ".join(a.value for a in ep.auth_methods_seen) if ep.auth_methods_seen else "-"
            sources = ", ".join(s.value.split("_", 1)[-1] for s in ep.discovery_sources)

            table.add_row(
                f"[{color}]{ep.status.value}[/]",
                ep.method,
                ep.path_pattern,
                ep.host or "-",
                str(ep.total_calls),
                f"{ep.error_rate:.0%}" if ep.total_calls > 0 else "-",
                auth_display,
                str(len(ep.consumers)),
                sources,
            )

        console.print(table)

    # Save JSON report
    if output_path:
        report_data = report.model_dump(mode="json")
        Path(output_path).write_text(json.dumps(report_data, indent=2, default=str))
        console.print(f"\n[green]Report saved to {output_path}[/]")


if __name__ == "__main__":
    main()
