"""
CLI entrypoint for Aura-Audit.

Usage examples:
  aura-audit scan --profile prod --region us-east-1
  aura-audit scan --profile dev --fast --output findings.json
  aura-audit scan --principal-arn arn:aws:iam::123456789012:role/MyRole
  aura-audit health
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from . import __version__
from .engine.semantic_auditor import SemanticAuditor
from .inference.bridge import InferenceBridge
from .output.formatter import JSONFormatter
from .providers.aws.provider import AWSProvider
from .schemas.finding import Finding, Severity

console = Console(stderr=True)   # progress/logs → stderr, JSON → stdout


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_summary(findings: list[Finding]) -> None:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    table = Table(title="Audit Summary", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")

    colors = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFORMATIONAL": "dim",
    }
    for severity, count in counts.items():
        if count > 0:
            table.add_row(
                f"[{colors[severity]}]{severity}[/{colors[severity]}]",
                str(count),
            )

    console.print()
    console.print(table)
    console.print(f"\n[bold]Total findings: {len(findings)}[/bold]")


@click.group()
@click.version_option(__version__, prog_name="aura-audit")
def main() -> None:
    """Aura-Audit: Semantic IAM over-privilege detector. Local inference only."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  scan
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--profile", default=None, envvar="AWS_PROFILE",
              help="AWS named profile from ~/.aws/credentials")
@click.option("--region", default="us-east-1", envvar="AWS_DEFAULT_REGION",
              show_default=True, help="AWS region")
@click.option("--principal-arn", default=None,
              help="Audit a single principal ARN instead of all")
@click.option("--principal-type",
              type=click.Choice(["role", "user", "group", "all"], case_sensitive=False),
              default="all", show_default=True,
              help="Filter principal types to audit")
@click.option("--fast", is_flag=True, default=False,
              help="Static heuristics only (Tier 1). No semantic or AI analysis. Fastest option.")
@click.option("--output", "-o", default=None,
              help="Write JSON output to file instead of STDOUT")
@click.option("--format",
              type=click.Choice(["array", "ndjson"]), default="array",
              show_default=True, help="JSON output format")
@click.option("--min-severity",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
                                case_sensitive=False),
              default="LOW", show_default=True,
              help="Minimum severity to include in output")
@click.option("--ollama-url", default=None, envvar="AURA_OLLAMA_URL",
              help="Ollama base URL [default: http://localhost:11434]")
@click.option("--model", default=None, envvar="AURA_OLLAMA_MODEL",
              help="Ollama model name [default: qwen2.5:1.5b]")
@click.option("--endpoint-url", default=None, envvar="AWS_ENDPOINT_URL",
              help="Custom AWS endpoint URL (e.g. http://localhost:4566 for LocalStack)")
@click.option("--concurrency", default=1, show_default=True,
              envvar="AURA_OLLAMA_CONCURRENCY",
              help="Max parallel Ollama inference requests")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable debug logging")
def scan(
    profile: str | None,
    region: str,
    principal_arn: str | None,
    principal_type: str,
    fast: bool,
    output: str | None,
    format: str,
    min_severity: str,
    ollama_url: str | None,
    model: str | None,
    endpoint_url: str | None,
    concurrency: int,
    verbose: bool,
) -> None:
    """Run a full semantic IAM audit against an AWS account."""
    _setup_logging(verbose)

    ollama_url = ollama_url or os.environ.get("AURA_OLLAMA_URL", "http://localhost:11434")
    model = model or os.environ.get("AURA_OLLAMA_MODEL", "qwen2.5:1.5b")

    asyncio.run(
        _run_scan(
            profile=profile,
            region=region,
            principal_arn=principal_arn,
            principal_type=principal_type,
            fast=fast,
            output=output,
            fmt=format,
            min_severity=min_severity,
            ollama_url=ollama_url,
            model=model,
            endpoint_url=endpoint_url,
            concurrency=concurrency,
        )
    )


async def _run_scan(
    profile: str | None,
    region: str,
    principal_arn: str | None,
    principal_type: str,
    fast: bool,
    output: str | None,
    fmt: str,
    min_severity: str,
    ollama_url: str,
    model: str,
    endpoint_url: str | None,
    concurrency: int,
) -> None:
    console.rule("[bold]Aura-Audit[/bold] — Semantic IAM Auditor")

    bridge = InferenceBridge(
        model=model,
        ollama_url=ollama_url,
        concurrency=concurrency,
    )

    async with bridge:
        if not fast:
            console.print(f"[dim]Checking Ollama at {ollama_url}...[/dim]")
            ok = await bridge.health_check()
            if not ok:
                console.print(
                    f"[yellow]⚠ Ollama model '{model}' not ready. "
                    f"Falling back to fast mode (Tier 1 only).[/yellow]"
                )
                fast = True

        provider = AWSProvider(profile=profile, region=region, endpoint_url=endpoint_url)
        auditor = SemanticAuditor(bridge=bridge, fast_only=fast)
        formatter = JSONFormatter(format=fmt, output=output, min_severity=min_severity)

        all_findings: list[Finding] = []
        tier3_failures: list[str] = []
        ingest_sem = asyncio.Semaphore(10)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:

            console.print(f"[dim]Fetching principals from AWS ({region})...[/dim]")
            principals = await provider.list_principals(
                principal_type=principal_type,
                specific_arn=principal_arn,
            )

            task_ingest = progress.add_task(
                "Fetching policies...", total=len(principals)
            )
            task_audit = progress.add_task(
                f"Auditing {len(principals)} principals...", total=len(principals)
            )

            async def fetch_and_audit(principal):
                async with ingest_sem:
                    bundle = await provider.fetch_policy_bundle(principal)
                progress.advance(task_ingest)

                findings = []
                async for finding in auditor.audit_bundle(bundle):
                    findings.append(finding)

                if not fast:
                    if not any(f.tier == 3 for f in findings):
                        tier3_failures.append(bundle.resource.name)

                all_findings.extend(findings)
                progress.advance(task_audit)

            await asyncio.gather(*[fetch_and_audit(p) for p in principals])

    if not fast and tier3_failures:
        console.print(
            f"\n[yellow]⚠ Tier 3 inference produced no findings for "
            f"{len(tier3_failures)}/{len(principals)} principals. "
            f"Results are Tier 1 only. Run with --verbose for raw model output.[/yellow]"
        )

    _print_summary(all_findings)
    formatter.serialize(all_findings)

    if output:
        console.print(f"\n[green]✓[/green] Findings written to [bold]{output}[/bold]")


# ─────────────────────────────────────────────────────────────────────────────
#  health
# ─────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--ollama-url", default="http://localhost:11434", envvar="AURA_OLLAMA_URL")
@click.option("--model", default="qwen2.5:1.5b", envvar="AURA_OLLAMA_MODEL")
@click.option("--profile", default=None, envvar="AWS_PROFILE")
@click.option("--region", default="us-east-1", envvar="AWS_DEFAULT_REGION")
def health(ollama_url: str, model: str, profile: str | None, region: str) -> None:
    """Check connectivity to Ollama and AWS."""
    asyncio.run(_run_health(ollama_url, model, profile, region))


async def _run_health(
    ollama_url: str, model: str, profile: str | None, region: str
) -> None:
    console.rule("Aura-Audit Health Check")
    any_failed = False

    bridge = InferenceBridge(model=model, ollama_url=ollama_url)
    async with bridge:
        ok = await bridge.health_check()
        if not ok:
            any_failed = True
        status = "[green]✓ OK[/green]" if ok else "[red]✗ FAIL[/red]"
        console.print(f"  Ollama ({ollama_url}, model={model}): {status}")

    try:
        provider = AWSProvider(profile=profile, region=region)
        identity = await provider.get_caller_identity()
        console.print(
            f"  AWS ({region}): [green]✓ OK[/green] — "
            f"Account={identity['Account']}, "
            f"ARN={identity['Arn']}"
        )
    except Exception as exc:
        any_failed = True
        console.print(
            f"  AWS ({region}): [red]✗ FAIL[/red] — {exc}\n"
            f"  [dim]Check credentials, profile name, and endpoint URL if using LocalStack.[/dim]"
        )

    if any_failed:
        raise SystemExit(1)