"""DNSAudit CLI - command-line interface."""

import sys
import os
import json

import click

from dnsaudit import __version__
from dnsaudit.client import DNSAuditClient, DNSAuditError, RateLimitError
from dnsaudit.output.formatter import print_scan_result, print_history, print_json

# Shared options
_API_KEY_OPTION = click.option(
    "--api-key",
    envvar="DNSAUDIT_API_KEY",
    default=None,
    metavar="KEY",
    help="DNSAudit.io API key. Defaults to $DNSAUDIT_API_KEY.",
)


def _make_client(api_key: str | None) -> DNSAuditClient:
    try:
        return DNSAuditClient(api_key=api_key)
    except DNSAuditError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


def _handle_error(exc: DNSAuditError) -> None:
    if isinstance(exc, RateLimitError):
        msg = f"Rate limit: {exc}"
        if exc.retry_after:
            msg += f"  Retry after {exc.retry_after}s."
        if exc.reset_date:
            msg += f"  Daily limit resets on {exc.reset_date}."
        click.echo(msg, err=True)
    else:
        click.echo(f"API error: {exc}", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="dnsaudit")
def cli() -> None:
    """DNSAudit CLI — DNS security scanning powered by dnsaudit.io."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("domain")
@_API_KEY_OPTION
@click.option(
    "--json", "output_json", is_flag=True, default=False,
    help="Output raw JSON instead of formatted table.",
)
@click.option(
    "--no-colour", "--no-color", is_flag=True, default=False,
    help="Disable ANSI colour output.",
)
def scan(domain: str, api_key: str | None, output_json: bool, no_colour: bool) -> None:
    """Run a full DNS security scan on DOMAIN.

    Performs 26+ checks including DNSSEC, SPF, DKIM, DMARC, and zone transfer tests.

    \b
    Examples:
      dnsaudit scan example.com
      dnsaudit scan example.com --json
      DNSAUDIT_API_KEY=xxx dnsaudit scan example.com
    """
    client = _make_client(api_key)
    try:
        result = client.scan(domain)
    except DNSAuditError as exc:
        _handle_error(exc)
        return

    if output_json:
        print_json(result)
    else:
        use_colour = not no_colour and sys.stdout.isatty()
        print_scan_result(result, use_colour=use_colour)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("domain")
@_API_KEY_OPTION
@click.option(
    "--format", "fmt",
    type=click.Choice(["json", "pdf"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Export format.",
)
@click.option(
    "--output", "-o",
    default=None,
    metavar="FILE",
    help="Save output to FILE instead of stdout.",
)
def export(domain: str, api_key: str | None, fmt: str, output: str | None) -> None:
    """Export scan results for DOMAIN.

    \b
    Examples:
      dnsaudit export example.com
      dnsaudit export example.com --format pdf -o report.pdf
    """
    client = _make_client(api_key)
    try:
        if fmt == "pdf":
            data = client.export_pdf(domain)
            dest = output or f"{domain}-report.pdf"
            with open(dest, "wb") as fh:
                fh.write(data)
            click.echo(f"PDF report saved to {dest}")
        else:
            result = client.export_json(domain)
            if output:
                with open(output, "w") as fh:
                    json.dump(result, fh, indent=2)
                click.echo(f"JSON export saved to {output}")
            else:
                print_json(result)
    except DNSAuditError as exc:
        _handle_error(exc)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------

@cli.command()
@_API_KEY_OPTION
@click.option(
    "--limit", default=10, show_default=True,
    metavar="N", help="Number of results to return (max 100).",
)
@click.option(
    "--json", "output_json", is_flag=True, default=False,
    help="Output raw JSON.",
)
@click.option(
    "--no-colour", "--no-color", is_flag=True, default=False,
    help="Disable ANSI colour output.",
)
def history(api_key: str | None, limit: int, output_json: bool, no_colour: bool) -> None:
    """Show your recent scan history.

    \b
    Examples:
      dnsaudit history
      dnsaudit history --limit 50
      dnsaudit history --json
    """
    client = _make_client(api_key)
    try:
        result = client.history(limit=limit)
    except DNSAuditError as exc:
        _handle_error(exc)
        return

    if output_json:
        print_json(result)
    else:
        use_colour = not no_colour and sys.stdout.isatty()
        print_history(result, use_colour=use_colour)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
