"""Command Line Interface for WebRecon - Clean and Professional."""

import sys
import click
import asyncio
from typing import Optional, List

from . import __version__
from .config import Config
from .scanner import WebReconScanner
from .utils.logger import setup_logging
from .utils.url_utils import parse_targets, deduplicate_targets


def print_banner():
    """Print clean banner."""
    click.echo()
    click.secho("  WebRecon", fg="cyan", bold=True)
    click.secho(f"  v{__version__} - Web Reconnaissance Tool", fg="white")
    click.echo()


def print_divider():
    """Print subtle divider."""
    click.secho("  " + "-" * 50, fg="bright_black")


@click.group()
@click.version_option(version=__version__, prog_name="webrecon")
def cli():
    """WebRecon - Professional Web Reconnaissance Tool"""
    pass


@cli.command()
@click.argument("target")
@click.option("-o", "--output", default="output", help="Output directory")
@click.option("-c", "--concurrency", default=5, help="Concurrent scans (default: 5)")
@click.option("-t", "--timeout", default=30, help="Request timeout in seconds")
@click.option("--rate-limit", default=1.0, help="Seconds between requests")
@click.option("--no-screenshot", is_flag=True, help="Disable screenshots")
@click.option("--no-whois", is_flag=True, help="Disable WHOIS lookup")
@click.option("--no-dns", is_flag=True, help="Disable DNS enumeration")
@click.option("--no-ssl", is_flag=True, help="Disable SSL analysis")
@click.option("--no-tech", is_flag=True, help="Disable technology detection")
@click.option("--no-extra", is_flag=True, help="Disable extra intelligence")
@click.option("--html", is_flag=True, help="Generate HTML report")
@click.option("--mobile", is_flag=True, help="Capture mobile screenshots")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--log-file", default=None, help="Log file path")
@click.option("--config", "config_file", default=None, help="Config file (JSON)")
def scan(
    target: str,
    output: str,
    concurrency: int,
    timeout: int,
    rate_limit: float,
    no_screenshot: bool,
    no_whois: bool,
    no_dns: bool,
    no_ssl: bool,
    no_tech: bool,
    no_extra: bool,
    html: bool,
    mobile: bool,
    verbose: bool,
    log_file: Optional[str],
    config_file: Optional[str]
):
    """
    Scan target URL/domain or file with URLs.
    
    \b
    Examples:
      webrecon scan example.com
      webrecon scan urls.txt -c 10 --html
      webrecon scan example.com --no-screenshot
    """
    log_level = "DEBUG" if verbose else "WARNING"
    setup_logging(level=log_level, log_file=log_file)
    
    if config_file:
        try:
            config = Config.from_file(config_file)
        except Exception as e:
            click.secho(f"  Error: {e}", fg="red")
            sys.exit(1)
    else:
        config = Config()
    
    config.output_dir = output
    config.concurrency = concurrency
    config.timeout = timeout
    config.rate_limit = rate_limit
    config.enable_screenshot = not no_screenshot
    config.enable_whois = not no_whois
    config.enable_dns = not no_dns
    config.enable_ssl = not no_ssl
    config.enable_tech_detect = not no_tech
    config.enable_extra_intel = not no_extra
    config.generate_html = html
    config.screenshot_mobile = mobile
    config.log_level = log_level
    config.log_file = log_file
    
    targets = parse_targets(target)
    
    if not targets:
        click.secho("  Error: No valid targets found", fg="red")
        sys.exit(1)
    
    targets = deduplicate_targets(targets)
    
    print_banner()
    
    click.echo(f"  Targets:     {click.style(str(len(targets)), fg='cyan', bold=True)}")
    click.echo(f"  Output:      {output}/")
    click.echo(f"  Concurrency: {concurrency}")
    
    modules_enabled = []
    if config.enable_headers: modules_enabled.append("headers")
    if config.enable_dns: modules_enabled.append("dns")
    if config.enable_ssl: modules_enabled.append("ssl")
    if config.enable_whois: modules_enabled.append("whois")
    if config.enable_tech_detect: modules_enabled.append("tech")
    if config.enable_screenshot: modules_enabled.append("screenshot")
    if config.enable_extra_intel: modules_enabled.append("extra")
    
    click.echo(f"  Modules:     {', '.join(modules_enabled)}")
    
    print_divider()
    click.echo()
    
    scanner = WebReconScanner(config)
    
    try:
        with click.progressbar(
            length=len(targets),
            label="  Scanning",
            show_eta=True,
            show_percent=True,
            fill_char=click.style("█", fg="cyan"),
            empty_char="░"
        ) as bar:
            results = scanner.scan_sync(targets)
            bar.update(len(targets))
        
        successful = sum(1 for r in results["results"] if r.get("success"))
        failed = len(results["results"]) - successful
        
        click.echo()
        print_divider()
        click.echo()
        click.secho("  Scan Complete", fg="green", bold=True)
        click.echo()
        click.echo(f"  Duration:   {results['scan_info']['duration']}s")
        click.echo(f"  Successful: {click.style(str(successful), fg='green')}")
        if failed > 0:
            click.echo(f"  Failed:     {click.style(str(failed), fg='red')}")
        click.echo()
        click.echo(f"  Output:     {output}/")
        click.echo(f"  Summary:    {output}/scan_summary.json")
        click.echo(f"  Results:    {output}/results/")
        if config.enable_screenshot:
            click.echo(f"  Screenshots: {output}/screenshots/")
        if html:
            click.echo(f"  Report:     {output}/report.html")
        click.echo()
        
    except KeyboardInterrupt:
        click.echo()
        click.secho("  Scan interrupted", fg="yellow")
        sys.exit(130)
    except Exception as e:
        click.echo()
        click.secho(f"  Error: {e}", fg="red")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option("-o", "--output", default="config.json", help="Output file path")
def init(output: str):
    """Generate sample configuration file."""
    config = Config()
    
    try:
        config.save(output)
        click.echo()
        click.secho(f"  Config created: {output}", fg="green")
        click.echo()
    except Exception as e:
        click.secho(f"  Error: {e}", fg="red")
        sys.exit(1)


@cli.command()
def modules():
    """List available reconnaissance modules."""
    print_banner()
    
    modules_info = [
        ("headers", "HTTP headers and security analysis", "Passive", "cyan"),
        ("dns", "DNS records and network intelligence", "Passive", "cyan"),
        ("ssl", "TLS/SSL certificate analysis", "Passive", "cyan"),
        ("whois", "Domain WHOIS lookup", "Passive", "cyan"),
        ("tech_detect", "Technology fingerprinting (500+ signatures)", "Passive", "cyan"),
        ("screenshot", "Full-page screenshot capture", "Active", "yellow"),
        ("extra_intel", "Additional intelligence gathering", "Mixed", "magenta"),
    ]
    
    for name, desc, activity, color in modules_info:
        badge = click.style(f"[{activity}]", fg=color)
        click.echo(f"  {badge} {click.style(name, bold=True)}")
        click.echo(f"          {desc}")
        click.echo()


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
